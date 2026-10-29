# SecureCode Agent — Specification

## Problem Statement

LLM-based coding agents can generate, edit, and execute code autonomously. Without guardrails they may introduce vulnerabilities, exfiltrate secrets, run destructive commands, or act on prompt injections. SecureCode Agent wraps every agent action in a **policy engine** that classifies risk, requires human approval for dangerous operations, and logs an immutable audit trail.

---

## Threat Model

| #  | Threat                | Control                                                  | Residual Risk                                      |
|----|-----------------------|----------------------------------------------------------|----------------------------------------------------|
| 1  | Prompt injection      | Input sanitiser strips known injection patterns          | Novel patterns may bypass the sanitiser             |
| 2  | Malicious code gen    | Static analysis + sandbox execution before merge         | Zero-day language exploits inside the sandbox        |
| 3  | Command injection     | Allowlist of permitted shell commands                    | Allowed commands composed into unexpected pipelines  |
| 4  | Path traversal        | Resolve & clamp all paths to the project root            | Symlink races if the OS allows them                  |
| 5  | Secret exfiltration   | Regex + entropy scan on every outbound payload           | Encoded or split secrets may evade detection         |
| 6  | Unauthorised network  | Sandbox drops all network access; proxy allowlist        | DNS-based exfiltration via allowed domains           |
| 7  | Resource exhaustion   | CPU / memory / time limits per sandbox run               | Disk-fill attacks within the quota                   |
| 8  | Dependency installs   | Block pip/npm install; deps come from a lockfile only    | Compromised packages already in the lockfile         |
| 9  | Cross-user access     | Row-level isolation; project scoped to owner             | Privilege escalation via a backend bug               |
| 10 | Approval bypass       | Dual-check: policy engine gate + human approval required | Social engineering the human approver                 |

---

## Agent State Machine

```
┌──────────┐
│  IDLE    │
└────┬─────┘
     │ task assigned
     ▼
┌──────────┐
│ PLANNING │──── plan ready ────┐
└──────────┘                    ▼
                          ┌───────────┐
                          │ APPROVAL  │ ◄── human reviews plan
                          └─────┬─────┘
                     approved   │   rejected
                   ┌────────────┴──────────┐
                   ▼                       ▼
             ┌───────────┐           ┌──────────┐
             │ EXECUTING │           │ FAILED   │
             └─────┬─────┘           └──────────┘
                   │
          success  │  error (retry ≤ 3)
         ┌─────────┴─────────┐
         ▼                   ▼
   ┌───────────┐       ┌───────────┐
   │ VERIFYING │       │ EXECUTING │ (back to executing)
   └─────┬─────┘       └───────────┘
         │
   pass  │  fail (retry ≤ 3)
  ┌──────┴──────┐
  ▼             ▼
┌──────┐  ┌──────────┐
│ DONE │  │ FAILED   │
└──────┘  └──────────┘
```

### States

| State       | Description                                      |
|-------------|--------------------------------------------------|
| `IDLE`      | Waiting for a task.                               |
| `PLANNING`  | Agent generates a step-by-step plan.              |
| `APPROVAL`  | Plan or action awaits human approval.             |
| `EXECUTING` | Agent runs tool calls inside the sandbox.         |
| `VERIFYING` | Automated tests and static analysis run.          |
| `DONE`      | Task completed and all checks passed.             |
| `FAILED`    | Rejected, or retries exhausted (max **3**).       |

### Approval Gates

1. **Plan approval** — before any code is generated.
2. **Patch approval** — before changes are applied to the project.
3. **Destructive-action approval** — file deletes, shell commands, dependency changes.

---

## Database Schema

### `users`
| Column       | Type        | Notes              |
|--------------|-------------|---------------------|
| id           | UUID PK     |                     |
| email        | TEXT UNIQUE |                     |
| name         | TEXT        |                     |
| created_at   | TIMESTAMP   |                     |

### `projects`
| Column       | Type        | Notes              |
|--------------|-------------|---------------------|
| id           | UUID PK     |                     |
| user_id      | UUID FK     | → users.id          |
| name         | TEXT        |                     |
| repo_path    | TEXT        |                     |
| created_at   | TIMESTAMP   |                     |

### `tasks`
| Column       | Type        | Notes              |
|--------------|-------------|---------------------|
| id           | UUID PK     |                     |
| project_id   | UUID FK     | → projects.id       |
| prompt       | TEXT        |                     |
| state        | TEXT        | see state machine   |
| retries      | INT         | max 3               |
| created_at   | TIMESTAMP   |                     |
| updated_at   | TIMESTAMP   |                     |

### `plans`
| Column       | Type        | Notes              |
|--------------|-------------|---------------------|
| id           | UUID PK     |                     |
| task_id      | UUID FK     | → tasks.id          |
| steps_json   | TEXT        | JSON array of steps |
| created_at   | TIMESTAMP   |                     |

### `tool_calls`
| Column       | Type        | Notes              |
|--------------|-------------|---------------------|
| id           | UUID PK     |                     |
| task_id      | UUID FK     | → tasks.id          |
| tool_name    | TEXT        |                     |
| input_json   | TEXT        |                     |
| output_json  | TEXT        |                     |
| risk_level   | TEXT        | low / medium / high |
| created_at   | TIMESTAMP   |                     |

### `patches`
| Column       | Type        | Notes              |
|--------------|-------------|---------------------|
| id           | UUID PK     |                     |
| task_id      | UUID FK     | → tasks.id          |
| diff         | TEXT        | unified diff        |
| file_path    | TEXT        |                     |
| created_at   | TIMESTAMP   |                     |

### `test_runs`
| Column       | Type        | Notes              |
|--------------|-------------|---------------------|
| id           | UUID PK     |                     |
| task_id      | UUID FK     | → tasks.id          |
| passed       | BOOLEAN     |                     |
| log          | TEXT        |                     |
| created_at   | TIMESTAMP   |                     |

### `approvals`
| Column       | Type        | Notes              |
|--------------|-------------|---------------------|
| id           | UUID PK     |                     |
| task_id      | UUID FK     | → tasks.id          |
| user_id      | UUID FK     | → users.id          |
| action       | TEXT        | approve / reject    |
| reason       | TEXT        |                     |
| created_at   | TIMESTAMP   |                     |

### `audit_events`
| Column       | Type        | Notes              |
|--------------|-------------|---------------------|
| id           | UUID PK     |                     |
| task_id      | UUID FK     | → tasks.id          |
| actor         | TEXT        | user or agent       |
| event_type   | TEXT        |                     |
| detail_json  | TEXT        |                     |
| created_at   | TIMESTAMP   |                     |

---

## API Endpoints

| Method | Path                              | Description                        |
|--------|-----------------------------------|------------------------------------|
| POST   | /api/projects                     | Create a project                   |
| GET    | /api/projects/:id                 | Get project details                |
| POST   | /api/tasks                        | Submit a new task                  |
| GET    | /api/tasks/:id                    | Get task status and history        |
| GET    | /api/tasks/:id/plan               | View the generated plan            |
| POST   | /api/tasks/:id/approve            | Approve a pending action           |
| POST   | /api/tasks/:id/reject             | Reject a pending action            |
| GET    | /api/tasks/:id/patches            | List patches for a task            |
| GET    | /api/tasks/:id/test-runs          | List test results for a task       |
| GET    | /api/audit                        | Query audit log (filterable)       |

---

## Evaluation Plan

| Metric                          | Target   | Method                                   |
|---------------------------------|----------|------------------------------------------|
| Prompt-injection block rate     | ≥ 95 %   | Run known injection corpus               |
| Malicious-code detection rate   | ≥ 90 %   | CWE-seeded benchmarks                    |
| Path-traversal block rate       | 100 %    | Automated fuzzing                        |
| Secret-leak block rate          | ≥ 98 %   | Synthetic secrets in output payloads     |
| Task success rate (benign)      | ≥ 80 %   | SWE-bench-lite subset                    |
| Median task latency             | < 120 s  | End-to-end timing on eval set            |
| False-positive approval rate    | < 10 %   | Manual review of blocked safe actions    |

---

## Non-Goals

- **IDE / editor integration** — out of scope for v1.
- **Multi-model orchestration** — single model backend only.
- **Fine-tuning or training** — uses off-the-shelf models.
- **Self-hosting the LLM** — relies on an external model provider API.
- **Real-time collaboration** — single-user per project.

---

## Encryption Notice

> **This system is NOT end-to-end encrypted.** The backend server and the external model provider both see plaintext code and prompts. Do not use this system for code that must remain confidential from the model provider.

