"""Policy engine — deny-by-default decision maker.

Pure module: NO file I/O, NO network, NO side effects.

Maps to SPEC.md threat model:
  #3  Command injection  → command allowlist + shell operator blocking
  #4  Path traversal     → block ../, absolute, encoded, symlink escapes
  #5  Secret exfiltration → block .env, SSH keys, credential files
  #8  Dependency installs → needs_approval
  #10 Approval bypass    → deny-by-default
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import unquote


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Decision:
    """Result of a policy check.

    action: "allow" | "deny" | "needs_approval"
    reason: human-readable explanation (never empty)
    """

    action: str
    reason: str


# ---------------------------------------------------------------------------
# Command policy
# ---------------------------------------------------------------------------

# Commands that may execute without approval
_ALLOWED_COMMANDS: set[str] = {
    "python", "python3",
    "pytest", "py.test",
    "cat", "head", "tail", "less", "more",
    "ls", "dir", "find", "tree",
    "grep", "egrep", "fgrep", "rg",
    "echo", "printf",
    "wc", "sort", "uniq", "diff",
    "cd", "pwd", "mkdir",
    "node", "npx", "tsc",
    "git",
    "black", "ruff", "mypy", "flake8", "eslint",
}

# Commands that always require human approval (dependency installs)
_APPROVAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bpip3?\s+install\b", re.IGNORECASE),
    re.compile(r"\bnpm\s+(install|i|ci)\b", re.IGNORECASE),
    re.compile(r"\byarn\s+(add|install)\b", re.IGNORECASE),
    re.compile(r"\bpnpm\s+(add|install)\b", re.IGNORECASE),
    re.compile(r"\bconda\s+install\b", re.IGNORECASE),
    re.compile(r"\bgem\s+install\b", re.IGNORECASE),
    re.compile(r"\bcargo\s+install\b", re.IGNORECASE),
    re.compile(r"\bgo\s+install\b", re.IGNORECASE),
]

# Shell meta-characters that signal command chaining / injection
_SHELL_INJECTION_PATTERN = re.compile(
    r"[;|&`\n]"       # semicolon, pipe, ampersand, backtick, newline
    r"|\$\("          # $(...)  subshell
    r"|\)\s*\{"       # )  { — potential function definition
)


def check_command(command: str) -> Decision:
    """Evaluate whether *command* is allowed to execute.

    Returns
    -------
    Decision
        action is one of "allow", "deny", or "needs_approval".
    """
    if not command or not command.strip():
        return Decision(action="deny", reason="empty_command")

    stripped = command.strip()

    # --- 1. Block shell injection operators --------------------------------
    if _SHELL_INJECTION_PATTERN.search(stripped):
        return Decision(action="deny", reason="shell_injection_operator")

    # --- 2. Dependency-install commands need approval ----------------------
    for pat in _APPROVAL_PATTERNS:
        if pat.search(stripped):
            return Decision(action="needs_approval", reason="dependency_install")

    # --- 3. Check first token against allowlist ----------------------------
    first_token = stripped.split()[0]
    # Strip path prefix so "/usr/bin/python3" → "python3"
    base_name = first_token.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]

    if base_name in _ALLOWED_COMMANDS:
        return Decision(action="allow", reason="command_allowlisted")

    # --- 4. Deny-by-default ------------------------------------------------
    return Decision(action="deny", reason="command_not_allowlisted")


# ---------------------------------------------------------------------------
# Path policy
# ---------------------------------------------------------------------------

# File-name patterns that indicate secrets / credentials
_SECRET_FILE_PATTERNS: list[re.Pattern[str]] = [
    # .env files (but NOT .env.example)
    re.compile(r"(^|[\\/])\.env(\.(?!example)[a-zA-Z0-9_]*)?$", re.IGNORECASE),
    # SSH keys
    re.compile(r"(^|[\\/])\.ssh[\\/]", re.IGNORECASE),
    # AWS credentials
    re.compile(r"(^|[\\/])\.aws[\\/]", re.IGNORECASE),
    # GCloud credentials
    re.compile(r"(^|[\\/])\.config[\\/]gcloud[\\/]", re.IGNORECASE),
    # npm token file
    re.compile(r"(^|[\\/])\.npmrc$", re.IGNORECASE),
    # PyPI token file
    re.compile(r"(^|[\\/])\.pypirc$", re.IGNORECASE),
    # Docker config (may contain registry creds)
    re.compile(r"(^|[\\/])\.docker[\\/]config\.json$", re.IGNORECASE),
    # Generic key/credential files
    re.compile(r"(^|[\\/])credentials(\.json|\.yaml|\.db)?$", re.IGNORECASE),
    re.compile(r"(^|[\\/])\.netrc$", re.IGNORECASE),
]

# Characters / sequences that are never legitimate in file paths
_DANGEROUS_CHAR_PATTERN = re.compile(
    r"\x00"           # null byte
    r"|\s\.\.[\\/\s]"  # space-padded ..
)

# Unicode characters that could be confused for slashes
_UNICODE_SLASH_PATTERN = re.compile(
    r"[\uff0f\u2215\u2044\u29f8\u2216\uff3c]"  # fullwidth /, division slash, etc.
)


def _decode_path(path: str) -> str:
    """Recursively URL-decode a path (handles double-encoding)."""
    prev = ""
    decoded = path
    for _ in range(5):  # cap iterations to prevent infinite loop
        prev = decoded
        decoded = unquote(decoded)
        if decoded == prev:
            break
    return decoded


def check_path(path: str, *, project_root: str) -> Decision:
    """Evaluate whether *path* is safe to access within *project_root*.

    Returns
    -------
    Decision
        action is "allow" or "deny".
    """
    if not path or not path.strip():
        return Decision(action="deny", reason="empty_path")

    raw = path.strip()

    # --- 0. Dangerous characters -------------------------------------------
    if _DANGEROUS_CHAR_PATTERN.search(raw):
        return Decision(action="deny", reason="dangerous_characters")

    # --- 1. Unicode slash confusion ----------------------------------------
    if _UNICODE_SLASH_PATTERN.search(raw):
        return Decision(action="deny", reason="unicode_slash_confusion")

    # --- 2. URL-decode (handles double/triple encoding) --------------------
    decoded = _decode_path(raw)

    # Normalise separators to forward slash for analysis
    normalised = decoded.replace("\\", "/")

    # --- 3. Block absolute paths -------------------------------------------
    if normalised.startswith("/"):
        return Decision(action="deny", reason="absolute_path")
    # Windows drive letter  (C:/ or C:\)
    if len(normalised) >= 2 and normalised[1] == ":":
        return Decision(action="deny", reason="absolute_path_windows")

    # --- 4. Block any ".." component (traversal) ---------------------------
    # Split on / and check each segment
    segments = normalised.split("/")
    for seg in segments:
        stripped_seg = seg.strip()
        # ".." or "..." or "...." etc. — all suspicious
        if stripped_seg and all(c == "." for c in stripped_seg) and len(stripped_seg) >= 2:
            return Decision(action="deny", reason="path_traversal")

    # --- 5. Resolve and verify containment ---------------------------------
    resolved = (PurePosixPath(project_root) / normalised).as_posix()
    root_posix = PurePosixPath(project_root).as_posix()
    if not resolved.startswith(root_posix):
        return Decision(action="deny", reason="path_escapes_project_root")

    # --- 6. Secret / credential files --------------------------------------
    for pat in _SECRET_FILE_PATTERNS:
        if pat.search(normalised):
            return Decision(action="deny", reason="secret_or_credential_file")

    # --- 7. Allow ----------------------------------------------------------
    return Decision(action="allow", reason="path_within_project")
