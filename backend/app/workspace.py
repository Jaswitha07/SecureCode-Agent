"""Workspace checkpoint — git-backed rollback for the agent's working repo.

Before any patch is applied to a workspace repository:
  1. Call WorkspaceCheckpoint.create(message) → returns the commit SHA.
  2. Apply the patch and commit it.
  3. If tests still fail after the retry limit, call rollback(sha) to
     restore the workspace to the exact state at the checkpoint.

Uses subprocess + git — no Python git library needed.
AGENTS.md rule #6: never log the repo path if it contains a secret.
"""

from __future__ import annotations

import subprocess


class WorkspaceCheckpoint:
    """Creates and restores git checkpoints in a workspace repository.

    Parameters
    ----------
    repo_path:
        Absolute path to the git repository root.
    """

    def __init__(self, repo_path: str) -> None:
        self.repo_path = repo_path

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", *args],
            cwd=self.repo_path,
            capture_output=True,
            text=True,
            check=check,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create(self, message: str) -> str:
        """Create a git checkpoint commit and return its full SHA.

        If the working tree is clean (nothing to commit) the SHA of the
        current HEAD is returned instead — rollback will still work.

        Parameters
        ----------
        message:
            Human-readable label for the checkpoint (does not contain secrets).

        Returns
        -------
        str
            The 40-character git commit SHA of the checkpoint.
        """
        # Stage everything currently in the working tree
        self._git("add", "-A")

        # Check whether there is anything to commit
        status = self._git("status", "--porcelain")
        if status.stdout.strip():
            self._git("commit", "-m", f"[checkpoint] {message}")

        # Return the SHA of HEAD (may be a pre-existing commit if tree was clean)
        result = self._git("rev-parse", "HEAD")
        return result.stdout.strip()

    def rollback(self, sha: str) -> None:
        """Hard-reset the working tree to *sha*.

        This discards all commits and working-tree changes after *sha*.

        Parameters
        ----------
        sha:
            The 40-character git commit SHA returned by :meth:`create`.
        """
        self._git("reset", "--hard", sha)
        # Remove any untracked files that might linger
        self._git("clean", "-fd")
