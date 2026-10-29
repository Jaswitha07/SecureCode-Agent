"""Log redaction filter — ensures secrets and API keys never reach log output.

AGENTS.md rule #6: Never log secrets or API keys.
SPEC.md threat #5: Secret exfiltration — regex scan on outbound payloads.
"""

from __future__ import annotations

import logging
import re

# Patterns that match common secret formats.
# Each tuple is (compiled regex, replacement).
_REDACTION_RULES: list[tuple[re.Pattern[str], str]] = [
    # Google API keys (AIzaSy...)
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "***REDACTED***"),

    # GitHub tokens (ghp_, gho_, ghs_, ghr_, github_pat_)
    (re.compile(r"(ghp_|gho_|ghs_|ghr_|github_pat_)[0-9A-Za-z]{20,}"), "***REDACTED***"),

    # Bearer / token auth headers
    (re.compile(r"(Bearer\s+|token\s+)[A-Za-z0-9\-_\.]{20,}",  re.IGNORECASE), "***REDACTED***"),

    # Private key blocks
    (re.compile(r"-----BEGIN\s+\w+\s+PRIVATE\s+KEY-----[\s\S]*?(?:-----END|$)", re.IGNORECASE),
     "***REDACTED***"),

    # Password in connection URIs  (proto://user:PASSWORD@host)
    (re.compile(r"(://[^:]+:)([^@]+)(@)"), r"\1***REDACTED***\3"),

    # ENV-style secrets: KEY=value where KEY looks secret-ish
    (re.compile(
        r"((?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE|CREDENTIAL|AUTH|"
        r"aws_secret_access_key)\s*=\s*)"
        r"(\S+)",
        re.IGNORECASE,
    ), r"\1***REDACTED***"),

    # AWS secret keys (40 chars, base64-ish)
    (re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"), "***REDACTED***"),
]


class RedactingFilter(logging.Filter):
    """A logging.Filter that scrubs secrets from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        # Redact args too (%-style formatting)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: redact(v) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    redact(a) if isinstance(a, str) else a for a in record.args
                )
        return True  # always emit the (now-safe) record


def redact(text: str) -> str:
    """Apply all redaction rules to *text* and return the sanitised version."""
    for pattern, replacement in _REDACTION_RULES:
        text = pattern.sub(replacement, text)
    return text


def get_redacting_logger(name: str) -> logging.Logger:
    """Return a logger with the RedactingFilter already attached."""
    logger = logging.getLogger(name)
    # Avoid adding duplicate filters
    if not any(isinstance(f, RedactingFilter) for f in logger.filters):
        logger.addFilter(RedactingFilter())
    return logger

