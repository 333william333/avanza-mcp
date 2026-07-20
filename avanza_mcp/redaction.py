"""Last-resort scrubbing of credential values from anything leaving the process.

This exists because of a real incident found in audit: constructing the library's
credential model with the wrong keyword raised a pydantic ``ValidationError`` whose
message embeds ``input_value={...}`` -- the entire credentials dict. That message
was returned to the model, putting the user's TOTP seed into the transcript.

The primary fix is not to interpolate untrusted exception text (see
:func:`avanza_mcp.formatting.handle_error`). This module is the backstop for
whatever that reasoning misses.

Deliberately kept import-free of the rest of the package so both ``client`` and
``formatting`` can use it without a cycle.
"""

from __future__ import annotations

__all__ = ["register_secret", "redact", "clear_secrets"]

# Values that must never appear in output. Populated at startup from the
# environment; never logged or persisted.
_SECRETS: set[str] = set()

# Below this length a "secret" is too likely to collide with ordinary text
# (a short username fragment could appear inside an instrument name).
_MIN_REDACTABLE_LENGTH = 6

PLACEHOLDER = "[redacted]"


def register_secret(value: str | None) -> None:
    """Mark a value as secret so :func:`redact` will scrub it from output."""
    if value and len(value) >= _MIN_REDACTABLE_LENGTH:
        _SECRETS.add(value)


def clear_secrets() -> None:
    """Forget all registered secrets. Used by tests."""
    _SECRETS.clear()


def redact(text: str) -> str:
    """Replace any registered secret found in ``text`` with a placeholder.

    Exact-match only. This catches a whole credential appearing verbatim; it will
    not catch a value that some library truncated mid-string, which is precisely
    why it is a backstop and not the primary control.
    """
    if not _SECRETS:
        return text
    for secret in _SECRETS:
        if secret in text:
            text = text.replace(secret, PLACEHOLDER)
    return text
