"""Shared serialisation, rendering and error handling for all tools.

The library returns a mix of Pydantic models, plain dicts and lists. Everything
funnels through :func:`to_plain` first, then either straight to JSON or through a
generic Markdown renderer that keeps responses compact -- financial payloads are
verbose, and raw JSON burns a lot of context.
"""

from __future__ import annotations

import datetime as dt
import decimal
import enum
import json
import sys
from typing import Any

import requests
from pydantic import BaseModel, ValidationError

from .client import AvanzaAuthError, AvanzaConfigError
from .guard import ReadOnlyViolationError
from .redaction import redact

__all__ = ["ResponseFormat", "to_plain", "render", "handle_error"]


class ResponseFormat(str, enum.Enum):
    """Output format for tool responses."""

    MARKDOWN = "markdown"
    JSON = "json"


def to_plain(obj: Any) -> Any:
    """Recursively convert Pydantic models, enums and dates into JSON-safe values."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, BaseModel):
        return to_plain(obj.model_dump(exclude_none=True))
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, (dt.datetime, dt.date)):
        return obj.isoformat()
    if isinstance(obj, decimal.Decimal):
        return float(obj)
    if isinstance(obj, dict):
        return {str(k): to_plain(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, (list, tuple, set)):
        return [to_plain(v) for v in obj]
    if isinstance(obj, bytes):
        return f"<{len(obj)} bytes>"
    return str(obj)


def _humanise(key: str) -> str:
    """``totalChangePercent`` -> ``Total Change Percent``."""
    spaced = "".join(f" {c}" if c.isupper() else c for c in key).replace("_", " ")
    return spaced.strip().title()


def _is_flat(value: Any) -> bool:
    return not isinstance(value, (dict, list))


def _render_table(rows: list[dict[str, Any]], indent: str) -> list[str]:
    """Render a list of uniform flat dicts as a Markdown table."""
    columns: list[str] = []
    for row in rows:
        for key in row:
            if key not in columns:
                columns.append(key)

    lines = [
        indent + "| " + " | ".join(_humanise(c) for c in columns) + " |",
        indent + "| " + " | ".join("---" for _ in columns) + " |",
    ]
    for row in rows:
        cells = []
        for column in columns:
            value = row.get(column, "")
            cells.append("" if value is None else str(value).replace("|", "\\|"))
        lines.append(indent + "| " + " | ".join(cells) + " |")
    return lines


def _render(value: Any, depth: int = 0) -> list[str]:
    indent = "  " * max(0, depth - 1)
    lines: list[str] = []

    if isinstance(value, dict):
        scalars = {k: v for k, v in value.items() if _is_flat(v)}
        nested = {k: v for k, v in value.items() if not _is_flat(v)}
        for key, item in scalars.items():
            lines.append(f"{indent}- **{_humanise(key)}**: {item}")
        for key, item in nested.items():
            if isinstance(item, list) and not item:
                continue
            heading = "#" * min(depth + 2, 6)
            lines.append("")
            lines.append(f"{heading} {_humanise(key)}")
            lines.extend(_render(item, depth + 1))
        return lines

    if isinstance(value, list):
        if not value:
            return [f"{indent}_(none)_"]
        # A list of uniform flat records reads far better as a table.
        if all(isinstance(v, dict) for v in value) and all(
            all(_is_flat(x) for x in v.values()) for v in value
        ):
            return _render_table(value, indent)
        for index, item in enumerate(value, 1):
            if _is_flat(item):
                lines.append(f"{indent}- {item}")
            else:
                lines.append(f"{indent}- **[{index}]**")
                lines.extend(_render(item, depth + 1))
        return lines

    return [f"{indent}{value}"]


def render(data: Any, fmt: ResponseFormat, title: str) -> str:
    """Serialise a library result in the requested format.

    Args:
        data: Raw result from the Avanza library.
        fmt: ``markdown`` for a compact human-readable summary, ``json`` for the
            complete structured payload.
        title: Heading used in Markdown output.

    Returns:
        The formatted string.
    """
    plain = to_plain(data)
    if fmt is ResponseFormat.JSON:
        body = json.dumps(plain, indent=2, ensure_ascii=False, default=str)
    elif plain is None or plain == [] or plain == {}:
        body = f"# {title}\n\n_No data returned._"
    else:
        body = "\n".join([f"# {title}", "", *_render(plain)]).strip()
    return redact(body)


def handle_error(exc: Exception) -> str:
    """Turn an exception into an actionable message for the agent.

    Two rules govern this function, both learned from a real leak found in audit:

    1. **Never interpolate untrusted exception text.** Some exceptions embed the
       input that caused them -- pydantic's ``ValidationError`` includes
       ``input_value={...}``, which for a credentials model is the credentials
       themselves. Only exception types we know to be safe get their message
       forwarded; everything else yields the type name alone.
    2. **Redact whatever slips through.** Every return value passes through
       :func:`~avanza_mcp.redaction.redact` as a backstop.

    Full detail always goes to stderr (also redacted) for debugging. stderr is not
    part of the MCP stream and is not shown to the model.
    """
    print(f"[avanza-mcp] {type(exc).__name__}: {redact(str(exc))}", file=sys.stderr)

    if isinstance(exc, ReadOnlyViolationError):
        # Raised by our own guard with a message we construct -- safe to forward.
        return redact(f"REFUSED (read-only server): {exc}")
    if isinstance(exc, (AvanzaConfigError, AvanzaAuthError)):
        # Also our own, with deliberately credential-free messages.
        return redact(f"Error: {exc}")
    if isinstance(exc, ValidationError):
        # NEVER forward the message: it embeds input_value, i.e. whatever was
        # being validated. For a credentials model that is the user's secrets.
        return (
            "Error: Internal validation error while building a request. "
            "Details were written to the server log, not included here because "
            "validation errors can echo their input."
        )
    if isinstance(exc, requests.HTTPError):
        status = exc.response.status_code if exc.response is not None else None
        if status == 401:
            return (
                "Error: Not authenticated. The Avanza session expired and could not "
                "be renewed. Check that the stored credentials are still valid."
            )
        if status == 403:
            return "Error: Access denied by Avanza for this resource."
        if status == 404:
            return (
                "Error: Not found. Check the id is correct and matches the instrument "
                "type -- Avanza uses distinct order book ids per instrument."
            )
        if status == 429:
            return "Error: Rate limited by Avanza. Wait a moment before retrying."
        return f"Error: Avanza returned HTTP {status}."
    if isinstance(exc, requests.Timeout):
        return "Error: Request to Avanza timed out. Try again."
    if isinstance(exc, requests.ConnectionError):
        return (
            "Error: Could not reach Avanza. Check the container has network access "
            "to www.avanza.se."
        )
    # Unknown exception type: the type name is safe, the message is not.
    return (
        f"Error: {type(exc).__name__}. Details were written to the server log; "
        "the message is withheld here because it may echo request data."
    )
