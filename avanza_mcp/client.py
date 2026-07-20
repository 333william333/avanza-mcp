"""Authenticated, hardened, read-only Avanza client.

Handles the three things the underlying library does not:

  * **Lazy login.** Authenticating during MCP startup would block the protocol
    handshake behind a network round trip, so we defer it to the first tool call.
  * **Session renewal.** ``avanza-api`` has no refresh mechanism -- the session is
    established once and dies after ``maxInactiveMinutes``. We detect the
    resulting 401 and rebuild the client transparently.
  * **Thread offloading.** The library is synchronous (``requests``). Calling it
    directly from an async tool would stall the event loop, so every call goes
    through ``asyncio.to_thread``.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import os
import sys
from typing import Any

import requests
from avanza import Avanza
from avanza.credentials import SecretCredentials

from .guard import ReadOnlyViolationError, harden, verify_hardened

__all__ = ["ReadOnlyAvanzaClient", "AvanzaConfigError", "AvanzaAuthError", "get_client"]

ENV_USERNAME = "AVANZA_USERNAME"
ENV_PASSWORD = "AVANZA_PASSWORD"
ENV_TOTP_SECRET = "AVANZA_TOTP_SECRET"


class AvanzaConfigError(RuntimeError):
    """Credentials are missing or malformed."""


class AvanzaAuthError(RuntimeError):
    """Authentication against Avanza failed."""


class ReadOnlyAvanzaClient:
    """Owns a single hardened ``Avanza`` session and serialises access to it."""

    def __init__(self, username: str, password: str, totp_secret: str) -> None:
        self._username = username
        self._password = password
        self._totp_secret = totp_secret
        self._client: Avanza | None = None
        self._lock = asyncio.Lock()

    # -- authentication ----------------------------------------------------

    def _login(self) -> Avanza:
        """Blocking login. Always run via ``asyncio.to_thread``."""
        credentials = SecretCredentials(
            username=self._username,
            password=self._password,
            totp_secret=self._totp_secret,
        )
        # quiet=True stops the library printing to stdout, which would corrupt the
        # MCP stdio stream. redirect_stdout is a backstop in case a future version
        # prints anyway -- anything it emits is forwarded to stderr instead.
        captured = io.StringIO()
        try:
            with contextlib.redirect_stdout(captured):
                client = Avanza(credentials, retry_with_next_otp=True, quiet=True)
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else "unknown"
            if status == 401:
                raise AvanzaAuthError(
                    "Avanza rejected the credentials (401). Check username, password "
                    "and TOTP secret, and that the clock is in sync. Re-run "
                    "scripts/setup-credentials.sh to update them."
                ) from exc
            raise AvanzaAuthError(f"Login failed with HTTP {status}.") from exc
        except Exception as exc:  # noqa: BLE001 - surfaced to the user as a tool error
            raise AvanzaAuthError(f"Login failed: {type(exc).__name__}: {exc}") from exc
        finally:
            leaked = captured.getvalue()
            if leaked:
                print(f"[avanza-mcp] library stdout: {leaked}", file=sys.stderr)

        harden(client)
        verify_hardened(client)  # fail loudly if the guard did not take effect
        return client

    async def _ensure_client(self) -> Avanza:
        if self._client is None:
            async with self._lock:
                if self._client is None:  # re-check: another task may have won the race
                    self._client = await asyncio.to_thread(self._login)
        return self._client

    async def _reauthenticate(self) -> Avanza:
        async with self._lock:
            self._client = None
            self._client = await asyncio.to_thread(self._login)
            return self._client

    # -- calling -----------------------------------------------------------

    async def call(self, method_name: str, *args: Any, **kwargs: Any) -> Any:
        """Invoke a read method on the hardened client, renewing the session if needed.

        Args:
            method_name: Name of the ``Avanza`` method to call. Must be a read
                method; anything mutating is blocked by the guard.

        Raises:
            ReadOnlyViolationError: The call was not a permitted read.
            AvanzaAuthError: Authentication failed or could not be renewed.
        """
        client = await self._ensure_client()

        try:
            return await self._invoke(client, method_name, *args, **kwargs)
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            if status != 401:
                raise
            # Session expired (no refresh mechanism exists) -- rebuild once and retry.
            print(
                "[avanza-mcp] session expired; re-authenticating.",
                file=sys.stderr,
            )
            client = await self._reauthenticate()
            return await self._invoke(client, method_name, *args, **kwargs)

    @staticmethod
    async def _invoke(client: Avanza, method_name: str, *args: Any, **kwargs: Any) -> Any:
        method = getattr(client, method_name, None)
        if method is None or not callable(method):
            raise ReadOnlyViolationError(f"No such method: {method_name}")
        return await asyncio.to_thread(method, *args, **kwargs)


# ---------------------------------------------------------------------------
# Process-wide singleton
# ---------------------------------------------------------------------------

_client: ReadOnlyAvanzaClient | None = None


def get_client() -> ReadOnlyAvanzaClient:
    """Return the shared client, constructing it from the environment on first use.

    Credentials are read from the environment, which the launcher script populates
    from the macOS Keychain via ``--env-file /dev/fd/N``. They are never written
    to disk by this process.
    """
    global _client
    if _client is not None:
        return _client

    missing = [
        name
        for name in (ENV_USERNAME, ENV_PASSWORD, ENV_TOTP_SECRET)
        if not os.environ.get(name)
    ]
    if missing:
        raise AvanzaConfigError(
            f"Missing credentials: {', '.join(missing)}. "
            "Run scripts/setup-credentials.sh to store them in the macOS Keychain, "
            "and start the server via scripts/avanza-mcp-launcher.sh."
        )

    _client = ReadOnlyAvanzaClient(
        username=os.environ[ENV_USERNAME],
        password=os.environ[ENV_PASSWORD],
        totp_secret=os.environ[ENV_TOTP_SECRET],
    )
    return _client
