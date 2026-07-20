"""Tests for credential handling and leak prevention.

Every test here exists because of a defect found in adversarial audit that the
original suite could not have caught: it monkeypatched the whole client, so no
test ever constructed real credentials or exercised a real login failure path.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
import requests
from avanza.credentials import SecretCredentials
from pydantic import ValidationError

from avanza_mcp import client as client_mod
from avanza_mcp import redaction
from avanza_mcp.client import AvanzaAuthError, AvanzaConfigError, ReadOnlyAvanzaClient
from avanza_mcp.formatting import ResponseFormat, handle_error, render

USERNAME = "min.epost@example.com"
PASSWORD = "MittSuperHemligaLosenord123"
TOTP_SEED = "JBSWY3DPEHPK3PXP"
ALL_SECRETS = (USERNAME, PASSWORD, TOTP_SEED)


@pytest.fixture(autouse=True)
def _clean_secret_registry():
    redaction.clear_secrets()
    yield
    redaction.clear_secrets()


# ---------------------------------------------------------------------------
# The login bug: credentials must actually be constructible
# ---------------------------------------------------------------------------


def test_credentials_can_be_constructed_the_way_login_does() -> None:
    """Regression: `totp_secret=` is ALIAS-ONLY and silently breaks every login.

    The library declares `totp_secret: str = Field(..., alias="totpSecret")` with no
    populate_by_name, so under pydantic 2 the snake_case keyword is rejected. This
    failed on every single login while all 155 other tests passed.
    """
    credentials = SecretCredentials(
        username=USERNAME, password=PASSWORD, totpSecret=TOTP_SEED
    )
    assert credentials.totp_secret == TOTP_SEED


def test_snake_case_keyword_is_still_rejected_by_the_library() -> None:
    """Pins the reason for the above. If this ever passes, the library changed."""
    with pytest.raises(ValidationError):
        SecretCredentials(username=USERNAME, password=PASSWORD, totp_secret=TOTP_SEED)


# ---------------------------------------------------------------------------
# The leak: no credential may reach the model
# ---------------------------------------------------------------------------


def test_validation_error_never_leaks_its_input() -> None:
    """pydantic embeds `input_value={...}` -- for a credentials model, the secrets."""
    try:
        SecretCredentials(username=USERNAME, password=PASSWORD, totp_secret=TOTP_SEED)
    except ValidationError as exc:
        assert TOTP_SEED in str(exc), "premise check: the raw error does embed the seed"
        message = handle_error(exc)
        for secret in ALL_SECRETS:
            assert secret not in message, f"{secret!r} leaked via handle_error"
    else:
        pytest.fail("expected a ValidationError")


def test_unknown_exception_messages_are_withheld() -> None:
    """An arbitrary exception's text may quote request data, so it is not forwarded."""
    message = handle_error(RuntimeError(f"connection failed while sending {TOTP_SEED}"))
    assert TOTP_SEED not in message
    assert "RuntimeError" in message  # the type is still useful and safe


def test_redaction_scrubs_registered_secrets() -> None:
    redaction.register_secret(TOTP_SEED)
    assert TOTP_SEED not in redaction.redact(f"leaked: {TOTP_SEED} here")
    assert redaction.PLACEHOLDER in redaction.redact(f"leaked: {TOTP_SEED} here")


def test_redaction_ignores_values_too_short_to_be_distinctive() -> None:
    """Avoids mangling ordinary text that happens to contain a short value."""
    redaction.register_secret("abc")
    assert redaction.redact("abc appears in many words") == "abc appears in many words"


def test_rendered_tool_output_is_redacted() -> None:
    """Backstop: even a payload echoing a secret is scrubbed on the way out."""
    redaction.register_secret(TOTP_SEED)
    out = render({"echo": f"value {TOTP_SEED}"}, ResponseFormat.JSON, "T")
    assert TOTP_SEED not in out


def test_constructing_the_client_registers_its_secrets() -> None:
    ReadOnlyAvanzaClient(USERNAME, PASSWORD, TOTP_SEED)
    for secret in ALL_SECRETS:
        assert redaction.PLACEHOLDER in redaction.redact(f"x {secret} y")


# ---------------------------------------------------------------------------
# Login failure paths must stay credential-free
# ---------------------------------------------------------------------------


def _login_raising(exc: Exception):
    def _factory(*_args: Any, **_kwargs: Any):
        raise exc

    return _factory


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(RuntimeError(f"boom {PASSWORD}"), id="generic"),
        pytest.param(ValueError(f"bad totp {TOTP_SEED}"), id="value-error"),
    ],
)
def test_login_failure_messages_contain_no_credentials(
    monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    monkeypatch.setattr(client_mod, "Avanza", _login_raising(failure))
    client = ReadOnlyAvanzaClient(USERNAME, PASSWORD, TOTP_SEED)

    with pytest.raises(AvanzaAuthError) as caught:
        client._login()

    message = handle_error(caught.value)
    for secret in ALL_SECRETS:
        assert secret not in str(caught.value), f"{secret!r} leaked into the exception"
        assert secret not in message, f"{secret!r} leaked into the tool response"


def test_http_401_login_failure_is_actionable_and_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = requests.Response()
    response.status_code = 401
    monkeypatch.setattr(
        client_mod, "Avanza", _login_raising(requests.HTTPError(response=response))
    )
    client = ReadOnlyAvanzaClient(USERNAME, PASSWORD, TOTP_SEED)

    with pytest.raises(AvanzaAuthError) as caught:
        client._login()
    assert "401" in str(caught.value)
    for secret in ALL_SECRETS:
        assert secret not in str(caught.value)


def test_credential_model_change_surfaces_as_config_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the library's credential model changes, fail clearly -- and without input."""

    def _reject(*_args: Any, **_kwargs: Any):
        raise SecretCredentials.__pydantic_validator__.validate_python({})  # type: ignore[misc]

    def _raise_validation(*_args: Any, **_kwargs: Any):
        SecretCredentials(username=USERNAME)  # missing fields -> ValidationError

    monkeypatch.setattr(client_mod, "SecretCredentials", _raise_validation)
    client = ReadOnlyAvanzaClient(USERNAME, PASSWORD, TOTP_SEED)

    with pytest.raises(AvanzaConfigError) as caught:
        client._login()
    for secret in ALL_SECRETS:
        assert secret not in str(caught.value)


# ---------------------------------------------------------------------------
# Config errors
# ---------------------------------------------------------------------------


def test_missing_environment_is_reported_without_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(client_mod, "_client", None)
    for name in (client_mod.ENV_USERNAME, client_mod.ENV_PASSWORD, client_mod.ENV_TOTP_SECRET):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(AvanzaConfigError) as caught:
        client_mod.get_client()
    assert "setup-credentials.sh" in str(caught.value)
