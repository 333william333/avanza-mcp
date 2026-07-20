"""Tests for the read-only guard.

These are the most important tests in the project. The server's entire safety
claim rests on the assertions here.
"""

from __future__ import annotations

import re

import pytest
from avanza import Avanza
from avanza.constants import HttpMethod, Route

from avanza_mcp import guard
from avanza_mcp.guard import (
    MUTATING_METHODS,
    READ_ROUTES,
    WRITE_ROUTES,
    ReadOnlyViolationError,
    assert_allowed,
    is_allowed,
    unreviewed_methods,
)

ALL_VERBS = list(HttpMethod)


def fill(template: str, value: str = "12345") -> str:
    """Turn a route template into a concrete path, as ``__call`` would receive it."""
    return template.replace("{}", value)


# ---------------------------------------------------------------------------
# The core guarantee: writes are refused
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("route", sorted(WRITE_ROUTES, key=lambda r: r.name))
def test_write_routes_refused_with_their_real_verb(route: Route) -> None:
    """Each mutating route is refused with the verb the library actually uses.

    Includes the two writes that are POSTs (order/delete, watchlist/remove),
    which a naive verb-based rule would let through.
    """
    for verb in WRITE_ROUTES[route]:
        assert not is_allowed(verb, fill(route.value))
        with pytest.raises(ReadOnlyViolationError):
            assert_allowed(verb, fill(route.value))


@pytest.mark.parametrize("route", sorted(WRITE_ROUTES, key=lambda r: r.name))
@pytest.mark.parametrize("verb", ALL_VERBS)
def test_write_routes_refused_with_every_verb(route: Route, verb: HttpMethod) -> None:
    """Mutating routes are refused under *any* verb, not just their usual one."""
    assert not is_allowed(verb, fill(route.value))


def test_no_read_pattern_matches_any_write_path() -> None:
    """No read route's regex may match a mutating route's path.

    This is the property that makes the allowlist trustworthy: it catches an
    over-broad pattern (e.g. one that lets ``/watchlist/watchlist/remove/1/2``
    match the ``/watchlist/watchlist`` template) regardless of verb.
    """
    offenders = []
    for write_route in WRITE_ROUTES:
        path = fill(write_route.value)
        matched = guard.matched_route(path)
        if matched is not None:
            offenders.append((write_route.name, path, matched))
    assert offenders == [], f"read patterns leak onto write paths: {offenders}"


def test_auth_paths_are_not_on_the_allowlist() -> None:
    """Auth POSTs bypass __call, so they must not need (or have) an allowlist entry."""
    for route in (Route.AUTHENTICATION_PATH, Route.TOTP_PATH):
        for verb in ALL_VERBS:
            assert not is_allowed(verb, fill(route.value))


# ---------------------------------------------------------------------------
# Reads still work
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("route", sorted(READ_ROUTES, key=lambda r: r.name))
def test_read_routes_allowed_with_their_real_verb(route: Route) -> None:
    """Each read route passes with the verb the library actually uses.

    Covers the two reads that are POSTs (filtered-search, account-performance
    chart), which a naive verb-based rule would wrongly block.
    """
    for verb in READ_ROUTES[route]:
        assert is_allowed(verb, fill(route.value)), f"{route.name} {verb.name} blocked"
        assert_allowed(verb, fill(route.value))


def test_the_two_post_reads_are_permitted() -> None:
    """Explicit regression test for the finding that drove the whole design."""
    assert is_allowed(HttpMethod.POST, "/_api/search/filtered-search")
    assert is_allowed(
        HttpMethod.POST,
        "/_api/account-performance/overview/chart/accounts/timeperiod",
    )


def test_the_two_post_writes_are_refused() -> None:
    """The mirror image: POST writes that a verb-based rule would miss."""
    assert not is_allowed(HttpMethod.POST, "/_api/trading-critical/rest/order/delete")
    assert not is_allowed(HttpMethod.POST, "/_api/trading-critical/rest/order/new")
    assert not is_allowed(HttpMethod.POST, "/_api/watchlist/watchlist/remove/1/2")


def test_read_routes_refused_under_wrong_verb() -> None:
    """A read route does not become a write channel by swapping the verb."""
    for route, verbs in READ_ROUTES.items():
        for verb in ALL_VERBS:
            if verb not in verbs:
                assert not is_allowed(verb, fill(route.value))


# ---------------------------------------------------------------------------
# Specific traps
# ---------------------------------------------------------------------------


def test_price_alert_is_get_only() -> None:
    """One path, three meanings: GET reads, POST sets, DELETE removes."""
    path = "/_cqbe/marketing/service/alert/12345"
    assert is_allowed(HttpMethod.GET, path)
    assert not is_allowed(HttpMethod.POST, path)
    assert not is_allowed(HttpMethod.DELETE, path)


def test_watchlist_prefix_confusion() -> None:
    """The read template must not swallow its add/remove siblings."""
    assert is_allowed(HttpMethod.GET, "/_api/watchlist/watchlist")
    assert not is_allowed(HttpMethod.GET, "/_api/watchlist/watchlist/add/1/2")
    assert not is_allowed(HttpMethod.POST, "/_api/watchlist/watchlist/remove/1/2")


def test_stop_loss_prefix_confusion() -> None:
    """GET /trading/stoploss reads; POST /trading/stoploss/new writes."""
    assert is_allowed(HttpMethod.GET, "/_api/trading/stoploss")
    assert not is_allowed(HttpMethod.POST, "/_api/trading/stoploss/new")
    assert not is_allowed(HttpMethod.DELETE, "/_api/trading/stoploss/1/2")


def test_monthly_savings_read_and_write_paths_differ() -> None:
    """Read lives under /_mobile, writes under /_api -- verify we track that."""
    assert is_allowed(HttpMethod.GET, "/_mobile/transfer/monthly-savings/123")
    assert not is_allowed(HttpMethod.POST, "/_api/transfer/monthly-savings/123")
    assert not is_allowed(HttpMethod.PUT, "/_api/transfer/monthly-savings/1/2/pause")


def test_placeholders_cannot_span_path_segments() -> None:
    """A crafted id must not be able to walk into another endpoint."""
    assert not is_allowed(HttpMethod.GET, "/_api/market-guide/stock/../../foo/analysis")
    assert not is_allowed(
        HttpMethod.GET, "/_api/price-chart/stock/x/../../trading-critical/rest/order/new"
    )


def test_traversal_segments_refused_outright() -> None:
    assert not is_allowed(HttpMethod.GET, "/_api/watchlist/watchlist/..")


def test_unknown_paths_refused() -> None:
    """Default-deny."""
    for path in ("/", "/_api/", "/_api/unknown/thing", "/_api/trading/rest/orders/extra"):
        assert not is_allowed(HttpMethod.GET, path)


def test_query_string_templates_match() -> None:
    """Two read templates embed a query string; ? and & must be escaped, not regex."""
    assert is_allowed(
        HttpMethod.GET, "/_api/trading-critical/rest/order/find?orderId=1&cAccountId=2"
    )
    assert is_allowed(
        HttpMethod.GET, "/_api/insights-development/?timePeriod=TODAY&accountIds=123"
    )


def test_inspiration_list_accepts_empty_placeholder() -> None:
    """get_inspiration_lists() formats its template with an empty string."""
    assert is_allowed(HttpMethod.GET, "/_mobile/marketing/inspirationlist/")


# ---------------------------------------------------------------------------
# Upgrade regression: catch a library that changes under us
# ---------------------------------------------------------------------------


def test_no_unreviewed_methods() -> None:
    """Every public method on Avanza is classified as read or mutating.

    If avanza-api is upgraded and adds a method, this fails -- forcing a review
    of the route tables instead of silently trusting the new version.
    """
    assert unreviewed_methods(Avanza) == set()


def test_every_route_is_classified() -> None:
    """Every Route enum member is read, write, or auth. No gaps."""
    classified = set(READ_ROUTES) | set(WRITE_ROUTES) | set(guard.AUTH_ROUTES)
    assert set(Route) - classified == set()


def test_mutating_method_list_matches_library() -> None:
    """Cross-check MUTATING_METHODS against what the library source actually does.

    Any method whose source references a known write route must be in the list.
    """
    import inspect

    write_names = {r.name for r in WRITE_ROUTES}
    for name in dir(Avanza):
        if name.startswith("_"):
            continue
        member = getattr(Avanza, name, None)
        if not callable(member):
            continue
        try:
            source = inspect.getsource(member)
        except (OSError, TypeError):
            continue
        referenced = set(re.findall(r"Route\.(\w+)", source))
        if referenced & write_names:
            assert name in MUTATING_METHODS, f"{name} touches a write route but is not blocked"


# ---------------------------------------------------------------------------
# L2: instance hardening
# ---------------------------------------------------------------------------


class _FakeAvanza(Avanza):
    """An Avanza instance without the network login, for testing harden()."""

    def __init__(self) -> None:  # noqa: D107 - deliberately skips Avanza.__init__
        self.calls: list[tuple[HttpMethod, str]] = []

        def _call(method, path, options=None, return_content=False):
            self.calls.append((method, path))
            return {"ok": True}

        self._Avanza__call = _call  # type: ignore[attr-defined]


@pytest.fixture()
def hardened() -> _FakeAvanza:
    return guard.harden(_FakeAvanza())


@pytest.mark.parametrize("name", sorted(MUTATING_METHODS))
def test_harden_blocks_every_mutating_method(hardened: _FakeAvanza, name: str) -> None:
    with pytest.raises(ReadOnlyViolationError):
        getattr(hardened, name)()


def test_harden_blocks_place_order_before_any_network_call(hardened: _FakeAvanza) -> None:
    """The headline case: placing an order never reaches the HTTP layer."""
    with pytest.raises(ReadOnlyViolationError):
        hardened.place_order(
            account_id="1", order_book_id="2", order_type="BUY", price=1.0,
            valid_until="2030-01-01", volume=1,
        )
    assert hardened.calls == []


def test_harden_allows_reads_through(hardened: _FakeAvanza) -> None:
    result = hardened._Avanza__call(HttpMethod.GET, "/_api/position-data/positions")
    assert result == {"ok": True}
    assert hardened.calls == [(HttpMethod.GET, "/_api/position-data/positions")]


def test_harden_blocks_writes_at_the_http_layer(hardened: _FakeAvanza) -> None:
    """Even bypassing the method wrappers, the chokepoint refuses."""
    with pytest.raises(ReadOnlyViolationError):
        hardened._Avanza__call(
            HttpMethod.POST, "/_api/trading-critical/rest/order/new", {"volume": 1}
        )
    assert hardened.calls == []


def test_harden_is_idempotent() -> None:
    client = guard.harden(guard.harden(_FakeAvanza()))
    guard.verify_hardened(client)
    with pytest.raises(ReadOnlyViolationError):
        client.delete_order("1", "2")


def test_verify_hardened_rejects_an_unguarded_client() -> None:
    with pytest.raises(ReadOnlyViolationError):
        guard.verify_hardened(_FakeAvanza())


def test_verify_hardened_accepts_a_guarded_client(hardened: _FakeAvanza) -> None:
    guard.verify_hardened(hardened)
