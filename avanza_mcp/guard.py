"""Read-only enforcement for the Avanza client.

This module is the security core of the server. It exists because **HTTP verb
alone cannot distinguish reads from writes in Avanza's API**:

  * ``POST /_api/search/filtered-search``  is a read (instrument search)
  * ``POST /_api/trading-critical/rest/order/delete``  is a write (cancels an order)

A "block all POST" rule would therefore both break search and fail to block
order cancellation. Path prefixes are equally useless: ``get_order_book`` and
``get_market_data`` live under ``trading-critical/`` despite being pure reads.

So the guard is an explicit allowlist of ``(route template, verb)`` pairs,
matched with ``re.fullmatch``. Anything not on the list is refused.

Two layers are applied by :func:`harden`:

  L1  Wrap ``Avanza.__call`` -- the single chokepoint every post-login request
      passes through -- and enforce the route allowlist.
  L2  Replace every known-mutating method on the instance with a raiser, and
      fail closed on any public method we do not recognise (so a library
      upgrade that adds a new mutating method is blocked by default rather
      than silently permitted).

The two authentication POSTs bypass ``__call`` entirely (they use
``self._session.post`` directly), so they are unaffected by L1.
"""

from __future__ import annotations

import re
import sys
from typing import Any, Callable

from avanza import Avanza
from avanza.constants import HttpMethod, Route

__all__ = [
    "ReadOnlyViolationError",
    "READ_ROUTES",
    "MUTATING_METHODS",
    "READ_METHODS",
    "is_allowed",
    "assert_allowed",
    "harden",
]

GET = HttpMethod.GET
POST = HttpMethod.POST


class ReadOnlyViolationError(RuntimeError):
    """Raised when something attempts an operation that is not a permitted read.

    This is a bug-or-attack signal, never an expected condition. If you see it,
    either the code tried to mutate account state, or ``avanza-api`` changed a
    route and the allowlist below needs re-review.
    """


# ---------------------------------------------------------------------------
# L1: route allowlist
# ---------------------------------------------------------------------------

# Every route we permit, with the exact verb(s) allowed for it. Verified against
# avanza-api 16.1.0 by introspecting `Route` and each method's source.
#
# PRICE_ALERT_PATH is deliberately GET-only: the same path serves set_price_alert
# (POST) and delete_price_alert (DELETE), both of which are writes.
READ_ROUTES: dict[Route, frozenset[HttpMethod]] = {
    Route.ACCOUNTS_POSITIONS_PATH: frozenset({GET}),
    Route.ACCOUNT_PERFORMANCE_CHART_PATH: frozenset({POST}),  # a read, despite POST
    Route.ANALYSIS_PATH: frozenset({GET}),
    Route.CATEGORIZED_ACCOUNTS: frozenset({GET}),
    Route.CHARTDATA_PATH: frozenset({GET}),
    Route.CREDITINFO_PATH: frozenset({GET}),
    Route.CURRENT_OFFERS_PATH: frozenset({GET}),
    Route.DEALS_PATH: frozenset({GET}),
    Route.ETF_DETAILS_PATH: frozenset({GET}),
    Route.ORDERS_PATH: frozenset({GET}),
    Route.FORUM_PATH: frozenset({GET}),
    Route.FUND_PATH: frozenset({GET}),
    Route.INSIGHTS_PATH: frozenset({GET}),
    Route.INSPIRATION_LIST_PATH: frozenset({GET}),
    Route.INSTRUMENT_PATH: frozenset({GET}),
    Route.INSTRUMENT_DETAILS_PATH: frozenset({GET}),
    Route.INSTRUMENT_SEARCH_PATH: frozenset({POST}),  # a read, despite POST
    Route.MARKETDATA_PATH: frozenset({GET}),
    Route.MONTHLY_SAVINGS_PATH: frozenset({GET}),
    Route.NEWS_PATH: frozenset({GET}),
    Route.NOTE_PATH: frozenset({GET}),
    Route.ORDER_GET_PATH: frozenset({GET}),
    Route.ORDERBOOK_PATH: frozenset({GET}),
    Route.PRICE_ALERT_PATH: frozenset({GET}),  # GET only -- POST/DELETE are writes
    Route.STOP_LOSS_PATH: frozenset({GET}),
    Route.TRANSACTIONS_DETAILS_PATH: frozenset({GET}),
    Route.WATCHLISTS_PATH: frozenset({GET}),
}

# Routes that mutate account state. Not used for matching -- the allowlist is
# default-deny, so these are already blocked -- but the test suite asserts each
# one is refused with its real verb, which is what makes that guarantee visible.
WRITE_ROUTES: dict[Route, frozenset[HttpMethod]] = {
    Route.MONTHLY_SAVINGS_CREATE_PATH: frozenset({POST}),
    Route.MONTHLY_SAVINGS_PAUSE_PATH: frozenset({HttpMethod.PUT}),
    Route.MONTHLY_SAVINGS_REMOVE_PATH: frozenset({HttpMethod.DELETE}),
    Route.MONTHLY_SAVINGS_RESUME_PATH: frozenset({HttpMethod.PUT}),
    Route.ORDER_DELETE_PATH: frozenset({POST}),  # a write, despite POST
    Route.ORDER_DELETE_STOP_LOSS_PATH: frozenset({HttpMethod.DELETE}),
    Route.ORDER_EDIT_PATH: frozenset({POST}),
    Route.ORDER_PLACE_PATH: frozenset({POST}),
    Route.ORDER_PLACE_PATH_BUY_FUND: frozenset({POST}),
    Route.ORDER_PLACE_PATH_SELL_FUND: frozenset({POST}),
    Route.ORDER_PLACE_STOP_LOSS_PATH: frozenset({POST}),
    Route.WATCHLISTS_ADD_PATH: frozenset({POST}),
    Route.WATCHLISTS_REMOVE_PATH: frozenset({POST}),  # a write, despite POST
}

# Authentication routes bypass __call (they use _session.post directly), so they
# never reach the guard. Listed for documentation completeness only.
AUTH_ROUTES = frozenset({Route.AUTHENTICATION_PATH, Route.TOTP_PATH})


def _template_to_regex(template: str) -> re.Pattern[str]:
    """Compile an Avanza route template into an anchored regex.

    ``{}`` placeholders become ``[^/]*``. Excluding ``/`` from placeholders is a
    deliberate safety property: it stops a crafted id from walking the path into
    a different (possibly mutating) endpoint. ``*`` rather than ``+`` because
    ``get_inspiration_lists`` formats its template with an empty string.

    Literal segments are regex-escaped, which matters for the two templates that
    embed a query string (``?``, ``&`` are regex-significant).
    """
    return re.compile("[^/]*".join(re.escape(part) for part in template.split("{}")))


_ALLOWLIST: tuple[tuple[re.Pattern[str], frozenset[HttpMethod], str], ...] = tuple(
    (_template_to_regex(route.value), verbs, route.name)
    for route, verbs in READ_ROUTES.items()
)


def is_allowed(method: HttpMethod, path: str) -> bool:
    """Return True if this exact (verb, path) pair is a permitted read."""
    if ".." in path:
        return False
    for pattern, verbs, _name in _ALLOWLIST:
        if method in verbs and pattern.fullmatch(path):
            return True
    return False


def matched_route(path: str) -> str | None:
    """Return the name of the read route this path matches, if any (for errors)."""
    for pattern, _verbs, name in _ALLOWLIST:
        if pattern.fullmatch(path):
            return name
    return None


def assert_allowed(method: HttpMethod, path: str) -> None:
    """Raise :class:`ReadOnlyViolationError` unless this is a permitted read."""
    if is_allowed(method, path):
        return
    route = matched_route(path)
    if route is not None:
        detail = (
            f"route {route} is read-only here and permits only "
            f"{sorted(v.name for v in READ_ROUTES[Route[route]])}"
        )
    else:
        detail = "path is not on the read allowlist"
    raise ReadOnlyViolationError(
        f"Blocked {method.name} {path}: {detail}. "
        "This server is strictly read-only and cannot place, modify or cancel orders."
    )


# ---------------------------------------------------------------------------
# L2: method-level blocking
# ---------------------------------------------------------------------------

# Every method on avanza.Avanza that mutates account state (avanza-api 16.1.0).
MUTATING_METHODS = frozenset(
    {
        "add_to_watchlist",
        "create_monthly_saving",
        "delete_monthly_saving",
        "delete_order",
        "delete_price_alert",
        "delete_stop_loss_order",
        "edit_order",
        "pause_monthly_saving",
        "place_order",
        "place_order_buy_fund",
        "place_order_sell_fund",
        "place_stop_loss_order",
        "remove_from_watchlist",
        "resume_monthly_saving",
        "set_price_alert",
    }
)

# Every method we have reviewed and confirmed to be a read (avanza-api 16.1.0).
READ_METHODS = frozenset(
    {
        "get_account_performance_chart_data",
        "get_accounts_positions",
        "get_all_monthly_savings",
        "get_all_stop_losses",
        "get_analysis",
        "get_certificate_details",
        "get_certificate_info",
        "get_chart_data",
        "get_credit_info",
        "get_deals",
        "get_etf_details",
        "get_forum_posts",
        "get_fund_info",
        "get_index_info",
        "get_insights_report",
        "get_inspiration_list",
        "get_inspiration_lists",
        "get_instrument",
        "get_instrument_details",
        "get_market_data",
        "get_monthly_savings_by_account_id",
        "get_news",
        "get_note_as_pdf",
        "get_offers",
        "get_order",
        "get_order_book",
        "get_orders",
        "get_overview",
        "get_price_alert",
        "get_stock_info",
        "get_transactions_details",
        "get_warrant_info",
        "get_watchlists",
        "search_for_certificate",
        "search_for_fund",
        "search_for_instrument",
        "search_for_stock",
        "search_for_warrant",
    }
)


def _public_methods(cls: type) -> set[str]:
    return {
        name
        for name in dir(cls)
        if not name.startswith("_") and callable(getattr(cls, name, None))
    }


def unreviewed_methods(cls: type = Avanza) -> set[str]:
    """Public methods that are in neither the read nor the mutating list.

    A non-empty result means ``avanza-api`` changed under us. The test suite
    asserts this is empty, and :func:`harden` blocks these at runtime.
    """
    return _public_methods(cls) - READ_METHODS - MUTATING_METHODS


def _blocked(name: str, reason: str) -> Callable[..., Any]:
    def _raise(*_args: Any, **_kwargs: Any) -> Any:
        raise ReadOnlyViolationError(
            f"Blocked call to {name}(): {reason}. "
            "This server is strictly read-only and cannot place, modify or cancel orders."
        )

    _raise.__name__ = name
    _raise.__avanza_mcp_blocked__ = True  # type: ignore[attr-defined]
    return _raise


def harden(client: Avanza) -> Avanza:
    """Apply both read-only layers to a live ``Avanza`` instance.

    Returns the same object, mutated in place. Safe to call more than once.
    """
    # -- L1: guard the single HTTP chokepoint -------------------------------
    # Avanza.__call is name-mangled to _Avanza__call. Class methods invoke it as
    # self._Avanza__call(...), so an instance attribute shadows the class method.
    original = getattr(client, "_Avanza__call")
    if getattr(original, "__avanza_mcp_guarded__", False):
        return client  # already hardened

    def guarded_call(
        method: HttpMethod,
        path: str,
        options: Any = None,
        return_content: bool = False,
    ) -> Any:
        assert_allowed(method, path)
        return original(method, path, options, return_content)

    guarded_call.__avanza_mcp_guarded__ = True  # type: ignore[attr-defined]
    setattr(client, "_Avanza__call", guarded_call)

    # -- L2: block mutating methods, and fail closed on unknown ones --------
    for name in MUTATING_METHODS:
        if hasattr(client, name):
            setattr(client, name, _blocked(name, "this method mutates account state"))

    for name in sorted(unreviewed_methods(type(client))):
        print(
            f"[avanza-mcp] WARNING: unreviewed method {name!r} in avanza-api; "
            "blocking it. Re-review guard.py against the new library version.",
            file=sys.stderr,
        )
        setattr(
            client,
            name,
            _blocked(name, "method is not on the reviewed read-only allowlist"),
        )

    return client


def verify_hardened(client: Avanza) -> None:
    """Sanity-check that :func:`harden` actually took effect.

    Called right after authentication so a refactor that breaks the guard fails
    loudly and immediately rather than at the first tool call. Checks for our
    marker attributes rather than invoking the methods -- we never want to call
    a mutating method, even speculatively.
    """
    if not getattr(getattr(client, "_Avanza__call", None), "__avanza_mcp_guarded__", False):
        raise ReadOnlyViolationError("HTTP guard is not installed; refusing to serve.")

    unblocked = [
        name
        for name in sorted(MUTATING_METHODS | unreviewed_methods(type(client)))
        if hasattr(client, name)
        and not getattr(getattr(client, name), "__avanza_mcp_blocked__", False)
    ]
    if unblocked:
        raise ReadOnlyViolationError(
            f"These methods are not blocked: {unblocked}. Refusing to serve."
        )
