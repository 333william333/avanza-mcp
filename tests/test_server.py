"""Tests for the tool surface.

Complements test_guard.py: the guard proves writes are impossible at the HTTP
layer, these prove the exposed tool surface never even tries.
"""

from __future__ import annotations

import ast
import pathlib
from typing import Any

import pytest

from avanza_mcp import server
from avanza_mcp.guard import MUTATING_METHODS, READ_METHODS

SERVER_SOURCE = pathlib.Path(server.__file__).read_text()


# ---------------------------------------------------------------------------
# The exposed surface is read-only
# ---------------------------------------------------------------------------


@pytest.fixture()
async def tools():
    return await server.mcp.list_tools()


async def test_every_tool_is_annotated_read_only(tools) -> None:
    for tool in tools:
        assert tool.annotations.readOnlyHint is True, tool.name
        assert tool.annotations.destructiveHint is False, tool.name


async def test_no_tool_name_suggests_a_write(tools) -> None:
    forbidden = ("place", "buy", "sell", "delete", "remove", "create", "edit", "cancel")
    for tool in tools:
        assert not any(word in tool.name for word in forbidden), tool.name


async def test_every_tool_has_a_substantive_description(tools) -> None:
    for tool in tools:
        assert tool.description and len(tool.description) > 80, tool.name


async def test_all_tools_are_prefixed(tools) -> None:
    """Avoids collisions when other MCP servers are loaded alongside this one."""
    for tool in tools:
        assert tool.name.startswith("avanza_"), tool.name


def test_source_only_ever_calls_reviewed_read_methods() -> None:
    """Static check: every library method named in server.py is a reviewed read.

    Catches a typo or a copy-paste that would route a tool at a mutating method,
    without needing to execute every code path.
    """
    tree = ast.parse(SERVER_SOURCE)
    called: set[str] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
        if name == "_run":
            # _run(title, fmt, method, *args) -- method is the third argument
            if len(node.args) >= 3 and isinstance(node.args[2], ast.Constant):
                called.add(node.args[2].value)
        elif name == "_run_many":
            # _run_many(title, fmt, {section: (method, *args)})
            for arg in node.args:
                if isinstance(arg, ast.Dict):
                    for value in arg.values:
                        if isinstance(value, ast.Tuple) and value.elts:
                            first = value.elts[0]
                            if isinstance(first, ast.Constant):
                                called.add(first.value)

    # Assignments of the form calls["x"] = ("method", ...) are also used.
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Tuple):
            if node.value.elts and isinstance(node.value.elts[0], ast.Constant):
                value = node.value.elts[0].value
                if isinstance(value, str) and (
                    value in READ_METHODS or value in MUTATING_METHODS
                ):
                    called.add(value)

    assert called, "static analysis found no method names -- the test needs updating"
    assert called <= READ_METHODS, f"non-read methods referenced: {called - READ_METHODS}"
    assert not (called & MUTATING_METHODS)


# ---------------------------------------------------------------------------
# End-to-end tool execution against a fake client
# ---------------------------------------------------------------------------


class FakeClient:
    """Stands in for ReadOnlyAvanzaClient, recording which methods tools invoke."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple]] = []

    async def call(self, method_name: str, *args: Any) -> Any:
        self.calls.append((method_name, args))
        return {"name": "Volvo B", "orderBookId": "5361", "lastPrice": 275.4}


@pytest.fixture()
def fake_client(monkeypatch: pytest.MonkeyPatch) -> FakeClient:
    client = FakeClient()
    monkeypatch.setattr(server, "get_client", lambda: client)
    return client


# (tool name, arguments) covering every tool with its required fields.
TOOL_INVOCATIONS: list[tuple[str, dict[str, Any]]] = [
    ("avanza_get_overview", {}),
    ("avanza_get_positions", {}),
    ("avanza_get_account_performance", {"account_url_ids": ["abc"]}),
    ("avanza_get_transactions", {}),
    ("avanza_get_orders_and_deals", {}),
    ("avanza_search_instruments", {"query": "Volvo"}),
    ("avanza_get_instrument", {"instrument_id": "5361"}),
    ("avanza_get_price_chart", {"order_book_id": "5361"}),
    ("avanza_get_order_book", {"order_book_id": "5361"}),
    ("avanza_get_instrument_analysis", {"instrument_id": "5361"}),
    ("avanza_get_news", {"instrument_id": "5361"}),
    ("avanza_get_watchlists", {}),
    ("avanza_get_inspiration_lists", {}),
    ("avanza_get_price_alerts", {"order_book_id": "5361"}),
]


async def test_invocation_table_covers_every_tool(tools) -> None:
    assert {name for name, _ in TOOL_INVOCATIONS} == {t.name for t in tools}


@pytest.mark.parametrize("name,arguments", TOOL_INVOCATIONS)
async def test_tool_executes_and_calls_only_read_methods(
    fake_client: FakeClient, name: str, arguments: dict[str, Any]
) -> None:
    result = await server.mcp.call_tool(name, arguments)
    assert result is not None

    invoked = {method for method, _ in fake_client.calls}
    assert invoked, f"{name} invoked no library method"
    assert invoked <= READ_METHODS, f"{name} invoked non-read methods: {invoked}"


async def test_detailed_flag_switches_to_the_details_endpoint(
    fake_client: FakeClient,
) -> None:
    await server.mcp.call_tool(
        "avanza_get_instrument", {"instrument_id": "5361", "detailed": True}
    )
    assert fake_client.calls[0][0] == "get_instrument_details"


async def test_optional_sections_are_not_fetched_by_default(
    fake_client: FakeClient,
) -> None:
    await server.mcp.call_tool("avanza_get_news", {"instrument_id": "5361"})
    assert [m for m, _ in fake_client.calls] == ["get_news"]

    fake_client.calls.clear()
    await server.mcp.call_tool(
        "avanza_get_news", {"instrument_id": "5361", "include_forum": True}
    )
    assert sorted(m for m, _ in fake_client.calls) == ["get_forum_posts", "get_news"]


async def test_orders_tool_with_no_sections_explains_itself(
    fake_client: FakeClient,
) -> None:
    await server.mcp.call_tool(
        "avanza_get_orders_and_deals",
        {"include_orders": False, "include_deals": False, "include_stop_losses": False},
    )
    assert fake_client.calls == []


async def test_one_failing_section_does_not_sink_the_others(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing analyst report must not hide the price data beside it."""

    class PartiallyFailingClient(FakeClient):
        async def call(self, method_name: str, *args: Any) -> Any:
            if method_name == "get_market_data":
                raise RuntimeError("no market data")
            return await super().call(method_name, *args)

    monkeypatch.setattr(server, "get_client", lambda: PartiallyFailingClient())
    result = await server.mcp.call_tool("avanza_get_order_book", {"order_book_id": "5361"})
    text = str(result)
    assert "Volvo B" in text  # the order book section survived
    assert "no market data" in text  # and the failure is reported, not swallowed


async def test_invalid_arguments_are_rejected_by_validation(
    fake_client: FakeClient,
) -> None:
    with pytest.raises(Exception):
        await server.mcp.call_tool("avanza_search_instruments", {"query": "x", "limit": 999})
    assert fake_client.calls == []
