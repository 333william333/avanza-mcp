"""Read-only MCP server for Avanza.

Exposes a curated set of read tools over an Avanza account. There are deliberately
no tools for placing, modifying or cancelling orders -- and the guard in
:mod:`avanza_mcp.guard` makes such an operation impossible even if a tool tried.

Tools take flat arguments rather than a single nested object, so the schema the
model sees is ``{"query": "Volvo"}`` rather than ``{"params": {"query": "Volvo"}}``.
"""

from __future__ import annotations

import asyncio
import datetime as dt
from typing import Annotated, Any, Optional

from avanza.constants import (
    InsightsReportTimePeriod,
    InstrumentType,
    Resolution,
    TimePeriod,
    TransactionsDetailsType,
)
from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .client import get_client
from .formatting import ResponseFormat, handle_error, render, to_plain

mcp = FastMCP("avanza_mcp")

# Every tool in this server is a read. These annotations are attached to all of
# them; they are hints for the client, while guard.py provides the enforcement.
READ_ONLY = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}

Fmt = Annotated[
    ResponseFormat,
    Field(description="'markdown' for a compact summary, 'json' for the full payload."),
]
OrderBookId = Annotated[
    str,
    Field(
        description="The instrument's orderBookId, from avanza_search_instruments or a position.",
        min_length=1,
        max_length=64,
    ),
]


async def _run(title: str, fmt: ResponseFormat, method: str, *args: Any) -> str:
    """Call one read method and render the result."""
    try:
        data = await get_client().call(method, *args)
        return render(data, fmt, title)
    except Exception as exc:  # noqa: BLE001 - converted to an agent-readable message
        return handle_error(exc)


async def _run_many(title: str, fmt: ResponseFormat, calls: dict[str, tuple]) -> str:
    """Call several read methods concurrently and render them under one heading.

    Args:
        calls: Mapping of section name -> ``(method_name, *args)``.

    A failure in one section is reported inline rather than failing the whole tool,
    so a missing analyst report does not hide the price data next to it.
    """
    client = get_client()
    names = list(calls)
    try:
        results = await asyncio.gather(
            *(client.call(calls[n][0], *calls[n][1:]) for n in names),
            return_exceptions=True,
        )
    except Exception as exc:  # noqa: BLE001
        return handle_error(exc)

    combined: dict[str, Any] = {}
    for name, result in zip(names, results):
        combined[name] = (
            {"error": handle_error(result)}
            if isinstance(result, Exception)
            else to_plain(result)
        )
    return render(combined, fmt, title)


# ---------------------------------------------------------------------------
# Account and portfolio
# ---------------------------------------------------------------------------


@mcp.tool(name="avanza_get_overview", annotations={"title": "Account Overview", **READ_ONLY})
async def avanza_get_overview(response_format: Fmt = ResponseFormat.MARKDOWN) -> str:
    """Get an overview of all Avanza accounts: type, balance, total value and return.

    Start here. The account identifiers this returns are needed by other tools --
    note that Avanza uses two different ones, `accountId` and `urlParameterId`.

    Args:
        response_format (ResponseFormat): 'markdown' (default) or 'json'.

    Returns:
        str: Accounts with id, urlParameterId, name, type, total value, buying power
        and performance. Errors are returned as "Error: ..." strings.

    Examples:
        - "How much is my portfolio worth?"
        - "Which accounts do I have at Avanza?"
    """
    return await _run("Avanza Account Overview", response_format, "get_overview")


@mcp.tool(name="avanza_get_positions", annotations={"title": "Portfolio Positions", **READ_ONLY})
async def avanza_get_positions(response_format: Fmt = ResponseFormat.MARKDOWN) -> str:
    """Get all current holdings (positions) across every Avanza account.

    Returns each holding with volume, average acquired price, current value and
    unrealised profit/loss, plus the orderBookId needed by the instrument tools.

    Args:
        response_format (ResponseFormat): 'markdown' (default) or 'json'.

    Returns:
        str: Positions grouped by instrument type, with orderBookId, name, volume,
        average acquired price, last price, market value and change.

    Examples:
        - "What do I own right now?"
        - "Which of my holdings are down the most?"
        - Don't use when: you want closed trades (use avanza_get_transactions).
    """
    return await _run("Avanza Positions", response_format, "get_accounts_positions")


@mcp.tool(
    name="avanza_get_account_performance",
    annotations={"title": "Account Performance", **READ_ONLY},
)
async def avanza_get_account_performance(
    account_url_ids: Annotated[
        list[str],
        Field(
            description=(
                "One or more `urlParameterId` values from avanza_get_overview. "
                "NOTE: this is the urlParameterId, not the accountId."
            ),
            min_length=1,
            max_length=20,
        ),
    ],
    time_period: Annotated[
        TimePeriod, Field(description="Period for the performance chart.")
    ] = TimePeriod.ONE_YEAR,
    insights_account_id: Annotated[
        Optional[str],
        Field(
            description=(
                "Optional `accountId` (not urlParameterId) to also fetch a development "
                "report for, breaking return down by instrument."
            ),
            max_length=64,
        ),
    ] = None,
    insights_time_period: Annotated[
        InsightsReportTimePeriod,
        Field(description="Period for the insights report. Fewer options than time_period."),
    ] = InsightsReportTimePeriod.THREE_YEARS_ROLLING,
    response_format: Fmt = ResponseFormat.MARKDOWN,
) -> str:
    """Get historical performance for one or more accounts, optionally with a breakdown.

    Args:
        account_url_ids (list[str]): urlParameterId values from avanza_get_overview.
        time_period (TimePeriod): TODAY, ONE_WEEK, ONE_MONTH, THREE_MONTHS, THIS_YEAR,
            ONE_YEAR, THREE_YEARS, FIVE_YEARS, THREE_YEARS_ROLLING, FIVE_YEARS_ROLLING,
            ALL_TIME.
        insights_account_id (Optional[str]): accountId for the optional report.
        insights_time_period (InsightsReportTimePeriod): TODAY, ONE_WEEK, THIS_YEAR or
            THREE_YEARS_ROLLING.
        response_format (ResponseFormat): 'markdown' (default) or 'json'.

    Returns:
        str: A time series of account value/return, and when requested a development
        report attributing return to individual instruments.

    Examples:
        - "How has my portfolio performed this year?" -> time_period='THIS_YEAR'
        - "Which holdings contributed most to my return?" -> set insights_account_id
    """
    calls: dict[str, tuple] = {
        "performance_chart": (
            "get_account_performance_chart_data",
            account_url_ids,
            time_period,
        )
    }
    if insights_account_id:
        calls["insights_report"] = (
            "get_insights_report",
            insights_account_id,
            insights_time_period,
        )
    return await _run_many("Avanza Account Performance", response_format, calls)


@mcp.tool(name="avanza_get_transactions", annotations={"title": "Transactions", **READ_ONLY})
async def avanza_get_transactions(
    transaction_types: Annotated[
        list[TransactionsDetailsType],
        Field(
            description="Filter by type, e.g. ['BUY','SELL'] or ['DIVIDEND']. Empty = all.",
            max_length=6,
        ),
    ] = [],
    transactions_from: Annotated[
        Optional[dt.date],
        Field(description="Start date (inclusive), ISO format e.g. '2025-01-01'."),
    ] = None,
    transactions_to: Annotated[
        Optional[dt.date],
        Field(description="End date (inclusive), ISO format e.g. '2025-12-31'."),
    ] = None,
    isin: Annotated[
        Optional[str],
        Field(description="Restrict to one instrument by ISIN.", max_length=32),
    ] = None,
    max_elements: Annotated[
        int,
        Field(
            description="Maximum transactions to return. Keep low unless you need history.",
            ge=1,
            le=1000,
        ),
    ] = 100,
    response_format: Fmt = ResponseFormat.MARKDOWN,
) -> str:
    """Get transaction history: trades, dividends, deposits and withdrawals.

    Args:
        transaction_types (list): Any of BUY, SELL, DIVIDEND, DEPOSIT, WITHDRAW, UNKNOWN.
        transactions_from (Optional[date]): Start of the date range.
        transactions_to (Optional[date]): End of the date range.
        isin (Optional[str]): Restrict to a single instrument.
        max_elements (int): Cap on results, 1-1000 (default 100).
        response_format (ResponseFormat): 'markdown' (default) or 'json'.

    Returns:
        str: Transactions with date, type, instrument, volume, price and amount.

    Examples:
        - "How much did I receive in dividends in 2025?" -> transaction_types=['DIVIDEND']
        - "Show every trade in Volvo B" -> isin='SE0000115446'
        - Don't use when: you want current holdings (use avanza_get_positions).
    """
    return await _run(
        "Avanza Transactions",
        response_format,
        "get_transactions_details",
        transaction_types,
        transactions_from,
        transactions_to,
        isin,
        max_elements,
    )


@mcp.tool(
    name="avanza_get_orders_and_deals", annotations={"title": "Orders and Deals", **READ_ONLY}
)
async def avanza_get_orders_and_deals(
    include_orders: Annotated[
        bool, Field(description="Include open (pending) orders.")
    ] = True,
    include_deals: Annotated[
        bool, Field(description="Include recently executed deals.")
    ] = True,
    include_stop_losses: Annotated[
        bool, Field(description="Include configured stop-loss triggers.")
    ] = False,
    response_format: Fmt = ResponseFormat.MARKDOWN,
) -> str:
    """Get open orders, recently executed deals and stop-loss settings.

    This tool only *reads* order state. This server cannot place, modify or cancel
    orders under any circumstances.

    Args:
        include_orders (bool): Include pending orders (default True).
        include_deals (bool): Include executed deals (default True).
        include_stop_losses (bool): Include stop-loss triggers (default False).
        response_format (ResponseFormat): 'markdown' (default) or 'json'.

    Returns:
        str: Sections for open orders (price, volume, validity), executed deals, and
        stop-loss triggers.

    Examples:
        - "Do I have any orders waiting to fill?"
        - "What was executed today?"
    """
    calls: dict[str, tuple] = {}
    if include_orders:
        calls["open_orders"] = ("get_orders",)
    if include_deals:
        calls["deals"] = ("get_deals",)
    if include_stop_losses:
        calls["stop_losses"] = ("get_all_stop_losses",)
    if not calls:
        return (
            "No sections selected. Enable at least one of include_orders, "
            "include_deals or include_stop_losses."
        )
    return await _run_many("Avanza Orders and Deals", response_format, calls)


# ---------------------------------------------------------------------------
# Instruments
# ---------------------------------------------------------------------------


@mcp.tool(
    name="avanza_search_instruments", annotations={"title": "Search Instruments", **READ_ONLY}
)
async def avanza_search_instruments(
    query: Annotated[
        str,
        Field(
            description="Free-text search, e.g. 'Volvo', 'Avanza Zero', 'OMXS30'.",
            min_length=1,
            max_length=200,
        ),
    ],
    instrument_type: Annotated[
        InstrumentType,
        Field(description="Restrict to one instrument type. Default searches all types."),
    ] = InstrumentType.ANY,
    limit: Annotated[int, Field(description="Maximum results.", ge=1, le=50)] = 10,
    response_format: Fmt = ResponseFormat.MARKDOWN,
) -> str:
    """Search for instruments (stocks, funds, ETFs, certificates, warrants, indexes).

    Use this to resolve a name into the `orderBookId` that the other instrument
    tools require.

    Args:
        query (str): Free-text search string.
        instrument_type (InstrumentType): 'stock', 'fund', 'exchange_traded_fund',
            'certificate', 'warrant', 'index', ... or '' for any type.
        limit (int): Maximum results, 1-50 (default 10).
        response_format (ResponseFormat): 'markdown' (default) or 'json'.

    Returns:
        str: Matches with name, orderBookId, ticker, instrument type and currency.

    Examples:
        - "Find the ticker for Investor B" -> query='Investor B', instrument_type='stock'
        - "Which Avanza index funds exist?" -> query='Avanza', instrument_type='fund'
    """
    return await _run(
        f"Search: {query}",
        response_format,
        "search_for_instrument",
        instrument_type,
        query,
        limit,
    )


@mcp.tool(name="avanza_get_instrument", annotations={"title": "Instrument Info", **READ_ONLY})
async def avanza_get_instrument(
    instrument_id: OrderBookId,
    instrument_type: Annotated[
        InstrumentType, Field(description="Type of the instrument.")
    ] = InstrumentType.STOCK,
    detailed: Annotated[
        bool,
        Field(description="Fetch the extended detail view (key ratios, holdings, fees)."),
    ] = False,
    response_format: Fmt = ResponseFormat.MARKDOWN,
) -> str:
    """Get information about a single instrument: price, key figures and metadata.

    Covers every instrument type. For funds this includes fees and holdings; for
    stocks, key ratios and company data.

    Args:
        instrument_id (str): The instrument's orderBookId.
        instrument_type (InstrumentType): stock, fund, exchange_traded_fund, index, ...
        detailed (bool): Request the extended view (default False).
        response_format (ResponseFormat): 'markdown' (default) or 'json'.

    Returns:
        str: Instrument data including name, ISIN, last price, change and
        type-specific figures.

    Examples:
        - "What is Volvo B trading at?" -> instrument_type='stock'
        - "What's the fee on this fund?" -> instrument_type='fund', detailed=True
        - Errors: returns "Error: Not found" if the id and type do not match.
    """
    method = "get_instrument_details" if detailed else "get_instrument"
    return await _run(
        f"Instrument {instrument_id}", response_format, method, instrument_type, instrument_id
    )


@mcp.tool(name="avanza_get_price_chart", annotations={"title": "Price History", **READ_ONLY})
async def avanza_get_price_chart(
    order_book_id: OrderBookId,
    period: Annotated[
        TimePeriod, Field(description="How far back to fetch prices.")
    ] = TimePeriod.ONE_YEAR,
    resolution: Annotated[
        Optional[Resolution],
        Field(
            description=(
                "Candle size, e.g. DAY or HOUR. Leave empty to let Avanza pick a "
                "resolution appropriate to the period."
            )
        ),
    ] = None,
    response_format: Fmt = ResponseFormat.MARKDOWN,
) -> str:
    """Get historical price data (OHLC time series) for an instrument.

    This can return a lot of data points. Prefer a coarse resolution for long
    periods -- e.g. period='FIVE_YEARS' with resolution='WEEK' or 'MONTH'.

    Args:
        order_book_id (str): The instrument's orderBookId.
        period (TimePeriod): TODAY through ALL_TIME.
        resolution (Optional[Resolution]): MINUTE, TWO_MINUTES, FIVE_MINUTES,
            TEN_MINUTES, THIRTY_MINUTES, HOUR, DAY, WEEK, MONTH, QUARTER.
        response_format (ResponseFormat): 'markdown' (default) or 'json'.

    Returns:
        str: Time series with timestamp, open, high, low, close and volume.

    Examples:
        - "Show Volvo's price over the last year" -> period='ONE_YEAR'
        - "Intraday movement today" -> period='TODAY', resolution='MINUTE'
    """
    return await _run(
        f"Price History {order_book_id}",
        response_format,
        "get_chart_data",
        order_book_id,
        period,
        resolution,
    )


@mcp.tool(name="avanza_get_order_book", annotations={"title": "Order Book", **READ_ONLY})
async def avanza_get_order_book(
    order_book_id: OrderBookId,
    include_market_data: Annotated[
        bool, Field(description="Also fetch last price, spread and turnover.")
    ] = True,
    response_format: Fmt = ResponseFormat.MARKDOWN,
) -> str:
    """Get the current order book (bid/ask depth) and market data for an instrument.

    Despite living under a 'trading' path in Avanza's API, this is purely a read.

    Args:
        order_book_id (str): The instrument's orderBookId.
        include_market_data (bool): Also fetch quote and turnover data (default True).
        response_format (ResponseFormat): 'markdown' (default) or 'json'.

    Returns:
        str: Bid/ask levels with volumes, plus last price, spread, high/low and
        turnover when market data is included.

    Examples:
        - "What's the spread on this stock right now?"
        - "How deep is the order book?"
    """
    calls: dict[str, tuple] = {"order_book": ("get_order_book", order_book_id)}
    if include_market_data:
        calls["market_data"] = ("get_market_data", order_book_id)
    return await _run_many(f"Order Book {order_book_id}", response_format, calls)


@mcp.tool(
    name="avanza_get_instrument_analysis", annotations={"title": "Analyst Data", **READ_ONLY}
)
async def avanza_get_instrument_analysis(
    instrument_id: OrderBookId, response_format: Fmt = ResponseFormat.MARKDOWN
) -> str:
    """Get analyst estimates and recommendations for a stock.

    Stocks only -- other instrument types have no coverage and will return an error.

    Args:
        instrument_id (str): The stock's orderBookId.
        response_format (ResponseFormat): 'markdown' (default) or 'json'.

    Returns:
        str: Analyst recommendations, target prices and estimate revisions where
        Avanza has coverage.

    Examples:
        - "What do analysts think of Ericsson?"
        - Don't use when: the instrument is a fund or index.
    """
    return await _run(
        f"Analysis {instrument_id}", response_format, "get_analysis", instrument_id
    )


# ---------------------------------------------------------------------------
# Market, news and watchlists
# ---------------------------------------------------------------------------


@mcp.tool(name="avanza_get_news", annotations={"title": "Instrument News", **READ_ONLY})
async def avanza_get_news(
    instrument_id: OrderBookId,
    include_forum: Annotated[
        bool, Field(description="Also include Avanza forum posts (user commentary).")
    ] = False,
    response_format: Fmt = ResponseFormat.MARKDOWN,
) -> str:
    """Get recent news articles for an instrument, optionally with forum discussion.

    Args:
        instrument_id (str): The instrument's orderBookId.
        include_forum (bool): Also fetch user forum posts (default False).
        response_format (ResponseFormat): 'markdown' (default) or 'json'.

    Returns:
        str: News items with headline, source and timestamp; forum posts when
        requested. Forum content is user-generated commentary, not verified fact.

    Examples:
        - "Any news on this holding?"
        - "What are people saying about this stock?" -> include_forum=True
    """
    calls: dict[str, tuple] = {"news": ("get_news", instrument_id)}
    if include_forum:
        calls["forum_posts"] = ("get_forum_posts", instrument_id)
    return await _run_many(f"News {instrument_id}", response_format, calls)


@mcp.tool(name="avanza_get_watchlists", annotations={"title": "Watchlists", **READ_ONLY})
async def avanza_get_watchlists(response_format: Fmt = ResponseFormat.MARKDOWN) -> str:
    """Get all watchlists and the instruments on them.

    Reads only. This server cannot add to or remove from a watchlist.

    Args:
        response_format (ResponseFormat): 'markdown' (default) or 'json'.

    Returns:
        str: Watchlists with name, id and member orderBookIds.

    Examples:
        - "What's on my watchlist?"
    """
    return await _run("Avanza Watchlists", response_format, "get_watchlists")


@mcp.tool(
    name="avanza_get_inspiration_lists", annotations={"title": "Inspiration Lists", **READ_ONLY}
)
async def avanza_get_inspiration_lists(
    list_id: Annotated[
        Optional[str],
        Field(
            description=(
                "A specific list to fetch, either a known type such as "
                "'HIGHEST_RATED_FUNDS' or a raw list id. Omit to see what's available."
            ),
            max_length=64,
        ),
    ] = None,
    response_format: Fmt = ResponseFormat.MARKDOWN,
) -> str:
    """Get Avanza's curated instrument lists, e.g. most-owned or lowest-fee funds.

    Call without `list_id` to see which lists exist, then again with one to get its
    contents.

    Args:
        list_id (Optional[str]): HIGHEST_RATED_FUNDS, LOWEST_FEE_INDEX_FUNDS,
            MOST_OWNED_FUNDS, BEST_DEVELOPMENT_FUNDS_LAST_THREE_MONTHS, or a raw id.
        response_format (ResponseFormat): 'markdown' (default) or 'json'.

    Returns:
        str: Either the catalogue of available lists, or one list's instruments.

    Examples:
        - "Which funds are most owned at Avanza?" -> list_id='MOST_OWNED_FUNDS'
        - "What curated lists exist?" -> omit list_id
    """
    if list_id is None:
        return await _run("Avanza Inspiration Lists", response_format, "get_inspiration_lists")
    return await _run(
        f"Inspiration List {list_id}", response_format, "get_inspiration_list", list_id
    )


@mcp.tool(name="avanza_get_price_alerts", annotations={"title": "Price Alerts", **READ_ONLY})
async def avanza_get_price_alerts(
    order_book_id: OrderBookId, response_format: Fmt = ResponseFormat.MARKDOWN
) -> str:
    """Get configured price alerts for an instrument.

    Reads only. This server cannot create or delete price alerts -- the guard
    permits GET on this endpoint and refuses POST and DELETE.

    Args:
        order_book_id (str): The instrument's orderBookId.
        response_format (ResponseFormat): 'markdown' (default) or 'json'.

    Returns:
        str: Alerts with target price, validity date and notification channels.
        Returns an empty list if none are set.

    Examples:
        - "Do I have a price alert on this stock?"
    """
    return await _run(
        f"Price Alerts {order_book_id}", response_format, "get_price_alert", order_book_id
    )


def main() -> None:
    """Run the server over stdio.

    Nothing may be written to stdout -- it carries the MCP protocol stream.
    """
    mcp.run()


if __name__ == "__main__":
    main()
