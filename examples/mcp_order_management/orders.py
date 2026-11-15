# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The tools. They know nothing about identity: by the time a call reaches
them, the HTTP layer has authenticated the caller and checked the tool's
scope (see app.py)."""

from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from typing import Annotated, Any, Dict

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

# The scope each tool needs. Passed to the middleware as `tool_scopes`, so any
# tool not listed here is denied before it runs (deny by default).
TOOL_SCOPES: Dict[str, list] = {
    "lookup_order": ["orders:read"],
    "refund_order": ["orders:admin"],
}

OrderStore = Dict[str, Dict[str, Any]]

_ORDERS = [
    {
        "id": "ORD-1001", "customer": "Asha Rao",
        "items": [{"sku": "KB-01", "quantity": 1, "unitPrice": 89}],
        "total": 89, "currency": "USD", "status": "shipped",
    },
    {
        "id": "ORD-1002", "customer": "Ben Ortiz",
        "items": [{"sku": "MS-02", "quantity": 2, "unitPrice": 25}, {"sku": "PD-07", "quantity": 1, "unitPrice": 15}],
        "total": 65, "currency": "USD", "status": "paid",
    },
]


def create_order_store() -> OrderStore:
    """An in-memory store with a few demo orders. State resets on restart."""
    return {order["id"]: copy.deepcopy(order) for order in _ORDERS}


OrderId = Annotated[str, Field(pattern=r"^ORD-\d{4,}$", description="An order id like ORD-1001")]


def register_order_tools(server: FastMCP, store: OrderStore) -> None:
    @server.tool(
        title="Look up an order",
        description="Returns an order by id: customer, items, total and status.",
        annotations=ToolAnnotations(readOnlyHint=True),
        structured_output=False,
    )
    def lookup_order(orderId: OrderId) -> str:  # noqa: N803 - the wire name, shared with the JS sample
        order = store.get(orderId)
        if order is None:
            raise ValueError(f"Order {orderId} not found")
        return json.dumps(order, indent=2)

    @server.tool(
        title="Refund an order",
        description="Refunds an order in full. Requires the orders:admin scope.",
        annotations=ToolAnnotations(destructiveHint=True, idempotentHint=False),
        structured_output=False,
    )
    def refund_order(orderId: OrderId, reason: Annotated[str, Field(min_length=1, max_length=200)]) -> str:  # noqa: N803
        order = store.get(orderId)
        if order is None:
            raise ValueError(f"Order {orderId} not found")
        if order["status"] == "refunded":
            raise ValueError(f"Order {orderId} was already refunded")
        order.update(
            status="refunded",
            refundedAt=datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            refundReason=reason,
        )
        return json.dumps(order, indent=2)
