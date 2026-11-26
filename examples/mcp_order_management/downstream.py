"""KYA-OS story L3-D in the sample: ``forward_lookup_order`` looks an order up
at another order service (service B) on the calling agent's behalf, the
Python twin of the JS sample's downstream.ts. The tool knows nothing about
identity: it calls B through ``with_delegation``, which forwards the chain the
agent presented here, signs the delegation proof for B's host and audits the
attachment. B verifies all of it with its own local verifier."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import Annotated, Any, Callable, Dict, List, Optional

import httpx
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult, TextContent, ToolAnnotations
from pydantic import Field

from helix_mcp_middleware import OutboundAttachment, with_delegation

FORWARD_TOOL = "forward_lookup_order"
FORWARD_TOOL_SCOPES: Dict[str, List[str]] = {FORWARD_TOOL: ["orders:read"]}
"""The forwarding tool needs what the downstream lookup needs."""

OrderId = Annotated[str, Field(pattern=r"^ORD-\d{4,}$", description="An order id like ORD-1001")]


@dataclass
class DownstreamOptions:
    url: str
    """Service B's MCP endpoint, e.g. ``http://127.0.0.1:3911/mcp``."""
    signer: Any
    """This server's Signer: the delegation proof's ``iss``."""
    advisory_headers: bool = False
    audit: Optional[Callable[[OutboundAttachment], Any]] = None
    """Where each attachment is audited (``McpAuditTrail.outbound_audit()``, a log line, ...)."""
    request: Optional[Callable[..., Any]] = None
    """An async ``request(method, url, headers=..., content=...)``; default a fresh ``httpx.AsyncClient`` per call."""
    clock: Optional[Callable[[], int]] = None
    """Milliseconds since the epoch, for the proof's ``iat``."""


def register_forward_tool(server: MCPServer, downstream: DownstreamOptions) -> None:
    @server.tool(
        name=FORWARD_TOOL,
        title="Look up an order at the downstream service",
        description="Asks the downstream order service for an order, on the calling agent's delegated authority.",
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True),
        structured_output=False,
    )
    async def forward_lookup_order(orderId: OrderId) -> CallToolResult:  # noqa: N803 - the wire name, shared with the JS sample
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "lookup_order", "arguments": {"orderId": orderId}}})
        headers = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
        async with httpx.AsyncClient(timeout=10) as client:
            forward = with_delegation(
                downstream.request or client.request,
                downstream.signer,
                advisory_headers=downstream.advisory_headers,
                audit=downstream.audit,
                on_audit_error=lambda error: print("outbound delegation audit failed:", error, file=sys.stderr),
                clock=downstream.clock,
            )
            response = await forward("POST", downstream.url, headers=headers, content=body)
        try:
            answer: Any = response.json()
        except ValueError:
            answer = None
        failed = response.status_code >= 400 or (isinstance(answer, dict) and ("error" in answer or (answer.get("result") or {}).get("isError") is True))
        text = json.dumps({"downstreamStatus": response.status_code, "downstream": answer})
        return CallToolResult(content=[TextContent(type="text", text=text)], isError=failed)
