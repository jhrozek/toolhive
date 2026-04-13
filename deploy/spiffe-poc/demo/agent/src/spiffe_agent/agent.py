"""Pydantic-ai agent that connects to ToolHive MCP servers via SPIFFE mTLS.

The main entry point is :func:`run_agent`, which handles token acquisition
(either client_credentials or token exchange), creates a TLS-secured MCP
connection, and runs the LLM agent against the available tools.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

from pydantic_ai import Agent, RunContext
from pydantic_ai.mcp import CallToolFunc, MCPServerStreamableHTTP, ToolResult

from spiffe_agent.spiffe_auth import (
    SPIFFECredentials,
    acquire_token,
    create_mcp_client,
    exchange_token,
)

logger = logging.getLogger(__name__)


class AuthorizationDeniedError(Exception):
    """Raised when the MCP server returns a 403 authorization denial."""


async def _check_authz_denial(
    ctx: RunContext[Any],
    call_tool: CallToolFunc,
    name: str,
    tool_args: dict[str, Any],
) -> ToolResult:
    """Intercept MCP tool results and raise on authorization denial.

    This runs before pydantic-ai passes the result to the LLM, so the
    LLM cannot hallucinate a response when access is denied.
    """
    result = await call_tool(name, tool_args)

    # Check for errors — the result may be an MCP ToolResult object or a dict
    is_error = getattr(result, "isError", None) or (
        isinstance(result, dict) and result.get("isError", False)
    )
    if is_error:
        # Extract error text from content
        content = getattr(result, "content", None) or (
            result.get("content") if isinstance(result, dict) else None
        )
        error_text = ""
        if content:
            for part in content:
                if hasattr(part, "text"):
                    error_text += part.text
                elif isinstance(part, dict) and "text" in part:
                    error_text += part["text"]

        if "403" in error_text or "unauthorized" in error_text.lower():
            logger.error("Authorization denied for tool '%s': %s", name, error_text)
            raise AuthorizationDeniedError(
                f"Tool '{name}' denied by authorization policy: {error_text}"
            )
    return result


def _log_token_identity(token: str) -> None:
    """Decode and log the JWT payload without signature verification.

    This is strictly for diagnostics — the token is NOT verified here.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            logger.warning("Token is not a valid JWT (expected 3 segments)")
            return
        # Base64-decode the payload (middle segment), adding padding as needed.
        payload_b64 = parts[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        claims: dict[str, object] = json.loads(payload_bytes)

        sub = claims.get("sub", "<unknown>")
        logger.info("Identity: sub=%s", sub)

        act = claims.get("act")
        if isinstance(act, dict):
            act_sub = act.get("sub", "<unknown>")
            logger.info("Delegation: act.sub=%s", act_sub)
    except Exception:
        logger.warning("Failed to decode JWT payload for logging", exc_info=True)


async def _preflight_tool_check(client: Any, mcp_url: str) -> list[str]:
    """Check which tools are authorized by doing a raw MCP session.

    Returns a list of tool names. An empty list means Cedar denied all tools.
    """
    # Initialize MCP session
    init_payload = {
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "preflight-check", "version": "1.0"},
        },
        "id": 1,
    }
    resp = await client.post(mcp_url, json=init_payload)
    session_id = resp.headers.get("mcp-session-id", "")

    if not session_id:
        logger.warning("No MCP session ID in preflight check")
        return []

    headers = {"Mcp-Session-Id": session_id}

    # Send initialized notification
    await client.post(
        mcp_url,
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers=headers,
    )

    # List tools
    list_resp = await client.post(
        mcp_url,
        json={"jsonrpc": "2.0", "method": "tools/list", "id": 2},
        headers=headers,
    )

    # Parse SSE response — the MCP response is in the event stream
    tool_names: list[str] = []
    for line in list_resp.text.splitlines():
        if line.startswith("data: "):
            data = json.loads(line[6:])
            tools = data.get("result", {}).get("tools", [])
            tool_names = [t["name"] for t in tools]
            break

    return tool_names


async def run_agent(
    proxy_url: str,
    task: str,
    creds: SPIFFECredentials,
    *,
    user_token: str | None = None,
    subject_token_type: str = "urn:ietf:params:oauth:token-type:id_token",
    model: str = "openai:gpt-4o",
) -> str:
    """Run a pydantic-ai agent against a ToolHive MCP server.

    Acquires an OAuth token (via client_credentials or token exchange),
    establishes a Streamable HTTP MCP connection through the proxy, and
    executes the given task prompt.

    When *user_token* is provided the agent first obtains its own
    client_credentials token, then performs an RFC 8693 token exchange
    passing both the user token (subject) and the agent token (actor)
    so the auth server can issue a delegation token with an ``act``
    claim.

    Args:
        proxy_url: Base URL of the ToolHive MCP proxy.
        task: The natural-language prompt for the agent.
        creds: SPIFFE X.509-SVID credential paths.
        user_token: If provided, perform token exchange instead of
            client_credentials. Used for user-to-agent delegation.
        subject_token_type: URN for the subject token type used during
            token exchange.
        model: The LLM model identifier (e.g. ``openai:gpt-4o``).

    Returns:
        The agent's text output.
    """
    # Step 0: Always acquire the agent's own token first.
    logger.info("Acquiring client_credentials token for agent identity")
    agent_token = await acquire_token(proxy_url, creds)

    if user_token:
        # Step 1: Exchange user token + agent token for a delegated token.
        logger.info("Performing token exchange for delegation")
        token = await exchange_token(
            proxy_url,
            user_token,
            creds,
            subject_token_type=subject_token_type,
            actor_token=agent_token,
        )
    else:
        token = agent_token

    _log_token_identity(token)

    # Step 2: Create MCP client and run the agent.
    client = create_mcp_client(token, creds.ca)
    try:
        mcp_url = f"{proxy_url}/mcp"
        logger.info("Connecting to MCP server at %s", mcp_url)

        server = MCPServerStreamableHTTP(
            mcp_url, http_client=client, process_tool_call=_check_authz_denial,
        )

        # Pre-flight authorization check: verify tools are available.
        # The MCP proxy filters the tool list through Cedar — if the client
        # is not authorized to call any tools, the list is empty.
        # We use the raw httpx client to call tools/list before the LLM runs.
        preflight_tool_names = await _preflight_tool_check(client, mcp_url)
        if not preflight_tool_names:
            raise AuthorizationDeniedError(
                "No tools available — authorization policy denied access to all tools"
            )
        logger.info("Authorized tools: %s", ", ".join(preflight_tool_names))

        agent = Agent(model, toolsets=[server])

        result = await agent.run(task)
        return result.output
    finally:
        await client.aclose()
