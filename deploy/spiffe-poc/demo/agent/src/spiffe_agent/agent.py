"""Pydantic-ai agent that connects to ToolHive MCP servers via SPIFFE mTLS.

The main entry point is :func:`run_agent`, which handles token acquisition
(either client_credentials or token exchange), creates a TLS-secured MCP
connection, and runs the LLM agent against the available tools.
"""

from __future__ import annotations

import base64
import json
import logging

from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStreamableHTTP

from spiffe_agent.spiffe_auth import (
    SPIFFECredentials,
    acquire_token,
    create_mcp_client,
    exchange_token,
)

logger = logging.getLogger(__name__)


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

        server = MCPServerStreamableHTTP(mcp_url, http_client=client)
        agent = Agent(model, toolsets=[server])

        result = await agent.run(task)
        return result.output
    finally:
        await client.aclose()
