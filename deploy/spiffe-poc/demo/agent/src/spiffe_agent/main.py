"""Entrypoint for the SPIFFE-authenticated pydantic-ai MCP agent.

Usage::

    python -m spiffe_agent.main "Fetch the contents of https://example.com" \\
        --proxy-url https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080

Environment variables can substitute for most flags:
  SPIFFE_PROXY_URL, SPIFFE_USER_TOKEN, LLM_MODEL
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

from spiffe_agent.agent import AuthorizationDeniedError, run_agent
from spiffe_agent.spiffe_auth import SPIFFECredentials


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spiffe-mcp-agent",
        description="Run a pydantic-ai agent against a SPIFFE-authenticated ToolHive MCP server.",
    )
    parser.add_argument(
        "task",
        help="The natural-language prompt for the agent.",
    )
    parser.add_argument(
        "--proxy-url",
        default=os.environ.get("SPIFFE_PROXY_URL"),
        help="Base URL of the ToolHive MCP proxy (env: SPIFFE_PROXY_URL).",
    )
    parser.add_argument(
        "--user-token",
        default=os.environ.get("SPIFFE_USER_TOKEN"),
        help="User access token for delegation via token exchange (env: SPIFFE_USER_TOKEN).",
    )
    parser.add_argument(
        "--subject-token-type",
        default=os.environ.get(
            "SPIFFE_SUBJECT_TOKEN_TYPE",
            "urn:ietf:params:oauth:token-type:id_token",
        ),
        help=(
            "URN for the subject token type during token exchange "
            "(env: SPIFFE_SUBJECT_TOKEN_TYPE, "
            "default: urn:ietf:params:oauth:token-type:id_token)."
        ),
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("LLM_MODEL", "openai:gpt-4o"),
        help="LLM model identifier (env: LLM_MODEL, default: openai:gpt-4o).",
    )
    parser.add_argument(
        "--cert",
        type=Path,
        default=None,
        help="Path to X.509-SVID certificate (overrides default SPIFFE CSI path).",
    )
    parser.add_argument(
        "--key",
        type=Path,
        default=None,
        help="Path to X.509-SVID private key (overrides default SPIFFE CSI path).",
    )
    parser.add_argument(
        "--ca",
        type=Path,
        default=None,
        help="Path to trust bundle CA (overrides default SPIFFE CSI path).",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser


def main() -> None:
    """Parse arguments and run the agent."""
    parser = _build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if not args.proxy_url:
        parser.error("--proxy-url is required (or set SPIFFE_PROXY_URL)")

    creds = SPIFFECredentials()
    if args.cert:
        creds.cert = args.cert
    if args.key:
        creds.key = args.key
    if args.ca:
        creds.ca = args.ca

    try:
        output = asyncio.run(
            run_agent(
                proxy_url=args.proxy_url,
                task=args.task,
                creds=creds,
                user_token=args.user_token,
                subject_token_type=args.subject_token_type,
                model=args.model,
            )
        )
    except KeyboardInterrupt:
        sys.exit(130)
    except AuthorizationDeniedError as exc:
        print(f"ACCESS DENIED: {exc}", file=sys.stderr)
        sys.exit(2)
    except Exception:
        logging.getLogger(__name__).exception("Agent run failed")
        sys.exit(1)

    print(output)


if __name__ == "__main__":
    main()
