"""SPIFFE authentication helpers for ToolHive MCP servers.

Provides X.509-SVID credential handling, OAuth token acquisition via
client_credentials and token exchange grants, and httpx client creation
with Bearer-token authorization and CA-only TLS.
"""

from __future__ import annotations

import logging
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

logger = logging.getLogger(__name__)

# Default SPIFFE CSI driver mount path inside Kubernetes pods.
_DEFAULT_SPIFFE_DIR = Path("/var/run/secrets/spiffe.io")


@dataclass
class SPIFFECredentials:
    """Paths to X.509-SVID certificate, private key, and trust bundle."""

    cert: Path = field(default_factory=lambda: _DEFAULT_SPIFFE_DIR / "tls.crt")
    key: Path = field(default_factory=lambda: _DEFAULT_SPIFFE_DIR / "tls.key")
    ca: Path = field(default_factory=lambda: _DEFAULT_SPIFFE_DIR / "ca.crt")


def extract_spiffe_id(cert_path: Path) -> str:
    """Read an X.509-SVID PEM file and return the SPIFFE ID from the SAN.

    The SPIFFE ID is the first URI SAN that starts with ``spiffe://``.

    Args:
        cert_path: Filesystem path to the PEM-encoded certificate.

    Returns:
        The SPIFFE ID string (e.g. ``spiffe://example.org/agent``).

    Raises:
        ValueError: If no SPIFFE URI is found in the certificate SANs.
    """
    cert_data = cert_path.read_bytes()
    cert = x509.load_pem_x509_certificate(cert_data)
    san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    uris = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
    for uri in uris:
        if uri.startswith("spiffe://"):
            logger.info("Extracted SPIFFE ID: %s", uri)
            return uri
    raise ValueError(
        f"No spiffe:// URI found in certificate SANs: {cert_path}"
    )


def _build_mtls_ssl_context(creds: SPIFFECredentials) -> ssl.SSLContext:
    """Build an SSL context configured for mutual TLS with SPIFFE certs."""
    ctx = ssl.create_default_context(cafile=str(creds.ca))
    ctx.load_cert_chain(certfile=str(creds.cert), keyfile=str(creds.key))
    return ctx


def _build_mtls_client(creds: SPIFFECredentials) -> httpx.AsyncClient:
    """Create an httpx async client configured for mTLS."""
    ssl_ctx = _build_mtls_ssl_context(creds)
    return httpx.AsyncClient(
        verify=ssl_ctx,
        timeout=httpx.Timeout(30.0),
    )


async def acquire_token(proxy_url: str, creds: SPIFFECredentials) -> str:
    """Acquire an OAuth access token using the client_credentials grant.

    Authenticates via mTLS to the auth server's ``/oauth/token`` endpoint.
    The ``client_id`` is the SPIFFE ID extracted from the certificate SAN
    and ``resource`` is the proxy URL (per RFC 8707).

    Args:
        proxy_url: Base URL of the ToolHive MCP proxy (used as the resource).
        creds: SPIFFE X.509-SVID credential paths.

    Returns:
        The access token string.

    Raises:
        httpx.HTTPStatusError: If the token request fails.
    """
    spiffe_id = extract_spiffe_id(creds.cert)
    client = _build_mtls_client(creds)
    try:
        response = await client.post(
            f"{proxy_url}/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": spiffe_id,
                "resource": proxy_url,
            },
        )
        response.raise_for_status()
        token_data: dict[str, Any] = response.json()
        access_token: str = token_data["access_token"]
        expires_in = token_data.get("expires_in", "unknown")
        logger.info(
            "Acquired client_credentials token (expires_in=%s)", expires_in
        )
        return access_token
    finally:
        await client.aclose()


async def exchange_token(
    proxy_url: str,
    subject_token: str,
    creds: SPIFFECredentials,
    *,
    subject_token_type: str = "urn:ietf:params:oauth:token-type:access_token",
    actor_token: str | None = None,
) -> str:
    """Exchange a user token for a delegated token via RFC 8693 token exchange.

    Authenticates via mTLS and presents the user's token as the subject
    token.  When *actor_token* is supplied the request includes actor
    token parameters so the auth server can issue a delegation token
    with an ``act`` claim.

    Args:
        proxy_url: Base URL of the ToolHive MCP proxy (used as the resource).
        subject_token: The user's token to exchange.
        creds: SPIFFE X.509-SVID credential paths.
        subject_token_type: URN for the subject token type.  Defaults to
            ``urn:ietf:params:oauth:token-type:access_token``.
        actor_token: If provided, the agent's own JWT included as the
            ``actor_token`` form parameter for the delegation flow.

    Returns:
        The exchanged access token string.

    Raises:
        httpx.HTTPStatusError: If the token exchange request fails.
    """
    spiffe_id = extract_spiffe_id(creds.cert)
    client = _build_mtls_client(creds)
    try:
        form_data: dict[str, str] = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject_token,
            "subject_token_type": subject_token_type,
            "client_id": spiffe_id,
            "resource": proxy_url,
        }
        if actor_token is not None:
            form_data["actor_token"] = actor_token
            form_data["actor_token_type"] = (
                "urn:ietf:params:oauth:token-type:access_token"
            )
        response = await client.post(
            f"{proxy_url}/oauth/token",
            data=form_data,
        )
        response.raise_for_status()
        token_data: dict[str, Any] = response.json()
        access_token: str = token_data["access_token"]
        token_type = token_data.get("issued_token_type", "unknown")
        expires_in = token_data.get("expires_in", "unknown")
        logger.info(
            "Exchanged token (type=%s, expires_in=%s)", token_type, expires_in
        )
        return access_token
    finally:
        await client.aclose()


def create_mcp_client(token: str, ca_path: Path) -> httpx.AsyncClient:
    """Create an httpx client for MCP requests with Bearer auth and CA-only TLS.

    Unlike the mTLS clients used for token acquisition, this client only
    verifies the server certificate (no client cert) and injects the
    Bearer token as a default Authorization header.

    Args:
        token: The OAuth access token for the MCP proxy.
        ca_path: Path to the CA bundle for verifying the proxy's TLS cert.

    Returns:
        A configured httpx.AsyncClient.
    """
    ssl_ctx = ssl.create_default_context(cafile=str(ca_path))
    return httpx.AsyncClient(
        verify=ssl_ctx,
        headers={"Authorization": f"Bearer {token}"},
        timeout=httpx.Timeout(60.0),
    )
