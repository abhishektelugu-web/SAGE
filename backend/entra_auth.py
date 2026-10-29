"""Validation of Microsoft Entra access tokens for approval reviewers."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import os
import re

import jwt
from jwt import PyJWKClient, PyJWKClientConnectionError


_TENANT_ID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
APPROVER_ROLE = "TraceGuard.Approver"
AUDITOR_ROLE = "TraceGuard.Auditor"


class EntraAuthConfigurationError(RuntimeError):
    """Required Microsoft Entra application settings are missing or invalid."""


class InvalidEntraAccessToken(ValueError):
    """The supplied access token failed signature or claim validation."""


class EntraIdentityProviderUnavailable(RuntimeError):
    """Microsoft Entra signing keys could not be retrieved."""


@dataclass(frozen=True, slots=True)
class ReviewerPrincipal:
    object_id: str
    display_name: str
    roles: frozenset[str]

    @property
    def audit_identity(self) -> str:
        return f"{self.display_name} (oid:{self.object_id})"


@lru_cache(maxsize=16)
def _jwks_client(tenant_id: str) -> PyJWKClient:
    keys_url = (
        "https://login.microsoftonline.com/"
        f"{tenant_id}/discovery/v2.0/keys"
    )
    return PyJWKClient(keys_url, cache_jwk_set=True, lifespan=300, timeout=5)


def validate_entra_access_token(token: str) -> ReviewerPrincipal:
    tenant_id = os.getenv("TRACEGUARD_ENTRA_TENANT_ID", "").strip()
    audience = os.getenv("TRACEGUARD_ENTRA_AUDIENCE", "").strip()
    client_id = os.getenv("TRACEGUARD_ENTRA_CLIENT_ID", "").strip()
    if (
        not _TENANT_ID_PATTERN.fullmatch(tenant_id)
        or not audience
        or not _TENANT_ID_PATTERN.fullmatch(client_id)
    ):
        raise EntraAuthConfigurationError(
            "Configure a tenant ID, API audience, and dashboard client ID for Entra."
        )

    issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
    try:
        signing_key = _jwks_client(tenant_id).get_signing_key_from_jwt(token)
    except PyJWKClientConnectionError as exc:
        raise EntraIdentityProviderUnavailable(
            "Microsoft Entra signing keys could not be retrieved."
        ) from exc
    except jwt.PyJWTError as exc:
        raise InvalidEntraAccessToken("The bearer token is invalid.") from exc

    try:
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=audience,
            issuer=issuer,
            options={
                "require": ["exp", "iat", "nbf", "iss", "aud", "tid", "oid"],
            },
        )
    except jwt.InvalidTokenError as exc:
        raise InvalidEntraAccessToken(
            "The bearer token failed Entra signature or claim validation."
        ) from exc

    if (
        str(claims.get("tid", "")).lower() != tenant_id.lower()
        or claims.get("azp") != client_id
    ):
        raise InvalidEntraAccessToken(
            "The bearer token was issued for a different tenant or client."
        )

    object_id = claims.get("oid")
    roles = claims.get("roles", [])
    if not isinstance(object_id, str) or not object_id.strip():
        raise InvalidEntraAccessToken("The bearer token has no user object ID.")
    if not isinstance(roles, list) or any(not isinstance(role, str) for role in roles):
        raise InvalidEntraAccessToken("The bearer token has invalid app roles.")

    display_name = claims.get("name") or claims.get("preferred_username") or object_id
    if not isinstance(display_name, str) or not display_name.strip():
        display_name = object_id
    return ReviewerPrincipal(
        object_id=object_id,
        display_name=display_name.strip()[:128],
        roles=frozenset(roles),
    )
