from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import backend.entra_auth as entra_auth


TENANT_ID = "11111111-2222-3333-4444-555555555555"
CLIENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
AUDIENCE = "api://traceguard-api"


class _SigningKey:
    def __init__(self, key):
        self.key = key


class _StaticJwksClient:
    def __init__(self, key):
        self.key = key

    def get_signing_key_from_jwt(self, _token):
        return _SigningKey(self.key)


@pytest.fixture
def rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return private_key, private_pem


def _set_auth_settings(monkeypatch):
    monkeypatch.setenv("TRACEGUARD_ENTRA_TENANT_ID", TENANT_ID)
    monkeypatch.setenv("TRACEGUARD_ENTRA_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("TRACEGUARD_ENTRA_CLIENT_ID", CLIENT_ID)


def _signed_token(private_key, **overrides):
    now = datetime.now(timezone.utc)
    claims = {
        "iss": f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
        "aud": AUDIENCE,
        "tid": TENANT_ID,
        "oid": "99999999-8888-7777-6666-555555555555",
        "azp": CLIENT_ID,
        "name": "Entra Test Approver",
        "roles": ["TraceGuard.Approver"],
        "iat": now,
        "nbf": now - timedelta(seconds=5),
        "exp": now + timedelta(minutes=5),
    }
    claims.update(overrides)
    return jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"kid": "fixture-key"},
    )


def test_entra_access_token_signature_and_claims_are_verified(
    monkeypatch, rsa_keys
):
    private_key, _ = rsa_keys
    _set_auth_settings(monkeypatch)
    monkeypatch.setattr(
        entra_auth,
        "_jwks_client",
        lambda _tenant: _StaticJwksClient(private_key.public_key()),
    )

    principal = entra_auth.validate_entra_access_token(
        _signed_token(private_key)
    )

    assert principal.object_id == "99999999-8888-7777-6666-555555555555"
    assert principal.display_name == "Entra Test Approver"
    assert principal.roles == frozenset({"TraceGuard.Approver"})
    assert "oid:" + principal.object_id in principal.audit_identity


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "api://another-api"},
        {"iss": "https://login.microsoftonline.com/another/v2.0"},
        {"tid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
        {"azp": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"},
        {"exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
    ],
)
def test_entra_access_token_rejects_wrong_identity_or_expiry(
    monkeypatch, rsa_keys, overrides
):
    private_key, _ = rsa_keys
    _set_auth_settings(monkeypatch)
    monkeypatch.setattr(
        entra_auth,
        "_jwks_client",
        lambda _tenant: _StaticJwksClient(private_key.public_key()),
    )

    with pytest.raises(entra_auth.InvalidEntraAccessToken):
        entra_auth.validate_entra_access_token(
            _signed_token(private_key, **overrides)
        )


def test_entra_access_token_rejects_invalid_signature(monkeypatch, rsa_keys):
    trusted_key, _ = rsa_keys
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _set_auth_settings(monkeypatch)
    monkeypatch.setattr(
        entra_auth,
        "_jwks_client",
        lambda _tenant: _StaticJwksClient(trusted_key.public_key()),
    )

    with pytest.raises(entra_auth.InvalidEntraAccessToken):
        entra_auth.validate_entra_access_token(_signed_token(other_key))


def test_entra_access_token_requires_tenant_specific_settings(monkeypatch):
    monkeypatch.delenv("TRACEGUARD_ENTRA_TENANT_ID", raising=False)
    monkeypatch.delenv("TRACEGUARD_ENTRA_AUDIENCE", raising=False)
    monkeypatch.delenv("TRACEGUARD_ENTRA_CLIENT_ID", raising=False)

    with pytest.raises(entra_auth.EntraAuthConfigurationError):
        entra_auth.validate_entra_access_token("not-a-jwt")
