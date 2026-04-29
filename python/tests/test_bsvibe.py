from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt as pyjwt
import pytest

from bsvibe_auth import BSVibeUser, BsvibeAuthProvider

TEST_SECRET = "test-secret-key-for-bsvibe-provider"


def _make_hs256_token() -> str:
    now = datetime.now(UTC)
    return pyjwt.encode(
        {
            "sub": "user-123",
            "email": "admin@bsvibe.dev",
            "aud": "authenticated",
            "iat": now,
            "exp": now + timedelta(hours=1),
            "active_tenant_id": "tenant-123",
            "app_metadata": {"tenant_id": "tenant-123", "role": "owner"},
            "user_metadata": {},
        },
        TEST_SECRET,
        algorithm="HS256",
    )


@pytest.mark.asyncio
async def test_bsvibe_provider_supports_hs256_session_tokens() -> None:
    provider = BsvibeAuthProvider(
        auth_url="http://auth-app:5179",
        jwt_secret=TEST_SECRET,
        algorithms=["HS256"],
    )

    user = await provider.verify_token(_make_hs256_token())

    assert isinstance(user, BSVibeUser)
    assert user.id == "user-123"
    assert user.email == "admin@bsvibe.dev"
    assert user.app_metadata == {"tenant_id": "tenant-123", "role": "owner"}
