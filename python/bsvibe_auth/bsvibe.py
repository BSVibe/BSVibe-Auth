"""BSVibe Auth provider — simplified auth using auth.bsvibe.dev.

Products only need ``BSVIBE_AUTH_URL`` (default: https://auth.bsvibe.dev).
JWKS is fetched from ``{auth_url}/api/jwks``.

If the JWKS proxy is not yet available, ``jwks_url`` can be set explicitly
as a temporary override (e.g. Supabase's JWKS endpoint directly).
"""

from __future__ import annotations

from datetime import UTC, datetime

import jwt

from bsvibe_auth.errors import AuthError, TokenExpiredError, TokenInvalidError
from bsvibe_auth.models import BSVibeUser
from bsvibe_auth.provider import AuthProvider


class BsvibeAuthProvider(AuthProvider):
    """JWT verification provider for BSVibe ecosystem.

    Fetches public keys via JWKS and verifies ES256 JWTs.

    Args:
        auth_url: BSVibe Auth URL (e.g. ``https://auth.bsvibe.dev``).
            JWKS is fetched from ``{auth_url}/api/jwks`` by default.
        jwks_url: Explicit JWKS URL override. When set, takes priority
            over the auto-derived ``{auth_url}/api/jwks``. Useful when
            the JWKS proxy is not deployed yet.
        algorithms: JWT algorithms. Defaults to ``["ES256"]``.
    """

    def __init__(
        self,
        auth_url: str = "https://auth.bsvibe.dev",
        jwks_url: str | None = None,
        algorithms: list[str] | None = None,
    ) -> None:
        self._auth_url = auth_url.rstrip("/")
        self._algorithms = algorithms or ["ES256"]
        resolved_jwks_url = jwks_url or f"{self._auth_url}/api/jwks"
        self._jwks_client = jwt.PyJWKClient(resolved_jwks_url, cache_keys=True)

    async def verify_token(self, token: str) -> BSVibeUser:
        """Verify a JWT using JWKS."""
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=self._algorithms,
                audience="authenticated",
            )
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError()
        except jwt.PyJWKClientError as e:
            raise AuthError(f"JWKS error: {e}")
        except jwt.InvalidTokenError as e:
            raise TokenInvalidError(str(e))

        return self._payload_to_user(payload)

    async def get_user(self, user_id: str) -> BSVibeUser | None:
        """Not supported — use SupabaseAuthProvider for admin operations."""
        raise AuthError(
            "get_user() requires Supabase Admin API access. "
            "Use SupabaseAuthProvider with service_role_key for admin operations."
        )

    @staticmethod
    def _payload_to_user(payload: dict) -> BSVibeUser:
        """Convert a JWT payload to a BSVibeUser."""
        iat = payload.get("iat")
        exp = payload.get("exp")
        return BSVibeUser(
            id=payload["sub"],
            email=payload.get("email"),
            role=payload.get("role", "authenticated"),
            app_metadata=payload.get("app_metadata", {}),
            user_metadata=payload.get("user_metadata", {}),
            issued_at=datetime.fromtimestamp(iat, tz=UTC) if iat else None,
            expires_at=datetime.fromtimestamp(exp, tz=UTC) if exp else None,
        )
