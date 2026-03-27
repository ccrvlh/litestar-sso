"""Spotify SSO Login Helper."""

from __future__ import annotations

from typing import TYPE_CHECKING
from typing import ClassVar

from litestar_sso.sso.base import OpenID
from litestar_sso.sso.base import SSOBase
from litestar_sso.sso.base import DiscoveryDocument


if TYPE_CHECKING:
    import httpx  # pragma: no cover


class SpotifySSO(SSOBase):
    """Class providing login via Spotify OAuth."""

    provider = "spotify"
    scope: ClassVar = ["user-read-private", "user-read-email"]

    async def get_discovery_document(self) -> DiscoveryDocument:
        """Get document containing handy urls."""
        return {
            "authorization_endpoint": "https://accounts.spotify.com/authorize",
            "token_endpoint": "https://accounts.spotify.com/api/token",
            "userinfo_endpoint": "https://api.spotify.com/v1/me",
        }

    async def openid_from_response(self, response: dict, session: httpx.AsyncClient | None = None) -> OpenID:
        """Return OpenID from user information provided by Spotify."""
        picture = response["images"][0]["url"] if response.get("images", []) else None
        return OpenID(
            email=response.get("email"),
            display_name=response.get("display_name"),
            provider=self.provider,
            id=response.get("id"),
            picture=picture,
        )
