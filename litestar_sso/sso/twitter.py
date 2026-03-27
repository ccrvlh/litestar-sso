"""Twitter (X) SSO Oauth Helper class."""

from __future__ import annotations

from typing import TYPE_CHECKING
from typing import ClassVar

from litestar_sso.sso.base import OpenID
from litestar_sso.sso.base import SSOBase
from litestar_sso.sso.base import DiscoveryDocument


if TYPE_CHECKING:
    import httpx  # pragma: no cover


class TwitterSSO(SSOBase):
    """Class providing login via Twitter SSO."""

    provider = "twitter"
    scope: ClassVar = ["users.read", "tweet.read"]
    uses_pkce = True
    requires_state = True

    async def get_discovery_document(self) -> DiscoveryDocument:
        return {
            "authorization_endpoint": "https://twitter.com/i/oauth2/authorize",
            "token_endpoint": "https://api.twitter.com/2/oauth2/token",
            "userinfo_endpoint": "https://api.twitter.com/2/users/me",
        }

    async def openid_from_response(self, response: dict, session: httpx.AsyncClient | None = None) -> OpenID:
        first_name, *last_name_parts = response["data"].get("name", "").split(" ")
        last_name = " ".join(last_name_parts) if last_name_parts else None
        return OpenID(
            id=str(response["data"]["id"]),
            display_name=response["data"]["username"],
            first_name=first_name,
            last_name=last_name,
            provider=self.provider,
        )
