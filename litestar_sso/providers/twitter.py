"""Twitter (X) SSO Oauth Helper class."""

from typing import TYPE_CHECKING, ClassVar, Optional

from litestar_sso.base import DiscoveryDocument, OpenID, SSOBase

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

    async def openid_from_response(self, response: dict, session: Optional["httpx.AsyncClient"] = None) -> OpenID:
        first_name, *last_name_parts = response["data"].get("name", "").split(" ")
        last_name = " ".join(last_name_parts) if last_name_parts else None
        return OpenID(
            id=str(response["data"]["id"]),
            display_name=response["data"]["username"],
            first_name=first_name,
            last_name=last_name,
            provider=self.provider,
        )
