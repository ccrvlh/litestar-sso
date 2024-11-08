"""Notion SSO Oauth Helper class."""

from typing import TYPE_CHECKING, ClassVar, Optional

from litestar_sso.base import DiscoveryDocument, OpenID, SSOBase, SSOLoginError

if TYPE_CHECKING:
    import httpx  # pragma: no cover


class NotionSSO(SSOBase):
    """Class providing login using Notion OAuth."""

    provider = "notion"
    scope: ClassVar = ["openid"]
    additional_headers: ClassVar = {"Notion-Version": "2022-06-28"}

    async def get_discovery_document(self) -> DiscoveryDocument:
        return {
            "authorization_endpoint": "https://api.notion.com/v1/oauth/authorize?owner=user",
            "token_endpoint": "https://api.notion.com/v1/oauth/token",
            "userinfo_endpoint": "https://api.notion.com/v1/users/me",
        }

    async def openid_from_response(self, response: dict, session: Optional["httpx.AsyncClient"] = None) -> OpenID:
        owner = response["bot"]["owner"]
        if owner["type"] != "user":
            raise SSOLoginError(401, f"Notion login failed, owner is not a user but {response['bot']['owner']['type']}")
        return OpenID(
            id=owner["user"]["id"],
            email=owner["user"]["person"]["email"],
            picture=owner["user"]["avatar_url"],
            display_name=owner["user"]["name"],
            provider=self.provider,
        )
