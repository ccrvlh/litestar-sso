"""Seznam SSO Login Helper."""

from typing import TYPE_CHECKING, ClassVar, Optional

from litestar_sso.base import DiscoveryDocument, OpenID, SSOBase

if TYPE_CHECKING:
    import httpx  # pragma: no cover


# https://vyvojari.seznam.cz/oauth/doc


class SeznamSSO(SSOBase):
    """Class providing login via Seznam OAuth."""

    provider = "seznam"
    base_url = "https://login.szn.cz/api/v1"
    scope: ClassVar = ["identity", "avatar"]  # + ["contact-phone", "adulthood", "birthday", "gender"]

    async def get_discovery_document(self) -> DiscoveryDocument:
        """Get document containing handy urls."""
        return {
            "authorization_endpoint": f"{self.base_url}/oauth/auth",
            "token_endpoint": f"{self.base_url}/oauth/token",
            "userinfo_endpoint": f"{self.base_url}/user",
        }

    async def openid_from_response(self, response: dict, session: Optional["httpx.AsyncClient"] = None) -> OpenID:
        """Return OpenID from user information provided by Seznam."""
        return OpenID(
            email=response.get("email"),
            first_name=response.get("firstname"),
            last_name=response.get("lastname"),
            display_name=response.get("accountDisplayName"),
            provider=self.provider,
            id=response.get("oauth_user_id"),
            picture=response.get("avatar_url"),
        )
