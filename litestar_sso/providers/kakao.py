"""Kakao SSO Oauth Helper class."""

from __future__ import annotations

from typing import TYPE_CHECKING
from typing import ClassVar

from litestar_sso.base import OpenID
from litestar_sso.base import SSOBase
from litestar_sso.base import DiscoveryDocument


if TYPE_CHECKING:
    import httpx  # pragma: no cover


class KakaoSSO(SSOBase):
    """Class providing login using Kakao OAuth."""

    provider = "kakao"
    scop: ClassVar = ["openid"]
    version = "v2"

    async def get_discovery_document(self) -> DiscoveryDocument:
        return {
            "authorization_endpoint": "https://kauth.kakao.com/oauth/authorize",
            "token_endpoint": "https://kauth.kakao.com/oauth/token",
            "userinfo_endpoint": f"https://kapi.kakao.com/{self.version}/user/me",
        }

    async def openid_from_response(self, response: dict, session: httpx.AsyncClient | None = None) -> OpenID:
        return OpenID(display_name=response["properties"]["nickname"], provider=self.provider)
