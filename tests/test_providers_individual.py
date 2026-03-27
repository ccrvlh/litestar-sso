import pytest

from litestar_sso import AppleSSO, GithubSSO, GoogleSSO, NotionSSO, OpenID, SSOLoginError
from utils import Response, make_fake_async_client


async def test_notion_openid_response():
    sso = NotionSSO("client_id", "client_secret")
    valid_response = {
        "bot": {
            "owner": {
                "type": "user",
                "user": {
                    "id": "test",
                    "person": {"email": "test@example.com"},
                    "avatar_url": "avatar",
                    "name": "Test User",
                },
            }
        }
    }
    invalid_response = {"bot": {"owner": {"type": "workspace", "workspace": {}}}}
    with pytest.raises(SSOLoginError):
        await sso.openid_from_response(invalid_response)
    openid = OpenID(id="test", email="test@example.com", display_name="Test User", picture="avatar", provider="notion")
    assert await sso.openid_from_response(valid_response) == openid


# --- GoogleSSO ---


async def test_google_openid_from_response_verified():
    sso = GoogleSSO("client_id", "client_secret")
    openid = await sso.openid_from_response(
        {
            "email_verified": True,
            "email": "test@google.com",
            "sub": "google123",
            "given_name": "Test",
            "family_name": "User",
            "name": "Test User",
            "picture": "https://pic.example.com/photo.jpg",
        }
    )
    assert openid.email == "test@google.com"
    assert openid.id == "google123"
    assert openid.first_name == "Test"
    assert openid.last_name == "User"
    assert openid.display_name == "Test User"
    assert openid.provider == "google"


async def test_google_openid_from_response_unverified():
    sso = GoogleSSO("client_id", "client_secret")
    with pytest.raises(SSOLoginError, match="not verified with Google"):
        await sso.openid_from_response({"email": "test@google.com", "email_verified": False})


async def test_google_get_discovery_document(monkeypatch):
    discovery = {
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
    }
    FakeAsyncClient = make_fake_async_client(
        returns_post=Response(url="https://accounts.google.com", json_content={}),
        returns_get=Response(url="https://accounts.google.com", json_content=discovery),
    )
    monkeypatch.setattr("httpx.AsyncClient", FakeAsyncClient)
    sso = GoogleSSO("client_id", "client_secret")
    doc = await sso.get_discovery_document()
    assert doc["authorization_endpoint"] == "https://accounts.google.com/o/oauth2/auth"


# --- GithubSSO ---


async def test_github_get_primary_email_no_session():
    sso = GithubSSO("client_id", "client_secret")
    result = await sso._get_primary_email(session=None)
    assert result is None


async def test_github_get_primary_email_success():
    class FakeResponse:
        status_code = 200

        def json(self):
            return [
                {"email": "other@github.com", "primary": False},
                {"email": "primary@github.com", "primary": True},
            ]

    class FakeSession:
        async def get(self, *args, **kwargs):
            return FakeResponse()

    sso = GithubSSO("client_id", "client_secret")
    result = await sso._get_primary_email(session=FakeSession())
    assert result == "primary@github.com"


async def test_github_get_primary_email_non_200():
    class FakeResponse:
        status_code = 404

        def json(self):
            return []

    class FakeSession:
        async def get(self, *args, **kwargs):
            return FakeResponse()

    sso = GithubSSO("client_id", "client_secret")
    result = await sso._get_primary_email(session=FakeSession())
    assert result is None


async def test_github_get_primary_email_no_primary():
    class FakeResponse:
        status_code = 200

        def json(self):
            return [{"email": "only@github.com", "primary": False}]

    class FakeSession:
        async def get(self, *args, **kwargs):
            return FakeResponse()

    sso = GithubSSO("client_id", "client_secret")
    result = await sso._get_primary_email(session=FakeSession())
    assert result is None


# --- AppleSSO ---


async def test_apple_get_login_url_no_extra_params():
    sso = AppleSSO("client_id", "client_secret")
    async with sso:
        url = await sso.get_login_url(redirect_uri="https://localhost")
    assert "response_mode=form_post" in url


async def test_apple_get_login_url_with_extra_params():
    sso = AppleSSO("client_id", "client_secret")
    async with sso:
        url = await sso.get_login_url(redirect_uri="https://localhost", params={"custom": "value"})
    assert "response_mode=form_post" in url
    assert "custom=value" in url


async def test_apple_extra_query_params():
    sso = AppleSSO("client_id", "my_secret")
    assert sso._extra_query_params == {"client_secret": "my_secret"}


async def test_apple_get_discovery_document():
    sso = AppleSSO("client_id", "client_secret")
    doc = await sso.get_discovery_document()
    assert doc["authorization_endpoint"] == "https://appleid.apple.com/auth/authorize"
    assert doc["token_endpoint"] == "https://appleid.apple.com/auth/token"


async def test_apple_openid_from_response():
    sso = AppleSSO("client_id", "client_secret")
    openid = await sso.openid_from_response({"sub": "apple_123", "email": "apple@example.com"})
    assert openid.id == "apple_123"
    assert openid.email == "apple@example.com"
    assert openid.provider == "apple"


async def test_apple_openid_from_token():
    sso = AppleSSO("client_id", "client_secret")
    openid = await sso.openid_from_token({"sub": "token_123", "email": "token@example.com"})
    assert openid.id == "token_123"
    assert openid.email == "token@example.com"
