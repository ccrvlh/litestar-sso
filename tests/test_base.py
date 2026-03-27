# type: ignore

import os

import pytest

from utils import AnythingDict
from utils import Request
from utils import Response
from utils import make_fake_async_client

from litestar_sso.base import SSOBase
from litestar_sso.base import SSOLoginError
from litestar_sso.base import SecurityWarning
from litestar_sso.base import UnsetStateWarning
from litestar_sso.schemas import OpenID


class ConcreteSSO(SSOBase):
    """Concrete SSO provider for testing — has working discovery doc and openid conversion."""

    provider = "concrete"
    scope = ["openid"]

    async def get_discovery_document(self):
        return {
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "userinfo_endpoint": "https://example.com/userinfo",
        }

    async def openid_from_response(self, response, session=None):
        return OpenID(id=response.get("sub", "test"), email=response.get("email", "test@example.com"), display_name="Test")

    async def openid_from_token(self, id_token, session=None):
        return OpenID(id=id_token.get("sub", "test"), email=id_token.get("email", "test@example.com"), display_name="Test")


class TestSSOBase:
    def test_base(self):
        sso = SSOBase("client_id", "client_secret")
        assert sso.client_id == "client_id"
        assert sso.client_secret == "client_secret"
        assert sso._oauth_client is None
        assert sso._refresh_token is None
        assert sso._state is None
        with pytest.warns(SecurityWarning, match="Please make sure you are using SSO provider in an async context"):
            assert sso.oauth_client is not None
            assert sso.access_token is None
            assert sso.refresh_token is None
            assert sso.id_token is None

    async def test_unset_usage(self):
        sso = SSOBase("client_id", "client_secret")
        with pytest.warns(UnsetStateWarning):
            assert sso.state is None

        with pytest.raises(ValueError):
            await sso.get_login_url()

    def test_state_warning(self):
        with pytest.warns(UnsetStateWarning):
            sso = SSOBase("client_id", "client_secret")
            sso.state

    def test_deprecated_use_state_warning(self):
        with pytest.warns(DeprecationWarning):
            SSOBase("client_id", "client_secret", use_state=True)

    async def test_not_implemented_ssobase(self):
        sso = SSOBase("client_id", "client_secret")
        with pytest.raises(NotImplementedError):
            await sso.openid_from_response({})
        with pytest.raises(NotImplementedError):
            await sso.get_discovery_document()

        request = Request()
        request.query_params["code"] = "code"
        with pytest.raises(NotImplementedError), pytest.warns(
            SecurityWarning, match="Please make sure you are using SSO provider in an async context"
        ):
            await sso.verify_and_process(request)

        sso.client_id = NotImplemented
        with pytest.raises(NotImplementedError), pytest.warns(
            SecurityWarning, match="Please make sure you are using SSO provider in an async context"
        ):
            sso.oauth_client

    async def test_login_error(self):
        sso = SSOBase("client_id", "client_secret")

        with pytest.raises(SSOLoginError), pytest.warns(
            SecurityWarning, match="Please make sure you are using SSO provider in an async context"
        ):
            await sso.verify_and_process(Request())

    def test_autoset_insecure_transport_env_var(self):
        assert not os.getenv(
            "OAUTHLIB_INSECURE_TRANSPORT"
        ), "OAUTHLIB_INSECURE_TRANSPORT should not be true before test"
        SSOBase("client_id", "client_secret", allow_insecure_http=True)
        assert os.getenv("OAUTHLIB_INSECURE_TRANSPORT"), "OAUTHLIB_INSECURE_TRANSPORT should be truthy after test"

    def test_requires_async_context_non_ssobase(self):
        """When first arg is not an SSOBase, the decorator passes through without warning."""
        from litestar_sso.base import requires_async_context

        @requires_async_context
        def plain_func(x):
            return x * 2

        assert plain_func(5) == 10

    async def test_openid_from_token_not_implemented(self):
        sso = SSOBase("client_id", "client_secret")
        with pytest.raises(NotImplementedError):
            await sso.openid_from_token({})

    async def test_get_login_url_pkce_warning(self):
        """PKCE warning fires when codes are not generated."""

        class PkceSSO(ConcreteSSO):
            uses_pkce = True

        sso = PkceSSO("client_id", "client_secret")
        async with sso:
            sso._pkce_code_verifier = None
            sso._pkce_code_challenge = None
            with pytest.warns(UserWarning, match="PKCE"):
                await sso.get_login_url(redirect_uri="https://localhost")

    async def test_get_login_url_requires_state_warning(self):
        """requires_state warning fires when no state provided and none generated."""

        class StatefulSSO(ConcreteSSO):
            requires_state = True

        sso = StatefulSSO("client_id", "client_secret")
        async with sso:
            sso._generated_state = None
            with pytest.warns(UserWarning, match="requires state"):
                await sso.get_login_url(redirect_uri="https://localhost")

    async def test_verify_and_process_post_form(self, monkeypatch):
        """POST form data is used when code is not in query params."""
        sso = ConcreteSSO("client_id", "client_secret")
        request = Request(method="POST", form_data={"code": "mycode"})

        async def fake_process_login(code, req, **kwargs):
            return OpenID(id="test", email="test@example.com", display_name="Test")

        async with sso:
            monkeypatch.setattr(sso, "process_login", fake_process_login)
            result = await sso.verify_and_process(request)
            assert result is not None

    async def test_verify_and_process_access_denied(self):
        """access_denied error raises SSOLoginError 401."""
        sso = ConcreteSSO("client_id", "client_secret")
        request = Request()
        request.query_params["error"] = "access_denied"
        async with sso:
            with pytest.raises(SSOLoginError, match="denied access"):
                await sso.verify_and_process(request)

    async def test_verify_and_process_oauth_error(self):
        """Generic OAuth error raises SSOLoginError 400."""
        sso = ConcreteSSO("client_id", "client_secret")
        request = Request()
        request.query_params["error"] = "server_error"
        async with sso:
            with pytest.raises(SSOLoginError, match="OAuth error"):
                await sso.verify_and_process(request)

    async def test_verify_and_process_state_required_missing(self):
        """State missing from callback when requires_state=True raises SSOLoginError."""

        class StatefulSSO(ConcreteSSO):
            requires_state = True

        sso = StatefulSSO("client_id", "client_secret")
        request = Request()
        request.query_params["code"] = "mycode"
        async with sso:
            with pytest.raises(SSOLoginError, match="'state' parameter was not found"):
                await sso.verify_and_process(request)

    async def test_verify_and_process_state_cookie_missing(self):
        """State in request but no sso_state cookie when requires_state=True."""

        class StatefulSSO(ConcreteSSO):
            requires_state = True

        sso = StatefulSSO("client_id", "client_secret")
        request = Request(cookies={})
        request.query_params["code"] = "mycode"
        request.query_params["state"] = "mystate"
        async with sso:
            with pytest.raises(SSOLoginError, match="State cookie not found"):
                await sso.verify_and_process(request)

    async def test_verify_and_process_state_cookie_mismatch(self):
        """State cookie doesn't match state param raises SSOLoginError 401."""
        sso = ConcreteSSO("client_id", "client_secret")
        request = Request(cookies={"sso_state": "wrong_state"})
        request.query_params["code"] = "mycode"
        request.query_params["state"] = "correct_state"
        async with sso:
            with pytest.raises(SSOLoginError, match="Invalid state"):
                await sso.verify_and_process(request)

    async def test_verify_and_process_pkce_missing_verifier(self, monkeypatch):
        """PKCE enabled but no cookie — warning fires and process_login is called."""

        class PkceSSO(ConcreteSSO):
            uses_pkce = True

        sso = PkceSSO("client_id", "client_secret")
        request = Request(cookies={})
        request.query_params["code"] = "mycode"

        async def fake_process_login(code, req, **kwargs):
            return OpenID(id="test", email="test@example.com", display_name="Test")

        async with sso:
            monkeypatch.setattr(sso, "process_login", fake_process_login)
            with pytest.warns(UserWarning, match="PKCE code verifier"):
                await sso.verify_and_process(request)

    async def test_process_login_pkce_verifier_in_params(self, monkeypatch):
        """pkce_code_verifier is added to request params when provided."""
        sso = ConcreteSSO("client_id", "client_secret")
        get_response = Response(url="https://example.com", json_content=AnythingDict({}))
        FakeAsyncClient = make_fake_async_client(
            returns_post=Response(url="https://example.com", json_content={"access_token": "token"}),
            returns_get=get_response,
        )
        async with sso:
            monkeypatch.setattr("httpx.AsyncClient", FakeAsyncClient)
            request = Request(url="https://localhost?code=mycode")
            result = await sso.process_login("mycode", request, pkce_code_verifier="myverifier")
            assert result is not None

    async def test_process_login_no_basic_auth(self, monkeypatch):
        """process_login posts without auth when use_basic_auth=False (AppleSSO)."""
        from litestar_sso.providers.apple import AppleSSO

        sso = AppleSSO("client_id", "client_secret")
        FakeAsyncClient = make_fake_async_client(
            returns_post=Response(
                url="https://appleid.apple.com",
                json_content={"access_token": "token", "id_token": "fake.id.token"},
            ),
            returns_get=Response(url="https://appleid.apple.com", json_content={}),
        )
        async with sso:
            monkeypatch.setattr("httpx.AsyncClient", FakeAsyncClient)
            monkeypatch.setattr("jwt.decode", lambda *_, **__: {"sub": "apple_user", "email": "apple@example.com"})
            request = Request(url="https://localhost?code=mycode")
            result = await sso.process_login("mycode", request)
            assert result is not None

    async def test_process_login_convert_response_false_id_token(self, monkeypatch):
        """convert_response=False returns decoded id_token dict directly."""
        from litestar_sso.providers.apple import AppleSSO

        sso = AppleSSO("client_id", "client_secret")
        FakeAsyncClient = make_fake_async_client(
            returns_post=Response(
                url="https://appleid.apple.com",
                json_content={"access_token": "token", "id_token": "fake.id.token"},
            ),
            returns_get=Response(url="https://appleid.apple.com", json_content={}),
        )
        async with sso:
            monkeypatch.setattr("httpx.AsyncClient", FakeAsyncClient)
            monkeypatch.setattr("jwt.decode", lambda *_, **__: {"sub": "apple_user", "email": "apple@example.com"})
            request = Request(url="https://localhost?code=mycode")
            result = await sso.process_login("mycode", request, convert_response=False)
            assert isinstance(result, dict)
            assert result.get("sub") == "apple_user"

    def test_sync_context_manager(self):
        """Sync context manager emits DeprecationWarning."""
        sso = SSOBase("client_id", "client_secret")
        with pytest.warns(DeprecationWarning, match="async context"):
            with sso as ctx:
                assert ctx is sso

    def test_sync_context_manager_with_requires_state(self):
        """__enter__ generates state when requires_state=True."""

        class StatefulSSO(SSOBase):
            provider = "stateful"
            requires_state = True
            scope = []

            async def get_discovery_document(self):
                return {}

            async def openid_from_response(self, response, session=None):
                return OpenID(id="test", email="test@example.com", display_name="Test")

        sso = StatefulSSO("client_id", "client_secret")
        with pytest.warns(DeprecationWarning):
            with sso as ctx:
                assert ctx._generated_state is not None

    def test_sync_context_manager_with_pkce(self):
        """__enter__ generates PKCE pair when uses_pkce=True."""

        class PkceSSO(SSOBase):
            provider = "pkce"
            uses_pkce = True
            scope = []

            async def get_discovery_document(self):
                return {}

            async def openid_from_response(self, response, session=None):
                return OpenID(id="test", email="test@example.com", display_name="Test")

        sso = PkceSSO("client_id", "client_secret")
        with pytest.warns(DeprecationWarning):
            with sso:
                assert sso._pkce_code_verifier is not None
                assert sso._pkce_code_challenge is not None

    async def test_get_login_redirect_state_cookie(self):
        """get_login_redirect sets sso_state cookie when state is provided."""
        from litestar.response import Redirect

        sso = ConcreteSSO("client_id", "client_secret")
        async with sso:
            redirect = await sso.get_login_redirect(redirect_uri="https://localhost", state="mystate")
            assert isinstance(redirect, Redirect)
