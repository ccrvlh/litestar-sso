"""Example of framework-agnostic SSO implementation."""

from abc import ABC
from abc import abstractmethod
from typing import Any
from typing import Dict
from typing import Union
from typing import Optional
from typing import Protocol
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

from typing_extensions import TypeAlias


# Type aliases for framework-agnostic types
JSON: TypeAlias = Union[Dict[str, Any], list[Any]]
Headers: TypeAlias = Dict[str, str]


class Request(Protocol):
    """Protocol defining the minimum interface needed from a request object."""

    @property
    @abstractmethod
    def query_params(self) -> dict[str, str]:
        """Get query parameters from request."""
        ...

    @property
    @abstractmethod
    def headers(self) -> Headers:
        """Get request headers."""
        ...


class Response(Protocol):
    """Protocol defining the minimum interface needed for responses."""

    @abstractmethod
    def redirect(self, url: str) -> Any:
        """Redirect to given URL."""
        ...

    @abstractmethod
    def json(self, data: JSON) -> Any:
        """Return JSON response."""
        ...


class WebFramework(ABC):
    """Abstract base class for web framework adapters."""

    @abstractmethod
    def build_url(self, path: str, params: Optional[dict] = None) -> str:
        """Build absolute URL for given path and optional query params."""
        ...

    @abstractmethod
    def create_response(self) -> Response:
        """Create framework-specific response object."""
        ...

    @abstractmethod
    def get_request(self) -> Request:
        """Get current request object."""
        ...


@dataclass
class FastAPIAdapter(WebFramework):
    """FastAPI-specific implementation."""

    from fastapi import FastAPI
    from fastapi import Request
    from fastapi import Response
    from starlette.responses import JSONResponse
    from starlette.responses import RedirectResponse

    app: FastAPI
    request: Request
    base_url: str

    def build_url(self, path: str, params: Optional[dict] = None) -> str:
        url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"
        if params:
            url = f"{url}?{urlencode(params)}"
        return url

    def create_response(self) -> Response:
        return self.Response()

    def get_request(self) -> Request:
        return self.request


@dataclass
class LitestarAdapter(WebFramework):
    """Litestar-specific implementation."""

    from litestar import Request
    from litestar import Litestar
    from litestar import Response
    from litestar.response import Redirect

    app: Litestar
    request: Request
    base_url: str

    def build_url(self, path: str, params: Optional[dict] = None) -> str:
        url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"
        if params:
            url = f"{url}?{urlencode(params)}"
        return url

    def create_response(self) -> Response:
        return self.Response()

    def get_request(self) -> Request:
        return self.request


class FrameworkAgnosticOAuth:
    """Framework-agnostic OAuth implementation."""

    def __init__(
        self,
        framework: WebFramework,
        client_id: str,
        client_secret: str,
        authorize_url: str,
        token_url: str,
        redirect_uri: str,
    ):
        self.framework = framework
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorize_url = authorize_url
        self.token_url = token_url
        self.redirect_uri = redirect_uri

    async def begin_auth(self) -> Response:
        """Start OAuth flow by redirecting to provider's authorization URL."""
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": "read",  # Customize based on provider
        }
        auth_url = f"{self.authorize_url}?{urlencode(params)}"
        response = self.framework.create_response()
        return response.redirect(auth_url)

    async def handle_callback(self) -> Response:
        """Handle OAuth callback and exchange code for token."""
        request = self.framework.get_request()
        code = request.query_params.get("code")

        if not code:
            response = self.framework.create_response()
            return response.json({"error": "No code provided"})

        # Exchange code for token
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                self.token_url,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "redirect_uri": self.redirect_uri,
                    "grant_type": "authorization_code",
                },
            )

        response = self.framework.create_response()
        return response.json(token_response.json())


# Example usage with FastAPI
"""
from fastapi import FastAPI, Request

app = FastAPI()
base_url = "http://localhost:8000"

@app.get("/login")
async def login(request: Request):
    framework = FastAPIAdapter(app=app, request=request, base_url=base_url)
    oauth = FrameworkAgnosticOAuth(
        framework=framework,
        client_id="your-client-id",
        client_secret="your-client-secret",
        authorize_url="https://provider.com/oauth/authorize",
        token_url="https://provider.com/oauth/token",
        redirect_uri=f"{base_url}/callback",
    )
    return await oauth.begin_auth()

@app.get("/callback")
async def callback(request: Request):
    framework = FastAPIAdapter(app=app, request=request, base_url=base_url)
    oauth = FrameworkAgnosticOAuth(
        framework=framework,
        client_id="your-client-id",
        client_secret="your-client-secret",
        authorize_url="https://provider.com/oauth/authorize",
        token_url="https://provider.com/oauth/token",
        redirect_uri=f"{base_url}/callback",
    )
    return await oauth.handle_callback()
"""

# Example usage with Litestar
"""
from litestar import Litestar, Request

app = Litestar()
base_url = "http://localhost:8000"

@app.get("/login")
async def login(request: Request):
    framework = LitestarAdapter(app=app, request=request, base_url=base_url)
    oauth = FrameworkAgnosticOAuth(
        framework=framework,
        client_id="your-client-id",
        client_secret="your-client-secret",
        authorize_url="https://provider.com/oauth/authorize",
        token_url="https://provider.com/oauth/token",
        redirect_uri=f"{base_url}/callback",
    )
    return await oauth.begin_auth()

@app.get("/callback")
async def callback(request: Request):
    framework = LitestarAdapter(app=app, request=request, base_url=base_url)
    oauth = FrameworkAgnosticOAuth(
        framework=framework,
        client_id="your-client-id",
        client_secret="your-client-secret",
        authorize_url="https://provider.com/oauth/authorize",
        token_url="https://provider.com/oauth/token",
        redirect_uri=f"{base_url}/callback",
    )
    return await oauth.handle_callback()
"""
