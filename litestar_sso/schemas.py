"""SSO login base dependency."""

from typing import TypedDict

import pydantic


class DiscoveryDocument(TypedDict):
    """Discovery document."""

    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str


class OpenID(pydantic.BaseModel):
    """Class (schema) to represent information got from sso provider in a common form."""

    id: str | None = None
    email: pydantic.EmailStr | None = None
    first_name: str | None = None
    last_name: str | None = None
    display_name: str | None = None
    picture: str | None = None
    provider: str | None = None
