"""SSO login base dependency."""

import pydantic

from typing import Optional, TypedDict


class DiscoveryDocument(TypedDict):
    """Discovery document."""

    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str


class OpenID(pydantic.BaseModel):
    """Class (schema) to represent information got from sso provider in a common form."""

    id: Optional[str] = None
    email: Optional[pydantic.EmailStr] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    display_name: Optional[str] = None
    picture: Optional[str] = None
    provider: Optional[str] = None
