"""Github Login Example"""

import os

import uvicorn
from litestar import Litestar, Request, get

from litestar_sso.sso.notion import NotionSSO

CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]

app = Litestar()

sso = NotionSSO(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    redirect_uri="http://localhost:3000/oauth2/callback",
    allow_insecure_http=True,
)


@get("/oauth2/login")
async def auth_init():
    """Initialize auth and redirect"""
    with sso:
        return await sso.get_login_redirect()


@get("/oauth2/callback")
async def auth_callback(request: Request):
    """Verify login"""
    with sso:
        user = await sso.verify_and_process(request)
        return user


if __name__ == "__main__":
    uvicorn.run(app="examples.notion:app", host="127.0.0.1", port=3000)
