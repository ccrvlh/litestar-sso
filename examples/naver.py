"""Naver Login Example
"""

import os
import uvicorn
from litestar import Litestar
from litestar import Request
from litestar import get
from litestar_sso.sso.naver import NaverSSO

CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]

app = Litestar()

sso = NaverSSO(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    redirect_uri="http://127.0.0.1:5000/auth/callback",
    allow_insecure_http=True,
)


@get("/auth/login")
async def auth_init():
    """Initialize auth and redirect"""
    with sso:
        return await sso.get_login_redirect()


@get("/auth/callback")
async def auth_callback(request: Request):
    """Verify login"""
    with sso:
        return await sso.verify_and_process(request, params={"client_secret": CLIENT_SECRET})


if __name__ == "__main__":
    uvicorn.run(app="examples.naver:app", host="127.0.0.1", port=5000, reload=True)
