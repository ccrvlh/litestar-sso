"""Fitbit Login Example"""

import os

import uvicorn
from litestar import Litestar, Request, get

from litestar_sso.providers.fitbit import FitbitSSO

CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]

app = Litestar()

sso = FitbitSSO(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    redirect_uri="http://localhost:3000/auth/callback",
    allow_insecure_http=True,
)


@get("/auth/login")
async def auth_init():
    """Initialize auth and redirect"""
    async with sso:
        return await sso.get_login_redirect()


@get("/auth/callback")
async def auth_callback(request: Request):
    """Verify login"""
    async with sso:
        return await sso.verify_and_process(request)


if __name__ == "__main__":
    uvicorn.run(app="examples.fitbit:app", host="127.0.0.1", port=3000)
