"""Litestar plugin to enable SSO to most common providers.

(such as Facebook login, Google login and login via Microsoft Office 365 account)
"""

from .base import OpenID
from .base import SSOBase
from .base import SSOLoginError
from .providers.line import LineSSO
from .providers.apple import AppleSSO
from .providers.kakao import KakaoSSO
from .providers.naver import NaverSSO
from .providers.tidal import TidalSSO
from .providers.fitbit import FitbitSSO
from .providers.github import GithubSSO
from .providers.gitlab import GitlabSSO
from .providers.google import GoogleSSO
from .providers.notion import NotionSSO
from .providers.discord import DiscordSSO
from .providers.generic import create_provider
from .providers.spotify import SpotifySSO
from .providers.twitter import TwitterSSO
from .providers.facebook import FacebookSSO
from .providers.linkedin import LinkedInSSO
from .providers.bitbucket import BitbucketSSO
from .providers.microsoft import MicrosoftSSO
from .providers.soundcloud import SoundcloudSSO


__all__ = [
    "OpenID",
    "SSOBase",
    "SSOLoginError",
    "AppleSSO",
    "BitbucketSSO",
    "DiscordSSO",
    "FacebookSSO",
    "FitbitSSO",
    "create_provider",
    "GithubSSO",
    "GitlabSSO",
    "GoogleSSO",
    "KakaoSSO",
    "LineSSO",
    "LinkedInSSO",
    "MicrosoftSSO",
    "NaverSSO",
    "NotionSSO",
    "SoundcloudSSO",
    "SpotifySSO",
    "TidalSSO",
    "TwitterSSO",
]
