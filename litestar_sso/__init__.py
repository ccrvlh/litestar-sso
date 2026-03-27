"""Litestar plugin to enable SSO to most common providers.

(such as Facebook login, Google login and login via Microsoft Office 365 account)
"""

from .base import OpenID, SSOBase, SSOLoginError
from .providers.apple import AppleSSO
from .providers.bitbucket import BitbucketSSO
from .providers.discord import DiscordSSO
from .providers.facebook import FacebookSSO
from .providers.fitbit import FitbitSSO
from .providers.generic import create_provider
from .providers.github import GithubSSO
from .providers.gitlab import GitlabSSO
from .providers.google import GoogleSSO
from .providers.kakao import KakaoSSO
from .providers.line import LineSSO
from .providers.linkedin import LinkedInSSO
from .providers.microsoft import MicrosoftSSO
from .providers.naver import NaverSSO
from .providers.notion import NotionSSO
from .providers.soundcloud import SoundcloudSSO
from .providers.spotify import SpotifySSO
from .providers.tidal import TidalSSO
from .providers.twitter import TwitterSSO

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
