from litestar.exceptions import HTTPException


class UnsetStateWarning(UserWarning):
    """Warning about unset state parameter."""


class ReusedOauthClientWarning(UserWarning):
    """Warning about reused oauth client instance."""


class SSOLoginError(HTTPException):
    """Raised when any login-related error ocurrs.

    Such as when user is not verified or if there was an attempt for fake login.
    """


class SecurityWarning(UserWarning):
    """Raised when insecure usage is detected"""
