class OAuthError(Exception):
    """Base class for OAuth errors"""

    pass


class OAuthStateMismatchError(OAuthError):
    pass
class OAuthNonceMismatchError(OAuthError):
    pass

class OAuthCannotDisconnectError(OAuthError):
    pass

class OAuthCannotConnectError(OAuthError):
    pass

class OAuthUserAlreadyExistsError(OAuthError):
    pass

class OAuthIDTokenValidationMismatchError(OAuthError):
    pass

class OAuthProviderNotConfiguredError(OAuthError):
    pass

