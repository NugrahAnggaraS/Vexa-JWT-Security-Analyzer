"""Exceptions raised while parsing or validating JWT structure."""


class RemoteFetchError(ValueError):
    """Raised when a remote document cannot be fetched safely."""

    def __init__(self, message: str, *, code: str = "REMOTE_FETCH") -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return self.message


class JwksError(ValueError):
    """Raised when a JWKS location or document cannot be used."""

    def __init__(self, message: str, *, code: str = "INVALID_JWKS") -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return self.message


class CompareError(ValueError):
    """Raised when two tokens cannot be compared."""

    def __init__(self, message: str, *, code: str = "INVALID_COMPARE") -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return self.message


class BatchError(ValueError):
    """Raised when a batch of tokens cannot be loaded."""

    def __init__(self, message: str, *, code: str = "INVALID_BATCH") -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return self.message


class OidcError(ValueError):
    """Raised when OpenID Provider metadata cannot be loaded."""

    def __init__(self, message: str, *, code: str = "INVALID_OIDC") -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return self.message


class JWTParseError(ValueError):
    """Raised when a token is not a well-formed compact JWS JWT.

    Attributes:
        code: Machine-readable error identifier for CLI mapping.
        message: Human-readable explanation of what failed.
    """

    def __init__(self, message: str, *, code: str = "INVALID_JWT") -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return self.message
