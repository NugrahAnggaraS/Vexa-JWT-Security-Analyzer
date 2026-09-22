"""Exceptions raised while parsing or validating JWT structure."""


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
