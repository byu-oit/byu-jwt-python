class BYUJWTError(Exception):
    """Error handling BYU JWT"""


class JWTVerifyError(BYUJWTError):
    """Error Verifing JWT"""


class JWTHandlerError(BYUJWTError):
    """Error while handling JWT"""
