import datetime
from typing import Any
import jwt

def encode(
    payload: dict[str, Any],
    secret: str | bytes,
    expiry_seconds: int = 900, # 15 minutes
) -> str:
    """
    Generate a signed JWT with mandatory expiration and issuance timestamps.

    Enforces HS256 algorithm to prevent algorithm confusion attacks.

    Args:
        payload: Custom claims to include in the token.
        secret: The secret key used for signing.
        expiry_seconds: Number of seconds until the token expires. Defaults to 15 minutes.

    Returns:
        The encoded and signed JWT string.

    Raises:
        TypeError: If payload is not a dictionary.
        ValueError: If reserved claims ('exp', 'iat') are present in the payload or
                    if expiry_seconds is non-positive.
    """
    if not isinstance(payload, dict):
        raise TypeError("payload must be a dict")

    if expiry_seconds <= 0:
        raise ValueError("expiry_seconds must be a positive integer")

    # Prevent accidental or malicious bypass of enforced claims
    if any(k in payload for k in ("exp", "iat")):
        raise ValueError("Payload must not contain reserved 'exp' or 'iat' claims.")

    # Normalize timestamps to UTC
    now = datetime.datetime.now(datetime.timezone.utc)
    exp = now + datetime.timedelta(seconds=expiry_seconds)

    claims = {
        **payload,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }

    # Algorithm is hardcoded to HS256 to eliminate choice and prevent confusion bugs.
    return jwt.encode(claims, secret, algorithm="HS256")


def decode(
    token: str,
    secret: str | bytes,
) -> dict[str, Any]:
    """
    Verify and decode a JWT with safe defaults.

    Args:
        token: The JWT string to decode.
        secret: The secret key used for verification.

    Returns:
        The decoded payload dictionary.

    Note:
        This function enforces that 'exp' and 'iat' claims are present and
        that the token is signed with HS256.
    """
    return jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        options={"require": ["exp", "iat"]},
    )
