import hmac
import hashlib


def sign(message: str | bytes, secret: str | bytes) -> str:
    """
    Generate an HMAC-SHA256 signature for a message using a secret key.

    Args:
        message: The data to be signed. If a string is provided, it is UTF-8 encoded.
        secret: The secret key used for the signature. If a string is provided, it is UTF-8 encoded.

    Returns:
        The lowercase hexadecimal HMAC-SHA256 signature.

    Raises:
        TypeError: If message or secret are not strings or bytes.
    """
    if isinstance(message, str):
        msg_bytes = message.encode("utf-8")
    elif isinstance(message, bytes):
        msg_bytes = message
    else:
        raise TypeError("message must be a string or bytes")

    if isinstance(secret, str):
        sec_bytes = secret.encode("utf-8")
    elif isinstance(secret, bytes):
        sec_bytes = secret
    else:
        raise TypeError("secret must be a string or bytes")

    return hmac.new(sec_bytes, msg_bytes, hashlib.sha256).hexdigest()


def verify(message: str | bytes, secret: str | bytes, signature: str) -> bool:
    """
    Verify an HMAC-SHA256 signature using constant-time comparison.

    This function is designed to never raise an exception and will return False
    on any invalid inputs or signature mismatches.

    Args:
        message: The original message that was signed.
        secret: The secret key used for signing.
        signature: The hexadecimal HMAC signature to verify.

    Returns:
        True if the signature matches the calculated HMAC, False otherwise.
    """
    try:
        if not isinstance(signature, str):
            return False

        computed = sign(message, secret)
        return hmac.compare_digest(computed, signature.lower())
    except (TypeError, ValueError, AttributeError):
        # Catch all potential input or processing errors during verification to prevent timing leaks
        # and ensure a reliable boolean response.
        return False
