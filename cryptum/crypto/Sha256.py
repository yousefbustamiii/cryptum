import hashlib
import hmac


def hash(value: str | bytes) -> str:
    """
    Compute the SHA-256 hash of a string or bytes value.

    Args:
        value: The data to hash. If a string is provided, it is UTF-8 encoded.

    Returns:
        The lowercase hexadecimal digest of the SHA-256 hash.

    Raises:
        TypeError: If value is not a string or bytes object.
    """
    if isinstance(value, str):
        data = value.encode("utf-8")
    elif isinstance(value, bytes):
        data = value
    else:
        raise TypeError("value must be a string or bytes")

    return hashlib.sha256(data).hexdigest()


def verify(value: str | bytes, expected_hash: str) -> bool:
    """
    Verify a value against an expected SHA-256 hash using constant-time comparison.

    Args:
        value: The data to hash and verify.
        expected_hash: The hexagonal hash digest to compare against.

    Returns:
        True if the computed hash matches the expected hash, False otherwise.

    Raises:
        TypeError: If value or expected_hash are not the expected types.
    """
    if not isinstance(expected_hash, str):
        raise TypeError("expected_hash must be a string")

    computed_hash = hash(value)
    return hmac.compare_digest(computed_hash, expected_hash.lower())
