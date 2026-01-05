from cryptum.core import urlsafe_entropy, with_prefix
from cryptum.core._constants import ENTROPY_SHORT_LIVED, PREFIX_CSRF_TOKEN
from cryptum.crypto import Sha256


def generate() -> dict[str, str]:
    """
    Generate a cryptographically secure, short-lived CSRF token.

    Returns:
        A dictionary containing:
        - 'plaintext': The token to put in forms or headers.
        - 'hash': The SHA-256 hash if storage is required.
    """
    plaintext = with_prefix(PREFIX_CSRF_TOKEN, urlsafe_entropy(ENTROPY_SHORT_LIVED))
    return {
        "plaintext": plaintext,
        "hash": Sha256.hash(plaintext),
    }
