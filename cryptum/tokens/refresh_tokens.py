from cryptum.core import urlsafe_entropy, with_prefix
from cryptum.core._constants import ENTROPY_LONG_LIVED, PREFIX_REFRESH_TOKEN
from cryptum.crypto import Sha256


def generate() -> dict[str, str]:
    """
    Generate a cryptographically secure, high-entropy refresh token.

    Returns:
        A dictionary containing:
        - 'plaintext': The refresh token (e.g., 'rt_...')
        - 'hash': The SHA-256 hash for storage/verification.
    """
    plaintext = with_prefix(PREFIX_REFRESH_TOKEN, urlsafe_entropy(ENTROPY_LONG_LIVED))
    return {
        "plaintext": plaintext,
        "hash": Sha256.hash(plaintext),
    }
