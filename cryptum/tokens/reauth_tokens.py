from cryptum.core import urlsafe_entropy, with_prefix
from cryptum.core._constants import ENTROPY_SHORT_LIVED, PREFIX_REAUTH_TOKEN
from cryptum.crypto import Sha256


def generate() -> dict[str, str]:
    """
    Generate a cryptographically secure re-authentication token.

    Returns:
        A dictionary containing:
        - 'plaintext': The reauth token (e.g., 'ra_...')
        - 'hash': The SHA-256 hash for storage/verification.
    """
    plaintext = with_prefix(PREFIX_REAUTH_TOKEN, urlsafe_entropy(ENTROPY_SHORT_LIVED))
    return {
        "plaintext": plaintext,
        "hash": Sha256.hash(plaintext),
    }
