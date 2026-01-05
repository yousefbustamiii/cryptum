from cryptum.core import urlsafe_entropy, with_prefix
from cryptum.core._constants import ENTROPY_SHORT_LIVED, PREFIX_SESSION
from cryptum.crypto import Sha256


def generate() -> dict[str, str]:
    """
    Generate a cryptographically secure session token.

    Returns:
        A dictionary containing:
        - 'plaintext': The session token (cookie value).
        - 'hash': The SHA-256 hash for database indexing/verification.
    """
    plaintext = with_prefix(PREFIX_SESSION, urlsafe_entropy(ENTROPY_SHORT_LIVED))
    return {
        "plaintext": plaintext,
        "hash": Sha256.hash(plaintext),
    }
