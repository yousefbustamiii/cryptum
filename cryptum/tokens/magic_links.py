from cryptum.core import urlsafe_entropy, with_prefix
from cryptum.core._constants import ENTROPY_SHORT_LIVED, PREFIX_MAGIC_LINK
from cryptum.crypto import Sha256


def generate() -> dict[str, str]:
    """
    Generate a cryptographically secure magic link token.

    Returns:
        A dictionary containing:
        - 'plaintext': The token for the magic link URL.
        - 'hash': The SHA-256 hash to store.
    """
    plaintext = with_prefix(PREFIX_MAGIC_LINK, urlsafe_entropy(ENTROPY_SHORT_LIVED))
    return {
        "plaintext": plaintext,
        "hash": Sha256.hash(plaintext),
    }
