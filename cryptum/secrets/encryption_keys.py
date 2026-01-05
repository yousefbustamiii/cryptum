from cryptum.core import urlsafe_entropy, with_prefix
from cryptum.core._constants import ENTROPY_SECRET, PREFIX_ENCRYPTION_KEY
from cryptum.crypto import Sha256


def generate() -> dict[str, str]:
    """
    Generate a cryptographically secure 256-bit encryption key.

    The key is generated using 32 bytes of entropy, encoded as a URL-safe
    base64 string, and prefixed with 'ek_'.

    Returns:
        A dictionary containing:
        - 'plaintext': The encryption key (e.g., 'ek_...').
        - 'hash': The SHA-256 hash for storage/auditing.
    """
    plaintext = with_prefix(PREFIX_ENCRYPTION_KEY, urlsafe_entropy(ENTROPY_SECRET))
    
    return {
        "plaintext": plaintext,
        "hash": Sha256.hash(plaintext)
    }
