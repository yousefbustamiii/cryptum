from cryptum.core import hex_entropy, with_prefix
from cryptum.core._constants import PREFIX_CONFIRMATION_KEY
from cryptum.crypto import Sha256


def generate() -> dict[str, str]:
    """
    Generate a 16-character random confirmation key.

    Returns:
        A dictionary containing:
        - 'plaintext': The confirmation key (e.g., 'ck_...').
        - 'hash': The SHA-256 hash for storage/auditing.
    """
    plaintext = with_prefix(PREFIX_CONFIRMATION_KEY, hex_entropy(8))
    
    return {
        "plaintext": plaintext,
        "hash": Sha256.hash(plaintext)
    }
