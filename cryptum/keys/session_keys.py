from cryptum.core import hex_entropy, with_prefix
from cryptum.core._constants import PREFIX_SESSION_KEY
from cryptum.crypto import Sha256


def generate() -> dict[str, str]:
    """
    Generate a 16-character random session key.

    Returns:
        A dictionary containing:
        - 'plaintext': The session key (e.g., 'ssk_...').
        - 'hash': The SHA-256 hash for storage/auditing.
    """
    plaintext = with_prefix(PREFIX_SESSION_KEY, hex_entropy(8))
    
    return {
        "plaintext": plaintext,
        "hash": Sha256.hash(plaintext)
    }
