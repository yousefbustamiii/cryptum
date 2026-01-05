from cryptum.core import hex_entropy, with_prefix
from cryptum.core._constants import PREFIX_FAILURE_KEY
from cryptum.crypto import Sha256


def generate() -> dict[str, str]:
    """
    Generate a 16-character random failure key.

    Returns:
        A dictionary containing:
        - 'plaintext': The failure key (e.g., 'flk_...').
        - 'hash': The SHA-256 hash for storage/auditing.
    """
    plaintext = with_prefix(PREFIX_FAILURE_KEY, hex_entropy(8))
    
    return {
        "plaintext": plaintext,
        "hash": Sha256.hash(plaintext)
    }
