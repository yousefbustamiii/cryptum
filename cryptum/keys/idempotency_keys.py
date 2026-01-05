from cryptum.core import hex_entropy, with_prefix
from cryptum.core._constants import PREFIX_IDEMPOTENCY_KEY
from cryptum.crypto import Sha256


def generate() -> dict[str, str]:
    """
    Generate a 16-character random idempotency key.

    Returns:
        A dictionary containing:
        - 'plaintext': The idempotency key (e.g., 'idemk_...').
        - 'hash': The SHA-256 hash for storage/auditing.
    """
    plaintext = with_prefix(PREFIX_IDEMPOTENCY_KEY, hex_entropy(8))
    
    return {
        "plaintext": plaintext,
        "hash": Sha256.hash(plaintext)
    }
