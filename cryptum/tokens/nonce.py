from cryptum.core import urlsafe_entropy, with_prefix
from cryptum.core._constants import ENTROPY_IDENTIFIER, PREFIX_NONCE
from cryptum.crypto import Sha256


def generate() -> dict[str, str]:
    """
    Generate a cryptographically secure one-time cryptographic nonce.

    Returns:
        A dictionary containing:
        - 'plaintext': The nonce (e.g., 'n_...')
        - 'hash': The SHA-256 hash if tracking or auditing is required.
    """
    plaintext = with_prefix(PREFIX_NONCE, urlsafe_entropy(ENTROPY_IDENTIFIER))
    return {
        "plaintext": plaintext,
        "hash": Sha256.hash(plaintext),
    }
