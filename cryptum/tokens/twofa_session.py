from cryptum.core import urlsafe_entropy, with_prefix
from cryptum.core._constants import ENTROPY_SHORT_LIVED, PREFIX_2FA_SESSION
from cryptum.crypto import Sha256


def generate() -> dict[str, str]:
    """
    Generate a cryptographically secure 2FA session token.

    Returns:
        A dictionary containing:
        - 'plaintext': The temporary 2FA completion token.
        - 'hash': The SHA-256 hash to store.
    """
    plaintext = with_prefix(PREFIX_2FA_SESSION, urlsafe_entropy(ENTROPY_SHORT_LIVED))
    return {
        "plaintext": plaintext,
        "hash": Sha256.hash(plaintext),
    }
