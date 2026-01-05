from cryptum.core import urlsafe_entropy, with_prefix
from cryptum.core._constants import ENTROPY_SHORT_LIVED, PREFIX_EMAIL_VERIFICATION
from cryptum.crypto import Sha256


def generate() -> dict[str, str]:
    """
    Generate a cryptographically secure email verification token.

    Returns:
        A dictionary containing:
        - 'plaintext': The token to send via email.
        - 'hash': The SHA-256 hash to store and verify against.
    """
    plaintext = with_prefix(PREFIX_EMAIL_VERIFICATION, urlsafe_entropy(ENTROPY_SHORT_LIVED))
    return {
        "plaintext": plaintext,
        "hash": Sha256.hash(plaintext),
    }
