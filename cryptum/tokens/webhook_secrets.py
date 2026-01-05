from cryptum.core import urlsafe_entropy, with_prefix
from cryptum.core._constants import ENTROPY_SECRET, PREFIX_WEBHOOK_SECRET
from cryptum.crypto import aes


def generate(encryption_secret: str) -> dict[str, str]:
    """
    Generate a cryptographically secure webhook secret and encrypt it using AES-256-GCM.

    Args:
        encryption_secret: The master server-side key used to encrypt the secret.

    Returns:
        A dictionary containing:
        - 'plaintext': The webhook secret (whs_...)
        - 'encrypted': The AES-256-GCM encrypted Base64 blob.
    """
    plaintext = with_prefix(PREFIX_WEBHOOK_SECRET, urlsafe_entropy(ENTROPY_SECRET))
    encrypted = aes.encrypt(plaintext, encryption_secret)

    return {
        "plaintext": plaintext,
        "encrypted": encrypted,
    }
