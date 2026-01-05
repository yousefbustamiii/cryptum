from cryptum.core import urlsafe_entropy, with_prefix
from cryptum.core._constants import ENTROPY_LONG_LIVED, PREFIX_ACCESS_KEY
from cryptum.crypto import hmac


def generate(secret_key: str) -> dict[str, str]:
    """
    Generate a cryptographically secure API key signed with HMAC-SHA256.

    Args:
        secret_key: The master server-side key used to sign the API key.

    Returns:
        A dictionary containing:
        - 'plaintext': The key to show the user (e.g., 'ak_...')
        - 'signature': The HMAC-SHA256 signature for verification.
    """
    plaintext = with_prefix(PREFIX_ACCESS_KEY, urlsafe_entropy(ENTROPY_LONG_LIVED))
    signature = hmac.sign(plaintext, secret_key)

    return {
        "plaintext": plaintext,
        "signature": signature,
    }
