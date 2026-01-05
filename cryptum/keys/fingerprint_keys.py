from cryptum.core import hex_entropy, with_prefix
from cryptum.core._constants import PREFIX_FINGERPRINT_KEY


def generate() -> str:
    """
    Generate a 16-character random fingerprint key for device/user tracking.

    Returns:
        The plaintext fingerprint key (e.g., 'fk_...').
    """
    return with_prefix(PREFIX_FINGERPRINT_KEY, hex_entropy(8))
