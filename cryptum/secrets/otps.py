from cryptum.core import random_string
from cryptum.crypto import Sha256


def generate() -> dict[str, str]:
    """
    Generate a cryptographically secure 6-digit numeric OTP.

    Returns:
        A dictionary containing:
        - 'plaintext': The 6-digit OTP as a string (e.g., '123456').
        - 'hash': The SHA-256 hash to store and verify against.
    """
    digits = random_string(6, "0123456789")
    
    return {
        "plaintext": digits,
        "hash": Sha256.hash(digits)
    }
