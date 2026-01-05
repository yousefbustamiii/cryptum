import string
from cryptum.core import random_string
from cryptum.crypto import Argon2id


def generate() -> dict[str, str]:
    """
    Generate a strong, cryptographically secure password.

    The password is 16 characters long and includes a mix of uppercase
    letters, lowercase letters, digits, and symbols. It is returned 
    along with its Argon2id hash.

    Returns:
        A dictionary containing:
        - 'plaintext': The generated 16-character password.
        - 'hash': The Argon2id hash for secure storage.
    """
    # Combine uppercase, lowercase, digits, and punctuation for maximum strength
    alphabet = string.ascii_letters + string.digits + string.punctuation
    
    password = random_string(16, alphabet)
    
    return {
        "plaintext": password,
        "hash": Argon2id.hash(password)
    }


def verify(password: str, hash: str) -> bool:
    """
    Verify a password against its Argon2id hash.

    Args:
        password: The plain-text password provided by the user.
        hash: The stored Argon2id hash.

    Returns:
        True if the password is correct, False otherwise.
    """
    return Argon2id.verify(password, hash)
