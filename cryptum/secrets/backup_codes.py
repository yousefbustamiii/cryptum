from cryptum.core import hex_entropy
from cryptum.crypto import Sha256


def generate(count: int = 10) -> list[dict[str, str]]:
    """
    Generate a list of cryptographically secure backup codes.

    Each code is 16 characters long (hexadecimal) and returned with its 
    SHA-256 hash.

    Args:
        count: The number of backup codes to generate. Defaults to 10.

    Returns:
        A list of dictionaries, each containing:
        - 'plaintext': The 16-character backup code.
        - 'hash': The SHA-256 hash to store.
    """
    codes = []
    for _ in range(count):
        # 8 bytes results in exactly 16 hex characters
        plaintext = hex_entropy(8)
        codes.append({
            "plaintext": plaintext,
            "hash": Sha256.hash(plaintext)
        })
    return codes
