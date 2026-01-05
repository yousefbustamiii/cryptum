import secrets
from cryptum.core import hex_entropy, with_prefix
from cryptum.core._constants import PREFIX_CLASSIFICATION_KEY


def generate() -> str:
    """
    Generate a classification key starting with '01', '02', or '03', followed by 14 random chars.
    The total value length after the prefix is 16 characters.

    Returns:
        The plaintext classification key (e.g., 'clk_01...').
    """
    starter = secrets.choice(["01", "02", "03"])
    # 7 bytes = 14 hex characters
    random_suffix = hex_entropy(7)
    
    value = f"{starter}{random_suffix}"
    return with_prefix(PREFIX_CLASSIFICATION_KEY, value)
