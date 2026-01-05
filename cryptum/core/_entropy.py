import secrets


def bytes_entropy(num_bytes: int) -> bytes:
    """
    Generate cryptographically secure random bytes.

    Args:
        num_bytes: The number of bytes to generate. Must be a positive integer.

    Returns:
        A bytes object containing the entropy.

    Raises:
        ValueError: If num_bytes is not a positive integer.
    """
    if not isinstance(num_bytes, int) or num_bytes <= 0:
        raise ValueError("num_bytes must be a positive integer")

    return secrets.token_bytes(num_bytes)


def urlsafe_entropy(num_bytes: int) -> str:
    """
    Generate a cryptographically secure URL-safe base64 string with padding stripped.

    The output length is deterministic based on the input bytes length.
    It follows the formula: ceil(num_bytes * 4 / 3).

    Args:
        num_bytes: The number of entropy bytes to generate before encoding.
            Must be a positive integer.

    Returns:
        A URL-safe base64 encoded string.

    Raises:
        ValueError: If num_bytes is not a positive integer.
    """
    if not isinstance(num_bytes, int) or num_bytes <= 0:
        raise ValueError("num_bytes must be a positive integer")

    return secrets.token_urlsafe(num_bytes)


def hex_entropy(num_bytes: int) -> str:
    """
    Generate a cryptographically secure hexadecimal string.

    The output length is deterministic: 2 * num_bytes.

    Args:
        num_bytes: The number of entropy bytes to generate before encoding.
            Must be a positive integer.

    Returns:
        A hexadecimal string.

    Raises:
        ValueError: If num_bytes is not a positive integer.
    """
    if not isinstance(num_bytes, int) or num_bytes <= 0:
        raise ValueError("num_bytes must be a positive integer")

    return secrets.token_hex(num_bytes)


def random_string(length: int, alphabet: str) -> str:
    """
    Generate a cryptographically secure random string from a given alphabet.

    Args:
        length: The desired length of the string.
        alphabet: A string of characters to choose from.

    Returns:
        A random string.

    Raises:
        ValueError: If length is not a positive integer or alphabet is empty.
    """
    if not isinstance(length, int) or length <= 0:
        raise ValueError("length must be a positive integer")
    if not alphabet:
        raise ValueError("alphabet cannot be empty")

    return "".join(secrets.choice(alphabet) for _ in range(length))
