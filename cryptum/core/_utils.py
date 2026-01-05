import hmac


def with_prefix(prefix: str, value: str) -> str:
    """
    Combine a prefix and a value with exactly one underscore separator.

    Validates that the prefix is non-empty and handles cases where the prefix
    ends with an underscore or the value starts with one.

    Args:
        prefix: The prefix string. Must be non-empty.
        value: The value string.

    Returns:
        The prefixed string (e.g., "prefix_value").

    Raises:
        ValueError: If prefix is empty or exclusively underscores.
    """
    stripped_prefix = prefix.strip("_")
    stripped_value = value.lstrip("_")

    if not stripped_prefix:
        raise ValueError("prefix must be a non-empty string")

    return f"{stripped_prefix}_{stripped_value}"


def timing_safe_equals(a: str, b: str) -> bool:
    """
    Compare two strings in constant time to prevent timing attacks.

    Args:
        a: First string to compare.
        b: Second string to compare.

    Returns:
        True if the strings are equal, False otherwise.
    """
    return hmac.compare_digest(a, b)
