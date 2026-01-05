from cryptum.core import hex_entropy, with_prefix
from cryptum.core._constants import PREFIX_TRACE_KEY


def generate() -> str:
    """
    Generate a 16-character random trace key for observability.

    Returns:
        The plaintext trace key (e.g., 'trk_...').
    """
    return with_prefix(PREFIX_TRACE_KEY, hex_entropy(8))
