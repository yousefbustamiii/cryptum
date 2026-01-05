import datetime
from cryptum.core import random_string, with_prefix
from cryptum.core._constants import PREFIX_TIME_KEY


def generate() -> str:
    """
    Generate a time-based key with the format: tk_<YYYYMMDDHHMMSS>_<4_random_digits>.

    Returns:
        The plaintext time key.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    timestamp = now.strftime("%Y%m%d%H%M%S")
    random_suffix = random_string(4, "0123456789")
    
    value = f"{timestamp}_{random_suffix}"
    return with_prefix(PREFIX_TIME_KEY, value)
