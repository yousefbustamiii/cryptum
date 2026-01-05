from argon2 import PasswordHasher, exceptions, Type


def hash(secret: str) -> str:
    """
    Hash a secret using Argon2id.

    Argon2id is used because it provides the best of both worlds: it is resistant
    to side-channel timing attacks (inherited from Argon2i) and GPU-based 
    cracking attacks (inherited from Argon2d).

    This implementation uses conservative, modern defaults:
    - Time cost: 3 iterations
    - Memory cost: 64 MiB (65536 KiB)
    - Parallelism: 2 threads

    Args:
        secret: The plain-text secret string to hash.

    Returns:
        A string containing the encoded hash, including salt and parameters.

    Raises:
        TypeError: If the secret is not a string.
    """
    if not isinstance(secret, str):
        raise TypeError("secret must be a string")

    # We instantiate the hasher inside to avoid global mutable state
    hasher = PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    )

    return hasher.hash(secret)


def verify(secret: str, hash: str) -> bool:
    """
    Verify a secret against an Argon2id hash.

    Args:
        secret: The plain-text secret string to verify.
        hash: The encoded hash string to verify against.

    Returns:
        True if the secret matches the hash, False otherwise.
    """
    if not isinstance(secret, str) or not isinstance(hash, str):
        raise TypeError("secret and hash must be strings")

    hasher = PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    )

    try:
        return hasher.verify(hash, secret)
    except exceptions.VerifyMismatchError:
        return False
    except Exception:
        return False
