import base64
import os
from typing import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def _derive_key(secret: str | bytes, salt: Optional[bytes] = None) -> bytes:
    """
    Derive a 32-byte key for AES-256 using HKDF (HMAC-based Key Derivation Function).
    This is significantly more secure than a raw hash as it provides key expansion 
    and strong cryptographic separation.
    """
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"cryptum-aes-gcm-key",
    ).derive(secret)

def encrypt(plaintext: str | bytes, secret_key: str | bytes, context: Optional[str] = None) -> str:
    """
    Encrypt data using AES-256-GCM and return a Base64 encoded string.
    
    The resulting string contains: base64(nonce + ciphertext + tag)
    
    Args:
        plaintext: The data to encrypt (string or bytes).
        secret_key: The master key used for encryption.
        context: Optional context (AAD) to bind the ciphertext to a specific scope.
        
    Returns:
        The Base64 encoded encrypted blob.
    """
    if isinstance(plaintext, str):
        data = plaintext.encode("utf-8")
    else:
        data = plaintext
        
    aad = context.encode("utf-8") if context else None
    
    key = _derive_key(secret_key)
    aesgcm = AESGCM(key)
    
    # 12 bytes is the standard nonce size for GCM
    nonce = os.urandom(12)
    
    # cryptography's AESGCM returns ciphertext + tag
    encrypted_data = aesgcm.encrypt(nonce, data, aad)
    
    # Combine nonce + ciphertext + tag
    blob = nonce + encrypted_data
    
    return base64.b64encode(blob).decode("utf-8")

def decrypt(ciphertext_b64: str, secret_key: str | bytes, context: Optional[str] = None) -> str:
    """
    Decrypt an AES-256-GCM encoded Base64 string back to plaintext.
    
    Args:
        ciphertext_b64: The Base64 encoded encrypted blob (nonce + ciphertext + tag).
        secret_key: The secret key used for encryption.
        context: The context (AAD) used during encryption.
        
    Returns:
        The decrypted plaintext as a UTF-8 string.
        
    Raises:
        ValueError: If decryption fails or data is corrupted.
    """
    try:
        blob = base64.b64decode(ciphertext_b64)
        if len(blob) < 28: # 12 (nonce) + 16 (min tag)
            raise ValueError("Invalid ciphertext: too short")
            
        aad = context.encode("utf-8") if context else None
        key = _derive_key(secret_key)
        aesgcm = AESGCM(key)
        
        nonce = blob[:12]
        encrypted_payload = blob[12:]
        
        decrypted_bytes = aesgcm.decrypt(nonce, encrypted_payload, aad)
        return decrypted_bytes.decode("utf-8")
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")
