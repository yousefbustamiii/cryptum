# Entropy Byte Sizes
# Ensures collision resistance for non-sensitive unique markers
ENTROPY_IDENTIFIER = 16

# Minimum standard for short-duration authentication artifacts
ENTROPY_SHORT_LIVED = 32

# Hardened entropy for tokens that persist for long periods (e.g., refresh tokens)
ENTROPY_LONG_LIVED = 64

# Standard length for high-security symmetric keys and cryptographic secrets
ENTROPY_SECRET = 32


# Canonical Token Prefixes
# Identifies an API Access Key at a glance for easier scanning and revocation
PREFIX_ACCESS_KEY = "ak"

# Clearly distinguishes Refresh Tokens from Access Tokens in storage/logs
PREFIX_REFRESH_TOKEN = "rt"

# Prevents confusion between CSRF protection and other session-related tokens
PREFIX_CSRF_TOKEN = "csrf"

# Signals that the value is a sensitive secret key meant for backend use
PREFIX_SECRET_KEY = "sk"

# Marks an ephemeral session identifier
PREFIX_SESSION = "sess"

# Used for webhook signing or identification secrets
PREFIX_WEBHOOK_SECRET = "whs"

# Clearly identifies email verification tokens
PREFIX_EMAIL_VERIFICATION = "ev"

# Used for magic link authentication
PREFIX_MAGIC_LINK = "ml"

# Identifies a high-privilege sudo session token
PREFIX_SUDO_SESSION = "sudo"

# Marks a temporary session for 2FA completion
PREFIX_2FA_SESSION = "tfas"

# Used for password reset flows
PREFIX_PASSWORD_RESET = "pr"

# Identifies a re-authentication challenge token
PREFIX_REAUTH_TOKEN = "ra"

# Used for one-time cryptographic nonces
PREFIX_NONCE = "n"

# Clearly identifies encryption keys for data at rest
PREFIX_ENCRYPTION_KEY = "ek"

# Key Prefixes
PREFIX_CONFIRMATION_KEY = "ck"
PREFIX_DEDUPLICATION_KEY = "dk"
PREFIX_FINGERPRINT_KEY = "fk"
PREFIX_IDEMPOTENCY_KEY = "idemk"
PREFIX_SESSION_KEY = "ssk"
PREFIX_TIME_KEY = "tk"
PREFIX_TRACE_KEY = "trk"
PREFIX_CLASSIFICATION_KEY = "clk"
PREFIX_FAILURE_KEY = "flk"