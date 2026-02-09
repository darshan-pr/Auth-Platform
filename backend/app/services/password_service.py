import bcrypt

def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    # Encode the password and hash it
    password_bytes = password.encode('utf-8')
    # Truncate to 72 bytes (bcrypt limit)
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a hash"""
    password_bytes = password.encode('utf-8')
    # Truncate to 72 bytes (bcrypt limit)
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    hashed_bytes = hashed.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)
