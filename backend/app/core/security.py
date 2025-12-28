"""
Authentication and security utilities.

This module provides secure password hashing, JWT token management,
and password validation utilities for the Employee Management System.

Security Features:
- Bcrypt password hashing with automatic salt generation
- JWT token creation and validation
- Password strength validation
- Temporary password generation
- Token expiration handling

Example:
    from app.core.security import hash_password, create_access_token
    
    # Hash a password
    hashed = hash_password("MyPassword123")
    
    # Create JWT token
    token = create_access_token({"user_id": 1, "role": "admin"})
"""

import logging
import re
import secrets
import string
from datetime import datetime, timedelta
from typing import Dict, Optional, Union

from jose import JWTError, jwt
from passlib.context import CryptContext

from backend.app.core.config import get_settings

# ============================================================================
# Configuration
# ============================================================================

# Load application settings
settings = get_settings()

# Configure logging for security operations
logger = logging.getLogger(__name__)

# ============================================================================
# Password Hashing Configuration
# ============================================================================

# Create password context for bcrypt hashing
# Bcrypt is recommended for password hashing due to its:
# - Built-in salt generation
# - Computational cost (resistant to brute force)
# - Industry-standard security
pwd_context = CryptContext(
    schemes=["bcrypt"],  # Use bcrypt algorithm
    deprecated="auto",   # Automatically handle deprecated hashes
    bcrypt__rounds=12,   # Cost factor (higher = slower but more secure)
)

# ============================================================================
# Password Hashing Functions
# ============================================================================

def hash_password(password: str) -> str:
    """
    Hash a plain text password using bcrypt.
    
    This function generates a secure hash of the password with an automatic
    salt. The same password will produce different hashes each time due to
    the random salt, making rainbow table attacks ineffective.
    
    Args:
        password: Plain text password to hash
        
    Returns:
        str: Bcrypt hashed password (includes salt)
        
    Raises:
        ValueError: If password is empty or None
        
    Example:
        >>> hashed = hash_password("MySecurePassword123")
        >>> print(hashed)
        $2b$12$KIXxLVQy8hR5Nq0vZ8H5K.X8P9Y7Q6R5S4T3U2V1W0...
        
    Notes:
        - Always hash passwords before storing in database
        - Never store plain text passwords
        - The hash includes the salt, so no separate storage needed
        - Bcrypt automatically generates a unique salt each time
    """
    if not password:
        raise ValueError("Password cannot be empty")
    
    try:
        hashed = pwd_context.hash(password)
        logger.debug("Password hashed successfully")
        return hashed
    except Exception as e:
        logger.error(f"Failed to hash password: {e}")
        raise


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain text password against a hashed password.
    
    This function securely compares a plain text password with a bcrypt hash.
    It extracts the salt from the hash and applies it to the plain password
    to verify if they match.
    
    Args:
        plain_password: Plain text password to verify
        hashed_password: Previously hashed password from database
        
    Returns:
        bool: True if password matches, False otherwise
        
    Example:
        >>> hashed = hash_password("MyPassword123")
        >>> verify_password("MyPassword123", hashed)
        True
        >>> verify_password("WrongPassword", hashed)
        False
        
    Notes:
        - Always use this function for password verification
        - Never compare passwords using simple string comparison
        - Returns False for any errors (fail-safe approach)
        - Resistant to timing attacks
    """
    if not plain_password or not hashed_password:
        logger.warning("Empty password or hash provided for verification")
        return False
    
    try:
        is_valid = pwd_context.verify(plain_password, hashed_password)
        if is_valid:
            logger.debug("Password verification successful")
        else:
            logger.debug("Password verification failed")
        return is_valid
    except Exception as e:
        logger.error(f"Error verifying password: {e}")
        return False


def needs_rehash(hashed_password: str) -> bool:
    """
    Check if a password hash needs to be regenerated.
    
    This is useful when:
    - The bcrypt cost factor has been increased
    - The hashing algorithm has been updated
    - Security best practices have changed
    
    Args:
        hashed_password: Existing password hash
        
    Returns:
        bool: True if hash should be regenerated, False otherwise
        
    Example:
        >>> if needs_rehash(user.password_hash):
        ...     user.password_hash = hash_password(plain_password)
        ...     db.commit()
    """
    try:
        return pwd_context.needs_update(hashed_password)
    except Exception as e:
        logger.error(f"Error checking if hash needs update: {e}")
        return False


# ============================================================================
# JWT Token Management
# ============================================================================

def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT access token with embedded user data.
    
    This function generates a signed JWT token containing user information
    and an expiration time. The token can be used for authentication in
    API requests.
    
    Args:
        data: Dictionary containing user data to encode in token
              Typically includes: user_id, role, email, etc.
        expires_delta: Optional custom expiration time
                      If None, uses settings.ACCESS_TOKEN_EXPIRE_MINUTES
                      
    Returns:
        str: Encoded JWT token string
        
    Raises:
        ValueError: If data is empty or invalid
        
    Example:
        >>> token_data = {
        ...     "user_id": 123,
        ...     "role": "admin",
        ...     "email": "admin@example.com"
        ... }
        >>> token = create_access_token(token_data)
        >>> print(token)
        eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
        
        >>> # Custom expiration (1 hour)
        >>> token = create_access_token(token_data, timedelta(hours=1))
        
    Token Structure:
        The token includes:
        - All data from the `data` parameter
        - "exp": Expiration timestamp
        - "iat": Issued at timestamp
        
    Notes:
        - Tokens are signed but not encrypted (don't include sensitive data)
        - Always validate tokens on the server side
        - Use HTTPS to prevent token interception
        - Store tokens securely on the client side
    """
    if not data:
        raise ValueError("Token data cannot be empty")
    
    # Create a copy to avoid modifying the original
    to_encode = data.copy()
    
    # Calculate expiration time
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        )
    
    # Add standard JWT claims
    to_encode.update({
        "exp": expire,  # Expiration time
        "iat": datetime.utcnow(),  # Issued at time
    })
    
    try:
        # Encode the JWT token
        encoded_jwt = jwt.encode(
            to_encode,
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM
        )
        
        logger.debug(
            f"Access token created for user_id: {data.get('user_id', 'unknown')}"
        )
        return encoded_jwt
        
    except Exception as e:
        logger.error(f"Failed to create access token: {e}")
        raise


def create_refresh_token(data: dict) -> str:
    """
    Create a JWT refresh token with longer expiration.
    
    Refresh tokens are used to obtain new access tokens without requiring
    the user to log in again. They have a longer lifespan than access tokens.
    
    Args:
        data: Dictionary containing user data to encode
        
    Returns:
        str: Encoded JWT refresh token
        
    Example:
        >>> refresh_token = create_refresh_token({"user_id": 123})
    """
    expires_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    return create_access_token(data, expires_delta)


def decode_access_token(token: str) -> Dict[str, Union[int, str]]:
    """
    Decode and validate a JWT access token.
    
    This function verifies the token signature, checks expiration,
    and returns the decoded payload. If the token is invalid or expired,
    it raises an appropriate exception.
    
    Args:
        token: JWT token string to decode
        
    Returns:
        dict: Decoded token payload containing user data
        
    Raises:
        JWTError: If token is invalid, expired, or malformed
        ValueError: If token is empty or None
        
    Example:
        >>> token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        >>> try:
        ...     payload = decode_access_token(token)
        ...     user_id = payload["user_id"]
        ...     role = payload["role"]
        ... except JWTError:
        ...     print("Invalid or expired token")
        
    Common Exceptions:
        - ExpiredSignatureError: Token has expired
        - JWTError: Token is invalid or malformed
        - JWTClaimsError: Required claims are missing
        
    Notes:
        - Always wrap this in try-except when using
        - Expired tokens will raise ExpiredSignatureError
        - Invalid signatures will raise JWTError
        - Use this to protect API endpoints
    """
    if not token:
        raise ValueError("Token cannot be empty")
    
    try:
        # Decode and verify the token
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        
        logger.debug(
            f"Token decoded successfully for user_id: {payload.get('user_id', 'unknown')}"
        )
        return payload
        
    except jwt.ExpiredSignatureError:
        logger.warning("Attempted to use expired token")
        raise JWTError("Token has expired")
        
    except jwt.JWTError as e:
        logger.warning(f"Invalid token: {e}")
        raise JWTError("Invalid token")
        
    except Exception as e:
        logger.error(f"Unexpected error decoding token: {e}")
        raise JWTError("Token validation failed")


def get_token_expiration(token: str) -> Optional[datetime]:
    """
    Get the expiration datetime of a JWT token.
    
    Args:
        token: JWT token string
        
    Returns:
        datetime: Token expiration time, or None if invalid
        
    Example:
        >>> exp_time = get_token_expiration(token)
        >>> if exp_time and exp_time > datetime.utcnow():
        ...     print("Token is still valid")
    """
    try:
        payload = decode_access_token(token)
        exp_timestamp = payload.get("exp")
        if exp_timestamp:
            return datetime.fromtimestamp(exp_timestamp)
        return None
    except:
        return None


# ============================================================================
# Password Strength Validation
# ============================================================================

def validate_password_strength(password: str) -> tuple[bool, list[str]]:
    """
    Validate password strength against security requirements.
    
    This function checks if a password meets the minimum security requirements
    defined in the application settings. It returns both a boolean result
    and a list of specific validation errors.
    
    Password Requirements (configurable via settings):
    - Minimum length (default: 8 characters)
    - At least one uppercase letter (if PASSWORD_REQUIRE_UPPERCASE=True)
    - At least one lowercase letter (if PASSWORD_REQUIRE_LOWERCASE=True)
    - At least one digit (if PASSWORD_REQUIRE_DIGIT=True)
    - At least one special character (if PASSWORD_REQUIRE_SPECIAL=True)
    
    Args:
        password: Password string to validate
        
    Returns:
        tuple: (is_valid, list_of_errors)
            - is_valid (bool): True if password meets all requirements
            - list_of_errors (list): List of specific validation errors
            
    Example:
        >>> is_valid, errors = validate_password_strength("weak")
        >>> if not is_valid:
        ...     for error in errors:
        ...         print(f"- {error}")
        - Password must be at least 8 characters long
        - Password must contain at least one uppercase letter
        - Password must contain at least one digit
        
        >>> is_valid, _ = validate_password_strength("StrongP@ss123")
        >>> print(is_valid)
        True
        
    Common Use Cases:
        # During user registration
        is_valid, errors = validate_password_strength(new_password)
        if not is_valid:
            raise ValidationError(errors)
        
        # During password reset
        if not validate_password_strength(new_password)[0]:
            return {"error": "Password does not meet requirements"}
    """
    errors = []
    
    if not password:
        return False, ["Password cannot be empty"]
    
    # Check minimum length
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        errors.append(
            f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long"
        )
    
    # Check for uppercase letter
    if settings.PASSWORD_REQUIRE_UPPERCASE:
        if not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter")
    
    # Check for lowercase letter
    if settings.PASSWORD_REQUIRE_LOWERCASE:
        if not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter")
    
    # Check for digit
    if settings.PASSWORD_REQUIRE_DIGIT:
        if not re.search(r"\d", password):
            errors.append("Password must contain at least one digit")
    
    # Check for special character
    if settings.PASSWORD_REQUIRE_SPECIAL:
        if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
            errors.append(
                "Password must contain at least one special character (!@#$%^&*...)"
            )
    
    is_valid = len(errors) == 0
    
    if is_valid:
        logger.debug("Password strength validation passed")
    else:
        logger.debug(f"Password strength validation failed: {len(errors)} errors")
    
    return is_valid, errors


def get_password_strength_score(password: str) -> int:
    """
    Calculate a password strength score from 0-5.
    
    Scoring criteria:
    - 1 point: Length >= 8
    - 1 point: Length >= 12
    - 1 point: Contains uppercase and lowercase
    - 1 point: Contains digits
    - 1 point: Contains special characters
    
    Args:
        password: Password to evaluate
        
    Returns:
        int: Strength score (0=very weak, 5=very strong)
        
    Example:
        >>> score = get_password_strength_score("MyP@ssw0rd123")
        >>> if score >= 4:
        ...     print("Strong password")
    """
    if not password:
        return 0
    
    score = 0
    
    # Length points
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    
    # Character variety points
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 1
    if re.search(r"\d", password):
        score += 1
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
        score += 1
    
    return score


# ============================================================================
# Temporary Password Generation
# ============================================================================

def generate_temp_password(length: int = 12) -> str:
    """
    Generate a random temporary password.
    
    This function creates a cryptographically secure random password
    suitable for temporary use (e.g., password resets, new user accounts).
    
    The generated password includes:
    - Uppercase letters (A-Z)
    - Lowercase letters (a-z)
    - Digits (0-9)
    
    Args:
        length: Desired password length (default: 12, minimum: 8)
        
    Returns:
        str: Randomly generated password
        
    Raises:
        ValueError: If length is less than 8
        
    Example:
        >>> temp_pass = generate_temp_password()
        >>> print(temp_pass)
        aB3dEf7GhI9k
        
        >>> # Generate longer password
        >>> long_pass = generate_temp_password(length=16)
        
    Common Use Cases:
        # Password reset
        new_password = generate_temp_password()
        user.password_hash = hash_password(new_password)
        send_email(user.email, f"Your temporary password: {new_password}")
        
        # New user account
        temp_pass = generate_temp_password()
        user = User(email=email, password_hash=hash_password(temp_pass))
        
    Notes:
        - Uses secrets module for cryptographic randomness
        - Always force user to change temporary password on first login
        - Send temporary passwords via secure channel (email, SMS)
        - Set expiration time for temporary passwords
        - Log password generation events for audit trail
    """
    if length < 8:
        raise ValueError("Password length must be at least 8 characters")
    
    # Define character sets
    # Using alphanumeric only to avoid confusion (no special chars)
    characters = string.ascii_letters + string.digits
    
    # Generate password using cryptographically secure random
    # secrets.choice() is more secure than random.choice()
    password = ''.join(secrets.choice(characters) for _ in range(length))
    
    # Ensure password has at least one uppercase, lowercase, and digit
    # Regenerate if it doesn't meet minimum requirements
    while not (
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"\d", password)
    ):
        password = ''.join(secrets.choice(characters) for _ in range(length))
    
    logger.info("Temporary password generated")
    return password


def generate_temp_password_with_special(length: int = 12) -> str:
    """
    Generate a random temporary password with special characters.
    
    Similar to generate_temp_password but includes special characters
    for higher entropy.
    
    Args:
        length: Desired password length (default: 12, minimum: 8)
        
    Returns:
        str: Randomly generated password with special characters
        
    Example:
        >>> temp_pass = generate_temp_password_with_special()
        >>> print(temp_pass)
        aB3@dE#7Gh!9
    """
    if length < 8:
        raise ValueError("Password length must be at least 8 characters")
    
    # Include special characters for higher entropy
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    
    password = ''.join(secrets.choice(characters) for _ in range(length))
    
    # Ensure password meets all requirements
    while not (
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"\d", password) and
        re.search(r"[!@#$%^&*]", password)
    ):
        password = ''.join(secrets.choice(characters) for _ in range(length))
    
    logger.info("Temporary password with special characters generated")
    return password


# ============================================================================
# Security Utilities
# ============================================================================

def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.
    
    Useful for:
    - Email verification tokens
    - Password reset tokens
    - API keys
    - Session tokens
    
    Args:
        length: Number of bytes for the token (default: 32)
        
    Returns:
        str: URL-safe random token (hex string)
        
    Example:
        >>> token = generate_secure_token()
        >>> print(len(token))
        64  # 32 bytes = 64 hex characters
        
        >>> reset_token = generate_secure_token()
        >>> user.reset_token = reset_token
        >>> send_reset_email(user.email, reset_token)
    """
    return secrets.token_hex(length)


def constant_time_compare(val1: str, val2: str) -> bool:
    """
    Compare two strings in constant time.
    
    This prevents timing attacks where an attacker could determine
    the correct value by measuring how long comparisons take.
    
    Args:
        val1: First string to compare
        val2: Second string to compare
        
    Returns:
        bool: True if strings are equal, False otherwise
        
    Example:
        >>> # Use for comparing tokens, API keys, etc.
        >>> if constant_time_compare(provided_token, stored_token):
        ...     print("Token valid")
        
    Notes:
        - Always use this for security-sensitive comparisons
        - Regular == comparison can leak timing information
        - Essential for API key validation, token comparison
    """
    return secrets.compare_digest(val1, val2)


# ============================================================================
# Token Blacklist (for logout functionality)
# ============================================================================

# In-memory token blacklist (use Redis in production)
_token_blacklist: set = set()


def blacklist_token(token: str) -> None:
    """
    Add a token to the blacklist (for logout).
    
    Note: This is an in-memory implementation.
    For production, use Redis or database-backed storage.
    
    Args:
        token: JWT token to blacklist
        
    Example:
        >>> # On user logout
        >>> blacklist_token(user_token)
    """
    _token_blacklist.add(token)
    logger.info("Token blacklisted")


def is_token_blacklisted(token: str) -> bool:
    """
    Check if a token has been blacklisted.
    
    Args:
        token: JWT token to check
        
    Returns:
        bool: True if token is blacklisted, False otherwise
        
    Example:
        >>> if is_token_blacklisted(token):
        ...     raise HTTPException(401, "Token has been revoked")
    """
    return token in _token_blacklist


def clear_token_blacklist() -> None:
    """
    Clear all blacklisted tokens.
    
    Useful for testing or maintenance.
    """
    global _token_blacklist
    _token_blacklist.clear()
    logger.info("Token blacklist cleared")


# ============================================================================
# Module Initialization
# ============================================================================

logger.info(
    f"Security module initialized - "
    f"JWT Algorithm: {settings.JWT_ALGORITHM}, "
    f"Token Expiry: {settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES} minutes"
)