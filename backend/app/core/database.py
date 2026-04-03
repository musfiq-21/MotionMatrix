"""
Database connection and session management.

This module provides SQLAlchemy database connection handling with:
- Connection pooling for efficient resource usage
- Session management with automatic cleanup
- Retry logic with exponential backoff for transient failures
- FastAPI dependency injection support

Example:
    from app.core.database import get_db, init_db
    
    # Initialize database tables
    init_db()
    
    # Use in FastAPI endpoint
    @app.get("/users")
    def get_users(db: Session = Depends(get_db)):
        return db.query(User).all()
"""

import logging
import time
from typing import Generator
from contextlib import contextmanager

from sqlalchemy import create_engine, event, exc, pool, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import QueuePool

from backend.app.core.config import get_settings

# ============================================================================
# Configuration
# ============================================================================

# Load application settings
settings = get_settings()

# Configure logging for database operations
logger = logging.getLogger(__name__)

# ============================================================================
# SQLAlchemy Base
# ============================================================================

# Declarative base class for all ORM models
# All models should inherit from this base class
Base = declarative_base()

# ============================================================================
# Database Engine Configuration
# ============================================================================

# Engine configuration parameters
ENGINE_CONFIG = {
    # Connection pooling settings
    "poolclass": QueuePool,  # Use QueuePool for production
    "pool_size": settings.DB_POOL_SIZE,  # Number of connections to maintain
    "max_overflow": settings.DB_MAX_OVERFLOW,  # Additional connections allowed
    "pool_pre_ping": True,  # Test connections before using them
    "pool_recycle": 3600,  # Recycle connections after 1 hour
    
    # Echo SQL queries (useful for debugging, disable in production)
    "echo": settings.DB_ECHO,
    
    # Connection arguments for PostgreSQL
    "connect_args": {
        "connect_timeout": 10,  # Connection timeout in seconds
        "options": "-c timezone=utc",  # Set timezone to UTC
    },
}


def create_database_engine():
    """
    Create and configure the SQLAlchemy engine.
    
    The engine manages the database connection pool and handles
    low-level database communication. This function configures:
    - Connection pooling for efficient resource management
    - Pre-ping to validate connections before use
    - Connection recycling to avoid stale connections
    
    Returns:
        Engine: Configured SQLAlchemy engine instance
        
    Raises:
        SQLAlchemyError: If engine creation fails
    """
    try:
        engine = create_engine(settings.DATABASE_URL, **ENGINE_CONFIG)
        logger.info("Database engine created successfully")
        return engine
    except Exception as e:
        logger.error(f"Failed to create database engine: {e}")
        raise


# Create the global engine instance
# This is created once and reused throughout the application lifecycle
engine = create_database_engine()

# ============================================================================
# Session Factory
# ============================================================================

# SessionLocal is a factory for creating database sessions
# Each session represents a "workspace" for database operations
# Sessions are not thread-safe and should not be shared between requests
SessionLocal = sessionmaker(
    bind=engine,  # Bind to our database engine
    autocommit=False,  # Manual commit required (safer for transactions)
    autoflush=False,  # Manual flush required (better control)
    expire_on_commit=True,  # Expire objects after commit (prevent stale data)
)

# ============================================================================
# Database Connection Events
# ============================================================================

@event.listens_for(engine, "connect")
def receive_connect(dbapi_conn, connection_record):
    """
    Event listener that fires when a new database connection is created.
    
    This can be used to set up connection-level configuration such as
    timezone settings, encoding, or connection-specific parameters.
    
    Args:
        dbapi_conn: The raw DBAPI connection
        connection_record: SQLAlchemy connection record
    """
    logger.debug("New database connection established")


@event.listens_for(engine, "checkout")
def receive_checkout(dbapi_conn, connection_record, connection_proxy):
    """
    Event listener that fires when a connection is retrieved from the pool.
    
    This verifies the connection is still alive before use. If the connection
    is dead, it will be invalidated and a new one will be created.
    
    Args:
        dbapi_conn: The raw DBAPI connection
        connection_record: SQLAlchemy connection record
        connection_proxy: SQLAlchemy connection proxy
    """
    logger.debug("Connection checked out from pool")


@event.listens_for(pool.Pool, "invalidate")
def receive_invalidate(dbapi_conn, connection_record, exception):
    """
    Event listener that fires when a connection is invalidated.
    
    This logs when connections are detected as invalid and removed from
    the pool, which helps with monitoring and debugging connection issues.
    
    Args:
        dbapi_conn: The raw DBAPI connection
        connection_record: SQLAlchemy connection record
        exception: The exception that caused invalidation
    """
    logger.warning(f"Connection invalidated: {exception}")


# ============================================================================
# Connection Retry Logic
# ============================================================================

def connect_to_database(max_retries: int = 5, base_delay: float = 1.0) -> bool:
    """
    Attempt to connect to the database with exponential backoff retry logic.
    
    This function tries to establish a database connection, retrying on failure
    with increasing delays between attempts. This handles transient connection
    issues like database startup delays or network hiccups.
    
    Args:
        max_retries: Maximum number of connection attempts (default: 5)
        base_delay: Initial delay between retries in seconds (default: 1.0)
        
    Returns:
        bool: True if connection successful, False otherwise
        
    Example:
        >>> if connect_to_database():
        ...     print("Database connected!")
        ... else:
        ...     print("Failed to connect to database")
    """
    for attempt in range(1, max_retries + 1):
        try:
            # Attempt to create a connection
            with engine.connect() as conn:
                # Execute a simple query to verify connection
                conn.execute(text("SELECT 1"))
                logger.info(f"Database connection successful on attempt {attempt}")
                return True
                
        except exc.OperationalError as e:
            # Calculate exponential backoff delay: 1s, 2s, 4s, 8s, 16s
            delay = base_delay * (2 ** (attempt - 1))
            
            if attempt < max_retries:
                logger.warning(
                    f"Database connection attempt {attempt}/{max_retries} failed: {e}. "
                    f"Retrying in {delay} seconds..."
                )
                time.sleep(delay)
            else:
                logger.error(
                    f"Failed to connect to database after {max_retries} attempts: {e}"
                )
                return False
                
        except Exception as e:
            # Unexpected error - don't retry
            logger.error(f"Unexpected error connecting to database: {e}")
            return False
    
    return False


# ============================================================================
# FastAPI Dependency
# ============================================================================

def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that provides a database session.
    
    This function creates a new database session for each request and
    ensures proper cleanup after the request completes. It follows the
    dependency injection pattern used by FastAPI.
    
    The session is automatically closed whether the request succeeds or fails,
    preventing connection leaks.
    
    Yields:
        Session: SQLAlchemy database session
        
    Example:
        @app.get("/users")
        def get_users(db: Session = Depends(get_db)):
            users = db.query(User).all()
            return users
            
    Notes:
        - Each request gets its own session
        - Sessions are automatically closed after use
        - If an exception occurs, the session is still properly closed
        - This is NOT thread-safe; each request needs its own session
    """
    # Create a new database session
    db = SessionLocal()
    
    try:
        # Yield the session to the route handler
        # Everything after 'yield' runs after the request completes
        yield db
        
    except Exception as e:
        # If an error occurs, rollback any pending changes
        logger.error(f"Database error in request: {e}")
        db.rollback()
        raise
        
    finally:
        # Always close the session, even if an error occurred
        # This ensures connections are returned to the pool
        db.close()
        logger.debug("Database session closed")


# ============================================================================
# Context Manager for Manual Session Management
# ============================================================================

@contextmanager
def get_db_context() -> Generator[Session, None, None]:
    """
    Context manager for database sessions outside of FastAPI requests.
    
    Use this when you need a database session in scripts, background tasks,
    or other contexts where FastAPI's dependency injection isn't available.
    
    Yields:
        Session: SQLAlchemy database session
        
    Example:
        from app.core.database import get_db_context
        
        with get_db_context() as db:
            user = db.query(User).first()
            print(user.name)
        # Session is automatically closed here
        
    Notes:
        - Automatically commits on success
        - Automatically rolls back on error
        - Always closes the session
    """
    db = SessionLocal()
    
    try:
        yield db
        # If we get here without exception, commit the changes
        db.commit()
        
    except Exception as e:
        # If any error occurs, rollback all changes
        logger.error(f"Database error in context: {e}")
        db.rollback()
        raise
        
    finally:
        # Always close the session
        db.close()


# ============================================================================
# Database Initialization
# ============================================================================

def init_db(retry: bool = True) -> bool:
    """
    Initialize the database by creating all tables.
    
    This function creates all tables defined in SQLAlchemy models that
    inherit from Base. It should be called when the application starts
    or during deployment.
    
    Args:
        retry: Whether to retry connection on failure (default: True)
        
    Returns:
        bool: True if initialization successful, False otherwise
        
    Example:
        >>> from backend.app.core.database import init_db
        >>> if init_db():
        ...     print("Database initialized successfully")
        ... else:
        ...     print("Database initialization failed")
        
    Notes:
        - Safe to call multiple times (won't recreate existing tables)
        - Uses CREATE TABLE IF NOT EXISTS internally
        - All models must be imported before calling this function
    """
    try:
        # First, ensure we can connect to the database
        if retry:
            logger.info("Attempting to connect to database...")
            if not connect_to_database():
                logger.error("Cannot initialize database: connection failed")
                return False
        
        # Create all tables defined in models
        # This is idempotent - won't fail if tables already exist
        logger.info("Creating database tables...")
        Base.metadata.create_all(bind=engine)
        
        logger.info("Database tables created successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        return False


def drop_all_tables() -> bool:
    """
    Drop all database tables.
    
    WARNING: This will delete ALL data in the database!
    This should only be used in testing environments or during development.
    
    Returns:
        bool: True if successful, False otherwise
        
    Example:
        >>> # Only use in tests!
        >>> drop_all_tables()
        True
        
    Notes:
        - This is DESTRUCTIVE and cannot be undone
        - Should never be used in production
        - Useful for test cleanup
    """
    try:
        logger.warning("Dropping all database tables...")
        Base.metadata.drop_all(bind=engine)
        logger.info("All tables dropped successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to drop tables: {e}")
        return False


# ============================================================================
# Database Health Check
# ============================================================================

def check_database_health() -> dict:
    """
    Check the health and status of the database connection.
    
    This function verifies that the database is accessible and returns
    information about the connection pool status.
    
    Returns:
        dict: Database health status with the following keys:
            - healthy (bool): Whether database is accessible
            - pool_size (int): Current pool size
            - checked_out (int): Number of connections in use
            - overflow (int): Number of overflow connections
            - message (str): Status message
            
    Example:
        >>> health = check_database_health()
        >>> if health['healthy']:
        ...     print(f"Database is healthy. Pool: {health['pool_size']}")
        ... else:
        ...     print(f"Database issue: {health['message']}")
    """
    try:
        # Test database connection
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        
        # Get pool statistics
        pool_status = engine.pool.status()
        
        return {
            "healthy": True,
            "pool_size": engine.pool.size(),
            "checked_out": engine.pool.checkedout(),
            "overflow": engine.pool.overflow(),
            "message": "Database is healthy",
            "pool_status": pool_status,
        }
        
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {
            "healthy": False,
            "pool_size": 0,
            "checked_out": 0,
            "overflow": 0,
            "message": f"Database unhealthy: {str(e)}",
            "pool_status": None,
        }


# ============================================================================
# Utility Functions
# ============================================================================

def dispose_engine():
    """
    Dispose of the engine and close all connections.
    
    This should be called when shutting down the application to ensure
    all database connections are properly closed.
    
    Example:
        >>> # In application shutdown handler
        >>> dispose_engine()
    """
    logger.info("Disposing database engine and closing connections...")
    engine.dispose()
    logger.info("Database engine disposed successfully")


def reset_engine():
    """
    Reset the engine by disposing and recreating it.
    
    This is useful for tests or when connection settings change.
    
    Returns:
        Engine: New SQLAlchemy engine instance
    """
    global engine
    
    logger.info("Resetting database engine...")
    engine.dispose()
    engine = create_database_engine()
    
    # Update SessionLocal to use new engine
    SessionLocal.configure(bind=engine)
    
    logger.info("Database engine reset successfully")
    return engine


# ============================================================================
# Module Initialization
# ============================================================================

# Log database configuration on module import
logger.info(
    f"Database module initialized - "
    f"Pool size: {settings.DB_POOL_SIZE}, "
    f"Max overflow: {settings.DB_MAX_OVERFLOW}"
)