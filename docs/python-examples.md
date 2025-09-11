# MattStash Python API Examples

This guide demonstrates practical Python usage patterns for MattStash, focusing on storing credentials and retrieving ready-to-use service clients.

## Table of Contents

- [S3 Credential Management](#s3-credential-management)
- [Database Credential Management](#database-credential-management)
- [Advanced Usage Patterns](#advanced-usage-patterns)
- [Error Handling](#error-handling)
- [Best Practices](#best-practices)

## S3 Credential Management

### Storing S3 Credentials

```python
import mattstash

# Store AWS S3 credentials
mattstash.put(
    "aws-production",
    username="AKIA1234567890EXAMPLE",  # Access Key ID
    password="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # Secret Access Key
    url="https://s3.amazonaws.com",  # S3 endpoint
    notes="Production AWS S3 account",
    tags=["aws", "s3", "production"]
)

# Store MinIO/S3-compatible credentials
mattstash.put(
    "minio-backup",
    username="minioadmin",
    password="minioadmin123",
    url="https://minio.company.com",
    notes="Internal MinIO backup storage",
    tags=["minio", "backup", "internal"]
)

# Store DigitalOcean Spaces credentials
mattstash.put(
    "do-spaces",
    username="DO_SPACES_KEY",
    password="DO_SPACES_SECRET",
    url="https://nyc3.digitaloceanspaces.com",
    notes="DigitalOcean Spaces CDN",
    tags=["digitalocean", "spaces", "cdn"]
)
```

### Retrieving Direct boto3 S3 Clients

```python
import mattstash

# Get ready-to-use S3 client for AWS
s3_aws = mattstash.get_s3_client(
    "aws-production",
    region="us-west-2",
    addressing="virtual",  # virtual hosted-style addressing
    signature_version="s3v4"
)

# Use the client immediately
try:
    # List buckets
    response = s3_aws.list_buckets()
    print(f"Found {len(response['Buckets'])} buckets:")
    for bucket in response['Buckets']:
        print(f"  - {bucket['Name']}")
    
    # Upload a file
    s3_aws.upload_file(
        'local-file.txt',
        'my-bucket',
        'uploaded-file.txt'
    )
    
    # Download a file
    s3_aws.download_file(
        'my-bucket',
        'uploaded-file.txt',
        'downloaded-file.txt'
    )
    
except Exception as e:
    print(f"S3 operation failed: {e}")

# Get S3 client for MinIO with custom configuration
s3_minio = mattstash.get_s3_client(
    "minio-backup",
    region="us-east-1",
    addressing="path",  # path-style addressing for MinIO
    retries_max_attempts=5
)

# MinIO operations
try:
    # Create bucket if it doesn't exist
    s3_minio.create_bucket(Bucket='daily-backups')
    
    # Put object
    s3_minio.put_object(
        Bucket='daily-backups',
        Key='backup-2024-01-15.tar.gz',
        Body=open('backup.tar.gz', 'rb')
    )
    
except Exception as e:
    print(f"MinIO operation failed: {e}")
```

### Advanced S3 Usage Patterns

```python
import mattstash
from contextlib import contextmanager

@contextmanager
def s3_client_context(credential_name, **kwargs):
    """Context manager for S3 operations with automatic cleanup."""
    client = mattstash.get_s3_client(credential_name, **kwargs)
    try:
        yield client
    finally:
        # Any cleanup if needed
        pass

# Usage with context manager
with s3_client_context("aws-production", region="eu-west-1") as s3:
    # Batch operations
    for i in range(10):
        s3.put_object(
            Bucket='data-bucket',
            Key=f'data/file-{i}.json',
            Body=f'{{"data": "example-{i}"}}'
        )

# Multi-environment S3 access
class S3Manager:
    def __init__(self):
        self.clients = {}
    
    def get_client(self, environment):
        if environment not in self.clients:
            credential_name = f"s3-{environment}"
            self.clients[environment] = mattstash.get_s3_client(
                credential_name,
                region="us-west-2"
            )
        return self.clients[environment]
    
    def sync_between_environments(self, source_env, dest_env, bucket, key):
        source = self.get_client(source_env)
        dest = self.get_client(dest_env)
        
        # Download from source
        obj = source.get_object(Bucket=bucket, Key=key)
        
        # Upload to destination
        dest.put_object(
            Bucket=bucket,
            Key=key,
            Body=obj['Body'].read()
        )

# Usage
s3_manager = S3Manager()
s3_manager.sync_between_environments("staging", "production", "assets", "config.json")
```

## Database Credential Management

### Storing Database Credentials

```python
import mattstash

# Store PostgreSQL credentials
mattstash.put(
    "postgres-production",
    username="app_user",
    password="secure_db_password_123",
    url="prod-db.company.com:5432",
    notes="Production PostgreSQL database",
    tags=["postgresql", "production", "primary"]
)

# Store MySQL credentials
mattstash.put(
    "mysql-analytics",
    username="analytics_ro",
    password="readonly_password_456",
    url="analytics-db.company.com:3306",
    notes="Read-only analytics MySQL database",
    tags=["mysql", "analytics", "readonly"]
)

# Store Redis credentials
mattstash.put(
    "redis-cache",
    username="redis_user",
    password="redis_password_789",
    url="cache-cluster.company.com:6379",
    notes="Redis cache cluster",
    tags=["redis", "cache", "session"]
)

# Store MongoDB credentials
mattstash.put(
    "mongodb-documents",
    username="doc_service",
    password="mongo_password_abc",
    url="mongodb://mongo1.company.com:27017,mongo2.company.com:27017,mongo3.company.com:27017",
    notes="MongoDB replica set for document storage",
    tags=["mongodb", "documents", "replica-set"]
)
```

### Retrieving Database URLs and Connections

```python
import mattstash
from sqlalchemy import create_engine, text, MetaData, Table, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base
import psycopg2
import redis
import pymongo

# === SQLAlchemy PostgreSQL Integration ===

# Generate database URL with masked password (for logging/display)
masked_db_url = mattstash.get_db_url(
    "postgres-production",
    database="myapp_production", 
    driver="psycopg"  # Modern psycopg3 driver
)
print(f"Database URL: {masked_db_url}")
# Output: "postgresql+psycopg://app_user:*****@prod-db.company.com:5432/myapp_production"

# Generate unmasked URL for actual connection
postgres_url = mattstash.get_db_url(
    "postgres-production",
    database="myapp_production",
    driver="psycopg",  # or "psycopg2", "asyncpg"
    mask_password=False  # Needed for actual connections
)

# Create SQLAlchemy engine with connection pooling
postgres_engine = create_engine(
    postgres_url,
    pool_size=10,
    max_overflow=20,
    pool_timeout=30,
    pool_recycle=3600,
    echo=False  # Set to True for SQL debugging
)

# Test the connection
try:
    with postgres_engine.connect() as connection:
        result = connection.execute(text("SELECT version()"))
        version = result.scalar()
        print(f"✅ Connected to PostgreSQL: {version}")
except Exception as e:
    print(f"❌ Connection failed: {e}")

# Create session factory for ORM operations
Base = declarative_base()
PostgresSession = sessionmaker(bind=postgres_engine)

# Example model definition
class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)

# Usage with SQLAlchemy ORM
with PostgresSession() as session:
    # Query using ORM
    user_count = session.query(User).count()
    print(f"Total users in database: {user_count}")
    
    # Raw SQL query
    result = session.execute(text("SELECT COUNT(*) FROM users WHERE created_at > :date"))
    recent_users = result.scalar()
    print(f"Recent users: {recent_users}")

# Multiple database connections with different drivers
development_url = mattstash.get_db_url(
    "postgres-development",
    database="myapp_dev",
    driver="psycopg2",  # Legacy psycopg2 driver
    mask_password=False
)

analytics_url = mattstash.get_db_url(
    "postgres-analytics",
    database="analytics_db", 
    driver="asyncpg",  # Async driver for high-performance apps
    mask_password=False
)

# Create multiple engines
dev_engine = create_engine(development_url, echo=True)  # Debug mode for development
analytics_engine = create_engine(analytics_url, pool_size=20)  # Larger pool for analytics

print(f"Development DB: {mattstash.get_db_url('postgres-development', database='myapp_dev')}")
print(f"Analytics DB: {mattstash.get_db_url('postgres-analytics', database='analytics_db')}")
```

### Complete PostgreSQL Integration Example

```python
import mattstash
from sqlalchemy import create_engine, text, select
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import SQLAlchemyError
from contextlib import contextmanager
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PostgreSQLManager:
    """Production-ready PostgreSQL connection manager using MattStash."""
    
    def __init__(self, credential_name: str, database: str, **engine_kwargs):
        self.credential_name = credential_name
        self.database = database
        self.engine = self._create_engine(**engine_kwargs)
        self.Session = sessionmaker(bind=self.engine)
    
    def _create_engine(self, **engine_kwargs):
        """Create SQLAlchemy engine from MattStash credentials."""
        try:
            # Get database URL from MattStash
            db_url = mattstash.get_db_url(
                self.credential_name,
                database=self.database,
                driver="psycopg",
                mask_password=False
            )
            
            # Default engine configuration
            default_config = {
                'pool_size': 5,
                'max_overflow': 10,
                'pool_timeout': 30,
                'pool_recycle': 3600,
                'pool_pre_ping': True,  # Validate connections before use
                'echo': False
            }
            default_config.update(engine_kwargs)
            
            engine = create_engine(db_url, **default_config)
            
            # Test connection
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            
            logger.info(f"✅ PostgreSQL engine created for {self.credential_name}:{self.database}")
            return engine
            
        except Exception as e:
            logger.error(f"❌ Failed to create PostgreSQL engine: {e}")
            raise
    
    @contextmanager
    def get_session(self):
        """Context manager for database sessions with automatic cleanup."""
        session = self.Session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    
    @contextmanager 
    def get_connection(self):
        """Context manager for raw database connections."""
        connection = self.engine.connect()
        try:
            yield connection
        finally:
            connection.close()
    
    def health_check(self) -> bool:
        """Check database connectivity and performance."""
        try:
            with self.get_connection() as conn:
                start_time = time.time()
                result = conn.execute(text("SELECT 1, version(), current_timestamp"))
                row = result.fetchone()
                response_time = time.time() - start_time
                
                logger.info(f"Database health check passed in {response_time:.3f}s")
                logger.info(f"PostgreSQL version: {row[1]}")
                return True
                
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False

# Initialize database managers for different environments
production_db = PostgreSQLManager(
    "postgres-production", 
    "myapp_production",
    pool_size=15,
    max_overflow=25,
    echo=False
)

development_db = PostgreSQLManager(
    "postgres-development",
    "myapp_dev", 
    pool_size=5,
    echo=True  # Enable SQL logging in development
)

analytics_db = PostgreSQLManager(
    "postgres-analytics",
    "analytics_db",
    pool_size=20,  # Higher pool for analytics workloads
    max_overflow=30
)

# Health check all databases at startup
databases = {
    "Production": production_db,
    "Development": development_db, 
    "Analytics": analytics_db
}

for name, db_manager in databases.items():
    if db_manager.health_check():
        print(f"✅ {name} database: Connected")
    else:
        print(f"❌ {name} database: Failed")

# Example usage in application code
def get_user_analytics():
    """Example function using multiple databases."""
    
    # Get user data from production
    with production_db.get_session() as session:
        users = session.execute(
            text("SELECT id, username, created_at FROM users WHERE active = true")
        ).fetchall()
    
    # Store analytics in analytics database
    with analytics_db.get_session() as session:
        for user in users:
            session.execute(
                text("""
                    INSERT INTO user_analytics (user_id, username, analysis_date)
                    VALUES (:user_id, :username, CURRENT_DATE)
                    ON CONFLICT (user_id, analysis_date) DO NOTHING
                """),
                {
                    "user_id": user.id,
                    "username": user.username
                }
            )
    
    print(f"Processed analytics for {len(users)} users")

# Run analytics processing
get_user_analytics()

# Raw connection example for complex operations
with production_db.get_connection() as conn:
    # Execute complex query that doesn't fit ORM patterns
    result = conn.execute(text("""
        WITH monthly_stats AS (
            SELECT 
                DATE_TRUNC('month', created_at) as month,
                COUNT(*) as user_count
            FROM users 
            WHERE created_at >= CURRENT_DATE - INTERVAL '12 months'
            GROUP BY DATE_TRUNC('month', created_at)
        )
        SELECT month, user_count, 
               user_count - LAG(user_count) OVER (ORDER BY month) as growth
        FROM monthly_stats
        ORDER BY month
    """))
    
    print("Monthly user growth:")
    for row in result:
        growth = row.growth or 0
        print(f"  {row.month.strftime('%Y-%m')}: {row.user_count} users (+{growth})")
```

# === MySQL Integration Example ===

mysql_url = mattstash.get_db_url(
    "mysql-analytics",
    database="analytics_db",
    driver="pymysql"  # or "mysqldb"
)

mysql_engine = create_engine(mysql_url)

# === Raw Database Connections ===

# Direct psycopg2 connection
def get_postgres_connection():
    cred = mattstash.get("postgres-production", show_password=True)
    host, port = cred.url.split(':')
    
    return psycopg2.connect(
        host=host,
        port=int(port),
        user=cred.username,
        password=cred.password,
        database="myapp_production"
    )

# Usage
with get_postgres_connection() as conn:
    with conn.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        print(f"Total users: {user_count}")

# Redis connection
def get_redis_connection():
    cred = mattstash.get("redis-cache", show_password=True)
    host, port = cred.url.split(':')
    
    return redis.Redis(
        host=host,
        port=int(port),
        username=cred.username,
        password=cred.password,
        decode_responses=True
    )

# Usage
redis_client = get_redis_connection()
redis_client.set("test_key", "test_value", ex=300)  # 5 minute expiry
value = redis_client.get("test_key")
print(f"Retrieved from Redis: {value}")

# MongoDB connection
def get_mongodb_connection():
    cred = mattstash.get("mongodb-documents", show_password=True)
    
    # MongoDB URL already includes multiple hosts
    connection_string = cred.url.replace(
        "mongodb://",
        f"mongodb://{cred.username}:{cred.password}@"
    )
    
    return pymongo.MongoClient(connection_string)

# Usage
mongo_client = get_mongodb_connection()
db = mongo_client["document_store"]
collection = db["documents"]

# Insert document
doc_id = collection.insert_one({
    "title": "Example Document",
    "content": "This is a test document",
    "created_at": "2024-01-15T10:30:00Z"
}).inserted_id

print(f"Inserted document with ID: {doc_id}")
```

### Database Connection Pooling and Management

```python
import mattstash
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool
from contextlib import contextmanager
import threading
import logging

class DatabaseManager:
    """Thread-safe database connection manager."""
    
    def __init__(self):
        self._engines = {}
        self._lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
    
    def get_engine(self, credential_name, database_name, **engine_kwargs):
        """Get or create a SQLAlchemy engine for the given credentials."""
        engine_key = f"{credential_name}:{database_name}"
        
        if engine_key not in self._engines:
            with self._lock:
                if engine_key not in self._engines:  # Double-check pattern
                    self._engines[engine_key] = self._create_engine(
                        credential_name, database_name, **engine_kwargs
                    )
        
        return self._engines[engine_key]
    
    def _create_engine(self, credential_name, database_name, **engine_kwargs):
        """Create a new SQLAlchemy engine."""
        db_url = mattstash.get_db_url(
            credential_name,
            database=database_name,
            mask_password=False
        )
        
        # Default engine configuration
        default_config = {
            'poolclass': QueuePool,
            'pool_size': 5,
            'max_overflow': 10,
            'pool_timeout': 30,
            'pool_recycle': 3600,
            'echo': False
        }
        default_config.update(engine_kwargs)
        
        engine = create_engine(db_url, **default_config)
        self.logger.info(f"Created database engine for {credential_name}:{database_name}")
        return engine
    
    @contextmanager
    def get_connection(self, credential_name, database_name):
        """Context manager for database connections."""
        engine = self.get_engine(credential_name, database_name)
        connection = engine.connect()
        try:
            yield connection
        finally:
            connection.close()
    
    def health_check(self, credential_name, database_name):
        """Check if database connection is healthy."""
        try:
            with self.get_connection(credential_name, database_name) as conn:
                conn.execute("SELECT 1")
            return True
        except Exception as e:
            self.logger.error(f"Health check failed for {credential_name}: {e}")
            return False

# Usage
db_manager = DatabaseManager()

# Application startup - test all database connections
databases = [
    ("postgres-production", "myapp_production"),
    ("mysql-analytics", "analytics_db"),
]

for cred_name, db_name in databases:
    if db_manager.health_check(cred_name, db_name):
        print(f"✅ {cred_name} connection OK")
    else:
        print(f"❌ {cred_name} connection failed")

# Runtime usage
with db_manager.get_connection("postgres-production", "myapp_production") as conn:
    result = conn.execute("SELECT COUNT(*) FROM orders WHERE status = 'pending'")
    pending_orders = result.scalar()
    print(f"Pending orders: {pending_orders}")
```

## Advanced Usage Patterns

### Configuration Management

```python
import mattstash
from dataclasses import dataclass
from typing import Optional
import os

@dataclass
class AppConfig:
    """Application configuration loaded from MattStash."""
    
    # Database connections
    primary_db_url: str
    analytics_db_url: str
    cache_connection: object
    
    # API keys
    stripe_key: str
    sendgrid_key: str
    slack_webhook: str
    
    # S3 clients
    s3_primary: object
    s3_backup: object
    
    @classmethod
    def load(cls, environment="production"):
        """Load configuration for the specified environment."""
        
        # Database URLs
        primary_db_url = mattstash.get_db_url(
            f"postgres-{environment}",
            database=f"myapp_{environment}",
            mask_password=False
        )
        
        analytics_db_url = mattstash.get_db_url(
            f"mysql-analytics-{environment}",
            database=f"analytics_{environment}",
            mask_password=False
        )
        
        # Cache connection
        cache_cred = mattstash.get(f"redis-{environment}", show_password=True)
        host, port = cache_cred.url.split(':')
        cache_connection = redis.Redis(
            host=host,
            port=int(port),
            password=cache_cred.password,
            decode_responses=True
        )
        
        # API keys
        stripe_key = mattstash.get(f"stripe-{environment}", show_password=True)["value"]
        sendgrid_key = mattstash.get(f"sendgrid-{environment}", show_password=True)["value"]
        slack_webhook = mattstash.get(f"slack-webhook-{environment}", show_password=True)["value"]
        
        # S3 clients
        s3_primary = mattstash.get_s3_client(
            f"s3-primary-{environment}",
            region="us-west-2"
        )
        
        s3_backup = mattstash.get_s3_client(
            f"s3-backup-{environment}",
            region="us-east-1"
        )
        
        return cls(
            primary_db_url=primary_db_url,
            analytics_db_url=analytics_db_url,
            cache_connection=cache_connection,
            stripe_key=stripe_key,
            sendgrid_key=sendgrid_key,
            slack_webhook=slack_webhook,
            s3_primary=s3_primary,
            s3_backup=s3_backup
        )

# Application startup
environment = os.getenv("APP_ENVIRONMENT", "development")
config = AppConfig.load(environment)

# Use throughout application
primary_engine = create_engine(config.primary_db_url)
analytics_engine = create_engine(config.analytics_db_url)

# Cache operations
config.cache_connection.set("app_status", "running")

# S3 operations
config.s3_primary.upload_file("report.pdf", "reports", "monthly-report.pdf")
```

### Credential Rotation

```python
import mattstash
from datetime import datetime, timedelta
import logging

class CredentialRotator:
    """Handle credential rotation with versioning."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def rotate_api_key(self, credential_name, new_key, rotation_delay_hours=24):
        """Rotate an API key with gradual rollout."""
        
        # Store new credential as next version
        current_versions = mattstash.list_versions(credential_name)
        next_version = len(current_versions) + 1
        
        mattstash.put(
            credential_name,
            value=new_key,
            version=next_version,
            notes=f"Rotated on {datetime.now().isoformat()}"
        )
        
        self.logger.info(f"Stored new key for {credential_name} as version {next_version}")
        
        # Schedule old key deprecation
        self._schedule_deprecation(credential_name, next_version - 1, rotation_delay_hours)
    
    def rotate_database_password(self, credential_name, new_password):
        """Rotate database password maintaining connection info."""
        
        # Get current credential
        current_cred = mattstash.get(credential_name, show_password=True)
        
        # Store new version with updated password
        mattstash.put(
            credential_name,
            username=current_cred.username,
            password=new_password,
            url=current_cred.url,
            notes=f"Password rotated on {datetime.now().isoformat()}",
            tags=current_cred.tags
        )
        
        self.logger.info(f"Rotated password for {credential_name}")
    
    def _schedule_deprecation(self, credential_name, old_version, delay_hours):
        """Schedule deprecation of old credential version."""
        # This would integrate with your task scheduler (Celery, etc.)
        self.logger.info(
            f"Old version {old_version} of {credential_name} "
            f"should be deprecated in {delay_hours} hours"
        )

# Usage
rotator = CredentialRotator()

# Rotate API key
rotator.rotate_api_key("github-token", "ghp_newtoken123456789")

# Rotate database password
rotator.rotate_database_password("postgres-production", "new_secure_password_456")
```

## Error Handling

```python
import mattstash
from mattstash.models.exceptions import CredentialNotFoundError, DatabaseError
import logging

def safe_get_s3_client(credential_name, **kwargs):
    """Safely get S3 client with comprehensive error handling."""
    try:
        return mattstash.get_s3_client(credential_name, **kwargs)
    except CredentialNotFoundError:
        logging.error(f"S3 credential '{credential_name}' not found")
        raise
    except ImportError:
        logging.error("boto3 not installed - install with: pip install boto3")
        raise
    except Exception as e:
        logging.error(f"Failed to create S3 client: {e}")
        raise

def safe_get_db_connection(credential_name, database_name):
    """Safely get database connection with fallback."""
    try:
        db_url = mattstash.get_db_url(
            credential_name,
            database=database_name,
            mask_password=False
        )
        return create_engine(db_url)
    except CredentialNotFoundError:
        logging.warning(f"Database credential '{credential_name}' not found, using fallback")
        # Fallback to environment variables
        return create_engine(os.getenv("DATABASE_URL"))
    except DatabaseError as e:
        logging.error(f"Database connection failed: {e}")
        raise

def retry_with_credential_refresh(func, credential_name, max_retries=3):
    """Retry operation with credential refresh on failure."""
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            if attempt < max_retries - 1:
                logging.warning(f"Attempt {attempt + 1} failed: {e}, retrying...")
                # Could refresh credential here if needed
                continue
            raise

# Usage
try:
    s3_client = safe_get_s3_client("aws-production", region="us-west-2")
    
    def upload_operation():
        return s3_client.upload_file("data.csv", "my-bucket", "data.csv")
    
    retry_with_credential_refresh(upload_operation, "aws-production")
    
except Exception as e:
    logging.error(f"S3 operation failed after retries: {e}")
```

## Best Practices

### 1. Environment Separation

```python
import mattstash
import os

def get_credential_name(service, environment=None):
    """Generate environment-specific credential names."""
    env = environment or os.getenv("APP_ENVIRONMENT", "development")
    return f"{service}-{env}"

# Usage
production_db = mattstash.get_db_url(
    get_credential_name("postgres", "production"),
    database="myapp"
)

staging_s3 = mattstash.get_s3_client(
    get_credential_name("s3", "staging")
)
```

### 2. Credential Caching

```python
import mattstash
from functools import lru_cache
import threading

class CredentialCache:
    """Thread-safe credential caching."""
    
    def __init__(self):
        self._cache = {}
        self._lock = threading.Lock()
    
    @lru_cache(maxsize=128)
    def get_credential(self, name, show_password=False):
        return mattstash.get(name, show_password=show_password)
    
    def invalidate(self, name=None):
        """Invalidate cache for specific credential or all."""
        if name:
            # Remove from LRU cache - this is a simplified example
            pass
        else:
            self.get_credential.cache_clear()

# Global cache instance
credential_cache = CredentialCache()
```

### 3. Health Monitoring

```python
import mattstash
from datetime import datetime
import asyncio

async def monitor_service_health():
    """Monitor health of all stored services."""
    health_status = {}
    
    # Get all credentials
    credentials = mattstash.list_creds()
    
    for cred in credentials:
        if "s3" in cred.tags:
            health_status[cred.credential_name] = await check_s3_health(cred.credential_name)
        elif "database" in cred.tags:
            health_status[cred.credential_name] = await check_db_health(cred.credential_name)
    
    return health_status

async def check_s3_health(credential_name):
    """Check S3 service health."""
    try:
        s3_client = mattstash.get_s3_client(credential_name, verbose=False)
        await asyncio.get_event_loop().run_in_executor(
            None, s3_client.list_buckets
        )
        return {"status": "healthy", "checked_at": datetime.now().isoformat()}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e), "checked_at": datetime.now().isoformat()}

async def check_db_health(credential_name):
    """Check database health."""
    try:
        # This would use your database health check logic
        return {"status": "healthy", "checked_at": datetime.now().isoformat()}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e), "checked_at": datetime.now().isoformat()}

# Usage
health_report = asyncio.run(monitor_service_health())
for service, status in health_report.items():
    print(f"{service}: {status['status']}")
```

This comprehensive guide shows how MattStash integrates seamlessly with your Python applications, providing secure credential storage with convenient access to ready-to-use service clients for both S3 and database operations.
