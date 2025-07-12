from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from models.database import Base
from core.config import settings
import logging

logger = logging.getLogger(__name__)

# Create async engine
engine = create_async_engine(
    settings.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://"),
    echo=settings.DEBUG,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

# Create async session factory
AsyncSessionLocal = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

async def create_tables():
    """Create database tables"""
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Error creating database tables: {e}")
        raise

async def get_database_session() -> AsyncSession:
    """Dependency to get database session"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            raise
        finally:
            await session.close()

# Synchronous session for Celery tasks
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker as sync_sessionmaker

sync_engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

SyncSessionLocal = sync_sessionmaker(bind=sync_engine)

def get_sync_session():
    """Get synchronous session for Celery tasks"""
    db = SyncSessionLocal()
    try:
        yield db
    except Exception as e:
        db.rollback()
        raise
    finally:
        db.close()