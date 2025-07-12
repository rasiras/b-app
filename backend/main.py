from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
from core.database import create_tables, get_database_session
from core.config import settings
from api.targets import router as targets_router
from api.scans import router as scans_router
from api.dashboard import router as dashboard_router
from api.inventory import router as inventory_router
from api.auth import router as auth_router

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Bug Bounty Automation Platform")
    await create_tables()
    yield
    # Shutdown
    logger.info("Shutting down Bug Bounty Automation Platform")

app = FastAPI(
    title="Bug Bounty Automation Platform",
    description="A comprehensive platform for managing bug bounty automation",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "message": "Bug Bounty Automation Platform is running"}

# Include routers
app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
app.include_router(targets_router, prefix="/api/targets", tags=["Targets"])
app.include_router(scans_router, prefix="/api/scans", tags=["Scans"])
app.include_router(dashboard_router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(inventory_router, prefix="/api/inventory", tags=["Inventory"])

@app.get("/")
async def root():
    return {"message": "Bug Bounty Automation Platform API"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)