from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from typing import List, Optional
from datetime import datetime, timedelta
import logging

from core.database import get_database_session
from models.database import Scan, Target, ScanLog
from api.schemas import ScanResponse, ScanHistoryResponse, ScanHistoryItem, PaginatedResponse

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/", response_model=PaginatedResponse)
async def get_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None),
    scan_type: Optional[str] = Query(None),
    target_id: Optional[int] = Query(None),
    db: AsyncSession = Depends(get_database_session)
):
    """Get paginated list of scans"""
    try:
        # Build query
        query = select(Scan).join(Target)
        
        # Apply filters
        if status:
            query = query.where(Scan.status == status)
        
        if scan_type:
            query = query.where(Scan.scan_type == scan_type)
        
        if target_id:
            query = query.where(Scan.target_id == target_id)
        
        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total = await db.scalar(count_query)
        
        # Apply pagination
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page).order_by(Scan.created_at.desc())
        
        # Execute query
        result = await db.execute(query)
        scans = result.scalars().all()
        
        # Convert to response format
        scan_items = []
        for scan in scans:
            target = await db.scalar(select(Target.name).where(Target.id == scan.target_id))
            
            duration = None
            if scan.started_at and scan.completed_at:
                duration = int((scan.completed_at - scan.started_at).total_seconds())
            
            scan_items.append(ScanHistoryItem(
                id=scan.id,
                scan_type=scan.scan_type,
                status=scan.status,
                target_name=target or "Unknown",
                started_at=scan.started_at,
                completed_at=scan.completed_at,
                duration=duration,
                results_summary=scan.results
            ))
        
        # Calculate pagination info
        pages = (total + per_page - 1) // per_page
        has_next = page < pages
        has_prev = page > 1
        
        return PaginatedResponse(
            items=scan_items,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages,
            has_next=has_next,
            has_prev=has_prev
        )
        
    except Exception as e:
        logger.error(f"Error getting scans: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve scans")

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_database_session)
):
    """Get a specific scan by ID"""
    try:
        scan = await db.scalar(select(Scan).where(Scan.id == scan_id))
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return ScanResponse(
            id=scan.id,
            target_id=scan.target_id,
            scan_type=scan.scan_type,
            status=scan.status,
            scan_config=scan.scan_config,
            results=scan.results,
            error_message=scan.error_message,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            created_at=scan.created_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve scan")

@router.get("/{scan_id}/logs")
async def get_scan_logs(
    scan_id: int,
    db: AsyncSession = Depends(get_database_session)
):
    """Get logs for a specific scan"""
    try:
        # Check if scan exists
        scan = await db.scalar(select(Scan).where(Scan.id == scan_id))
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get logs
        logs = await db.execute(
            select(ScanLog).where(ScanLog.scan_id == scan_id).order_by(ScanLog.created_at.asc())
        )
        
        return logs.scalars().all()
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan logs for {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve scan logs")

@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_database_session)
):
    """Delete a scan record"""
    try:
        scan = await db.scalar(select(Scan).where(Scan.id == scan_id))
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Only allow deletion of completed or failed scans
        if scan.status in ["running", "pending"]:
            raise HTTPException(status_code=400, detail="Cannot delete running or pending scans")
        
        await db.delete(scan)
        await db.commit()
        
        return {"message": "Scan deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete scan")