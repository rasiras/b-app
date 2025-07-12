from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy import select, func, and_, or_
from typing import List, Optional
from datetime import datetime, timedelta
import logging

from core.database import get_database_session
from models.database import Target, Subdomain, Vulnerability, Scan
from api.schemas import (
    TargetCreate, TargetUpdate, TargetResponse, ScanCreate, ScanResponse,
    PaginationParams, PaginatedResponse, BulkScanRequest, BulkScanResponse
)
from scanners.tasks import run_subdomain_scan, run_port_scan, run_vulnerability_scan, run_full_scan

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/", response_model=PaginatedResponse)
async def get_targets(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None),
    tags: Optional[List[str]] = Query(None),
    is_active: Optional[bool] = Query(None),
    db: AsyncSession = Depends(get_database_session)
):
    """Get paginated list of targets with optional filtering"""
    try:
        # Build query
        query = select(Target)
        
        # Apply filters
        if search:
            query = query.where(
                or_(
                    Target.name.ilike(f"%{search}%"),
                    Target.base_domain.ilike(f"%{search}%"),
                    Target.description.ilike(f"%{search}%")
                )
            )
        
        if tags:
            # Filter by tags (JSON array contains any of the specified tags)
            for tag in tags:
                query = query.where(Target.tags.op('?')(tag))
        
        if is_active is not None:
            query = query.where(Target.is_active == is_active)
        
        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total = await db.scalar(count_query)
        
        # Apply pagination
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page)
        
        # Execute query
        result = await db.execute(query)
        targets = result.scalars().all()
        
        # Enhance with additional data
        target_responses = []
        for target in targets:
            # Get subdomain count
            subdomain_count = await db.scalar(
                select(func.count(Subdomain.id)).where(
                    Subdomain.target_id == target.id,
                    Subdomain.is_active == True
                )
            )
            
            # Get vulnerability count
            vulnerability_count = await db.scalar(
                select(func.count(Vulnerability.id)).join(Subdomain).where(
                    Subdomain.target_id == target.id,
                    Vulnerability.is_false_positive == False
                )
            )
            
            # Get last scan
            last_scan_result = await db.execute(
                select(Scan.created_at).where(
                    Scan.target_id == target.id
                ).order_by(Scan.created_at.desc()).limit(1)
            )
            last_scan = last_scan_result.scalar()
            
            target_response = TargetResponse(
                id=target.id,
                name=target.name,
                base_domain=target.base_domain,
                description=target.description,
                tags=target.tags,
                scope=target.scope,
                notes=target.notes,
                is_active=target.is_active,
                created_at=target.created_at,
                updated_at=target.updated_at,
                subdomain_count=subdomain_count or 0,
                vulnerability_count=vulnerability_count or 0,
                last_scan=last_scan
            )
            target_responses.append(target_response)
        
        # Calculate pagination info
        pages = (total + per_page - 1) // per_page
        has_next = page < pages
        has_prev = page > 1
        
        return PaginatedResponse(
            items=target_responses,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages,
            has_next=has_next,
            has_prev=has_prev
        )
        
    except Exception as e:
        logger.error(f"Error getting targets: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve targets")

@router.post("/", response_model=TargetResponse)
async def create_target(
    target: TargetCreate,
    db: AsyncSession = Depends(get_database_session)
):
    """Create a new target"""
    try:
        # Check if domain already exists
        existing = await db.scalar(
            select(Target).where(Target.base_domain == target.base_domain)
        )
        if existing:
            raise HTTPException(
                status_code=400,
                detail=f"Target with domain {target.base_domain} already exists"
            )
        
        # Create new target
        db_target = Target(**target.dict())
        db.add(db_target)
        await db.commit()
        await db.refresh(db_target)
        
        return TargetResponse(
            id=db_target.id,
            name=db_target.name,
            base_domain=db_target.base_domain,
            description=db_target.description,
            tags=db_target.tags,
            scope=db_target.scope,
            notes=db_target.notes,
            is_active=db_target.is_active,
            created_at=db_target.created_at,
            updated_at=db_target.updated_at,
            subdomain_count=0,
            vulnerability_count=0,
            last_scan=None
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating target: {e}")
        raise HTTPException(status_code=500, detail="Failed to create target")

@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(
    target_id: int,
    db: AsyncSession = Depends(get_database_session)
):
    """Get a specific target by ID"""
    try:
        target = await db.scalar(
            select(Target).where(Target.id == target_id)
        )
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        
        # Get additional data
        subdomain_count = await db.scalar(
            select(func.count(Subdomain.id)).where(
                Subdomain.target_id == target_id,
                Subdomain.is_active == True
            )
        )
        
        vulnerability_count = await db.scalar(
            select(func.count(Vulnerability.id)).join(Subdomain).where(
                Subdomain.target_id == target_id,
                Vulnerability.is_false_positive == False
            )
        )
        
        last_scan_result = await db.execute(
            select(Scan.created_at).where(
                Scan.target_id == target_id
            ).order_by(Scan.created_at.desc()).limit(1)
        )
        last_scan = last_scan_result.scalar()
        
        return TargetResponse(
            id=target.id,
            name=target.name,
            base_domain=target.base_domain,
            description=target.description,
            tags=target.tags,
            scope=target.scope,
            notes=target.notes,
            is_active=target.is_active,
            created_at=target.created_at,
            updated_at=target.updated_at,
            subdomain_count=subdomain_count or 0,
            vulnerability_count=vulnerability_count or 0,
            last_scan=last_scan
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting target {target_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve target")

@router.put("/{target_id}", response_model=TargetResponse)
async def update_target(
    target_id: int,
    target_update: TargetUpdate,
    db: AsyncSession = Depends(get_database_session)
):
    """Update a target"""
    try:
        target = await db.scalar(
            select(Target).where(Target.id == target_id)
        )
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        
        # Check if new domain conflicts with existing one
        if target_update.base_domain and target_update.base_domain != target.base_domain:
            existing = await db.scalar(
                select(Target).where(Target.base_domain == target_update.base_domain)
            )
            if existing:
                raise HTTPException(
                    status_code=400,
                    detail=f"Target with domain {target_update.base_domain} already exists"
                )
        
        # Update fields
        update_data = target_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(target, field, value)
        
        target.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(target)
        
        # Get additional data
        subdomain_count = await db.scalar(
            select(func.count(Subdomain.id)).where(
                Subdomain.target_id == target_id,
                Subdomain.is_active == True
            )
        )
        
        vulnerability_count = await db.scalar(
            select(func.count(Vulnerability.id)).join(Subdomain).where(
                Subdomain.target_id == target_id,
                Vulnerability.is_false_positive == False
            )
        )
        
        last_scan_result = await db.execute(
            select(Scan.created_at).where(
                Scan.target_id == target_id
            ).order_by(Scan.created_at.desc()).limit(1)
        )
        last_scan = last_scan_result.scalar()
        
        return TargetResponse(
            id=target.id,
            name=target.name,
            base_domain=target.base_domain,
            description=target.description,
            tags=target.tags,
            scope=target.scope,
            notes=target.notes,
            is_active=target.is_active,
            created_at=target.created_at,
            updated_at=target.updated_at,
            subdomain_count=subdomain_count or 0,
            vulnerability_count=vulnerability_count or 0,
            last_scan=last_scan
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating target {target_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update target")

@router.delete("/{target_id}")
async def delete_target(
    target_id: int,
    db: AsyncSession = Depends(get_database_session)
):
    """Delete a target and all associated data"""
    try:
        target = await db.scalar(
            select(Target).where(Target.id == target_id)
        )
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        
        await db.delete(target)
        await db.commit()
        
        return {"message": "Target deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting target {target_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete target")

@router.post("/{target_id}/scan", response_model=ScanResponse)
async def start_scan(
    target_id: int,
    scan_request: ScanCreate,
    db: AsyncSession = Depends(get_database_session)
):
    """Start a scan for a target"""
    try:
        # Check if target exists
        target = await db.scalar(
            select(Target).where(Target.id == target_id)
        )
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        
        if not target.is_active:
            raise HTTPException(status_code=400, detail="Cannot scan inactive target")
        
        # Create scan record
        scan = Scan(
            target_id=target_id,
            scan_type=scan_request.scan_type,
            status="pending",
            scan_config=scan_request.scan_config
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        
        # Launch appropriate scan task
        if scan_request.scan_type == "subdomain":
            run_subdomain_scan.delay(target_id, scan.id, scan_request.scan_config)
        elif scan_request.scan_type == "port":
            run_port_scan.delay(target_id, scan.id, scan_request.scan_config)
        elif scan_request.scan_type == "vuln":
            run_vulnerability_scan.delay(target_id, scan.id, scan_request.scan_config)
        elif scan_request.scan_type == "full":
            run_full_scan.delay(target_id, scan.id, scan_request.scan_config)
        else:
            raise HTTPException(status_code=400, detail="Invalid scan type")
        
        return ScanResponse(
            id=scan.id,
            target_id=scan.target_id,
            scan_type=scan.scan_type,
            status=scan.status,
            scan_config=scan.scan_config,
            results=scan.results,
            created_at=scan.created_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting scan for target {target_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to start scan")

@router.post("/bulk-scan", response_model=BulkScanResponse)
async def bulk_scan(
    bulk_request: BulkScanRequest,
    db: AsyncSession = Depends(get_database_session)
):
    """Start scans for multiple targets"""
    try:
        # Validate targets
        targets = await db.execute(
            select(Target).where(
                Target.id.in_(bulk_request.target_ids),
                Target.is_active == True
            )
        )
        valid_targets = targets.scalars().all()
        valid_target_ids = [t.id for t in valid_targets]
        failed_targets = [tid for tid in bulk_request.target_ids if tid not in valid_target_ids]
        
        scan_ids = []
        
        # Create scan records and launch tasks
        for target_id in valid_target_ids:
            scan = Scan(
                target_id=target_id,
                scan_type=bulk_request.scan_type,
                status="pending",
                scan_config=bulk_request.scan_config
            )
            db.add(scan)
            await db.flush()  # Get the ID
            scan_ids.append(scan.id)
            
            # Launch appropriate scan task
            if bulk_request.scan_type == "subdomain":
                run_subdomain_scan.delay(target_id, scan.id, bulk_request.scan_config)
            elif bulk_request.scan_type == "port":
                run_port_scan.delay(target_id, scan.id, bulk_request.scan_config)
            elif bulk_request.scan_type == "vuln":
                run_vulnerability_scan.delay(target_id, scan.id, bulk_request.scan_config)
            elif bulk_request.scan_type == "full":
                run_full_scan.delay(target_id, scan.id, bulk_request.scan_config)
        
        await db.commit()
        
        return BulkScanResponse(
            success=True,
            scan_ids=scan_ids,
            failed_targets=failed_targets,
            message=f"Started {len(scan_ids)} scans, {len(failed_targets)} targets failed"
        )
        
    except Exception as e:
        logger.error(f"Error in bulk scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to start bulk scan")

@router.get("/{target_id}/subdomains")
async def get_target_subdomains(
    target_id: int,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    is_active: Optional[bool] = Query(None),
    db: AsyncSession = Depends(get_database_session)
):
    """Get subdomains for a target"""
    try:
        # Check if target exists
        target = await db.scalar(
            select(Target).where(Target.id == target_id)
        )
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        
        # Build query
        query = select(Subdomain).where(Subdomain.target_id == target_id)
        
        if is_active is not None:
            query = query.where(Subdomain.is_active == is_active)
        
        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total = await db.scalar(count_query)
        
        # Apply pagination
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page).order_by(Subdomain.created_at.desc())
        
        result = await db.execute(query)
        subdomains = result.scalars().all()
        
        # Calculate pagination info
        pages = (total + per_page - 1) // per_page
        has_next = page < pages
        has_prev = page > 1
        
        return PaginatedResponse(
            items=subdomains,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages,
            has_next=has_next,
            has_prev=has_prev
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting subdomains for target {target_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve subdomains")

@router.get("/{target_id}/vulnerabilities")
async def get_target_vulnerabilities(
    target_id: int,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    severity: Optional[List[str]] = Query(None),
    is_verified: Optional[bool] = Query(None),
    is_false_positive: Optional[bool] = Query(None),
    db: AsyncSession = Depends(get_database_session)
):
    """Get vulnerabilities for a target"""
    try:
        # Check if target exists
        target = await db.scalar(
            select(Target).where(Target.id == target_id)
        )
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        
        # Build query
        query = select(Vulnerability).join(Subdomain).where(Subdomain.target_id == target_id)
        
        if severity:
            query = query.where(Vulnerability.severity.in_(severity))
        
        if is_verified is not None:
            query = query.where(Vulnerability.is_verified == is_verified)
        
        if is_false_positive is not None:
            query = query.where(Vulnerability.is_false_positive == is_false_positive)
        
        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total = await db.scalar(count_query)
        
        # Apply pagination
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page).order_by(Vulnerability.created_at.desc())
        
        result = await db.execute(query)
        vulnerabilities = result.scalars().all()
        
        # Calculate pagination info
        pages = (total + per_page - 1) // per_page
        has_next = page < pages
        has_prev = page > 1
        
        return PaginatedResponse(
            items=vulnerabilities,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages,
            has_next=has_next,
            has_prev=has_prev
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting vulnerabilities for target {target_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve vulnerabilities")