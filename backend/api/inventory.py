from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from typing import List, Optional
import logging

from core.database import get_database_session
from models.database import Target, Subdomain, Vulnerability, TechStack, Service
from api.schemas import SearchFilters, PaginatedResponse

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/search")
async def search_inventory(
    query: Optional[str] = Query(None),
    target_ids: Optional[List[int]] = Query(None),
    tags: Optional[List[str]] = Query(None),
    severity: Optional[List[str]] = Query(None),
    technology: Optional[List[str]] = Query(None),
    cve_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_database_session)
):
    """Search across all inventory items"""
    try:
        results = {
            "targets": [],
            "subdomains": [],
            "vulnerabilities": [],
            "technologies": []
        }
        
        # Search targets
        if query:
            target_query = select(Target).where(
                or_(
                    Target.name.ilike(f"%{query}%"),
                    Target.base_domain.ilike(f"%{query}%")
                )
            )
            if target_ids:
                target_query = target_query.where(Target.id.in_(target_ids))
            
            target_results = await db.execute(target_query.limit(20))
            results["targets"] = target_results.scalars().all()
        
        # Search subdomains
        if query:
            subdomain_query = select(Subdomain).where(
                Subdomain.subdomain.ilike(f"%{query}%")
            )
            if target_ids:
                subdomain_query = subdomain_query.where(Subdomain.target_id.in_(target_ids))
            
            subdomain_results = await db.execute(subdomain_query.limit(20))
            results["subdomains"] = subdomain_results.scalars().all()
        
        # Search vulnerabilities
        vuln_query = select(Vulnerability).join(Subdomain)
        conditions = []
        
        if query:
            conditions.append(
                or_(
                    Vulnerability.title.ilike(f"%{query}%"),
                    Vulnerability.description.ilike(f"%{query}%")
                )
            )
        
        if severity:
            conditions.append(Vulnerability.severity.in_(severity))
        
        if cve_id:
            conditions.append(Vulnerability.cve_id == cve_id)
        
        if target_ids:
            conditions.append(Subdomain.target_id.in_(target_ids))
        
        if conditions:
            vuln_query = vuln_query.where(and_(*conditions))
        
        vuln_results = await db.execute(vuln_query.limit(20))
        results["vulnerabilities"] = vuln_results.scalars().all()
        
        # Search technologies
        tech_query = select(TechStack).join(Subdomain)
        tech_conditions = []
        
        if query:
            tech_conditions.append(TechStack.technology.ilike(f"%{query}%"))
        
        if technology:
            tech_conditions.append(TechStack.technology.in_(technology))
        
        if target_ids:
            tech_conditions.append(Subdomain.target_id.in_(target_ids))
        
        if tech_conditions:
            tech_query = tech_query.where(and_(*tech_conditions))
        
        tech_results = await db.execute(tech_query.limit(20))
        results["technologies"] = tech_results.scalars().all()
        
        return results
        
    except Exception as e:
        logger.error(f"Error searching inventory: {e}")
        raise HTTPException(status_code=500, detail="Failed to search inventory")

@router.get("/technologies")
async def get_technologies(
    category: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_database_session)
):
    """Get technology inventory"""
    try:
        query = select(
            TechStack.technology,
            TechStack.category,
            func.count(TechStack.id).label('count')
        ).group_by(TechStack.technology, TechStack.category)
        
        if category:
            query = query.where(TechStack.category == category)
        
        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total = await db.scalar(count_query)
        
        # Apply pagination
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page).order_by(func.count(TechStack.id).desc())
        
        result = await db.execute(query)
        technologies = result.all()
        
        tech_list = []
        for tech, cat, count in technologies:
            tech_list.append({
                "technology": tech,
                "category": cat,
                "count": count
            })
        
        # Calculate pagination info
        pages = (total + per_page - 1) // per_page
        has_next = page < pages
        has_prev = page > 1
        
        return PaginatedResponse(
            items=tech_list,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages,
            has_next=has_next,
            has_prev=has_prev
        )
        
    except Exception as e:
        logger.error(f"Error getting technologies: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve technologies")

@router.get("/vulnerabilities")
async def get_vulnerabilities(
    severity: Optional[List[str]] = Query(None),
    is_verified: Optional[bool] = Query(None),
    is_false_positive: Optional[bool] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_database_session)
):
    """Get vulnerability inventory"""
    try:
        query = select(Vulnerability).join(Subdomain).join(Target)
        
        # Apply filters
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
        
    except Exception as e:
        logger.error(f"Error getting vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve vulnerabilities")

@router.get("/cve-matches")
async def get_cve_matches(
    cve_id: Optional[str] = Query(None),
    technology: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_database_session)
):
    """Get CVE matches for technologies"""
    try:
        # This would query the CVE database and match with tech stacks
        # For now, return a simple structure
        matches = []
        
        if cve_id:
            # Find tech stacks that might be affected by this CVE
            tech_query = select(TechStack, Subdomain, Target).join(Subdomain).join(Target)
            if technology:
                tech_query = tech_query.where(TechStack.technology.ilike(f"%{technology}%"))
            
            tech_results = await db.execute(tech_query)
            for tech, subdomain, target in tech_results:
                matches.append({
                    "cve_id": cve_id,
                    "technology": tech.technology,
                    "target_name": target.name,
                    "subdomain": subdomain.subdomain,
                    "confidence": tech.confidence
                })
        
        return {"matches": matches}
        
    except Exception as e:
        logger.error(f"Error getting CVE matches: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve CVE matches")