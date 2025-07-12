from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from datetime import datetime, timedelta
import logging

from core.database import get_database_session
from models.database import Target, Subdomain, Vulnerability, Scan, TechStack, Notification
from api.schemas import DashboardResponse, DashboardStats, VulnerabilitySummary, TechnologySummary, RecentActivity

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/", response_model=DashboardResponse)
async def get_dashboard(
    db: AsyncSession = Depends(get_database_session)
):
    """Get dashboard overview statistics"""
    try:
        # Get basic stats
        total_targets = await db.scalar(select(func.count(Target.id)))
        active_targets = await db.scalar(select(func.count(Target.id)).where(Target.is_active == True))
        
        total_subdomains = await db.scalar(select(func.count(Subdomain.id)))
        active_subdomains = await db.scalar(select(func.count(Subdomain.id)).where(Subdomain.is_active == True))
        
        total_vulnerabilities = await db.scalar(
            select(func.count(Vulnerability.id)).where(Vulnerability.is_false_positive == False)
        )
        
        critical_vulnerabilities = await db.scalar(
            select(func.count(Vulnerability.id)).where(
                and_(
                    Vulnerability.severity == "critical",
                    Vulnerability.is_false_positive == False
                )
            )
        )
        
        high_vulnerabilities = await db.scalar(
            select(func.count(Vulnerability.id)).where(
                and_(
                    Vulnerability.severity == "high",
                    Vulnerability.is_false_positive == False
                )
            )
        )
        
        running_scans = await db.scalar(
            select(func.count(Scan.id)).where(Scan.status == "running")
        )
        
        # Get today's scan stats
        today = datetime.utcnow().date()
        completed_scans_today = await db.scalar(
            select(func.count(Scan.id)).where(
                and_(
                    Scan.status == "completed",
                    func.date(Scan.completed_at) == today
                )
            )
        )
        
        failed_scans_today = await db.scalar(
            select(func.count(Scan.id)).where(
                and_(
                    Scan.status == "failed",
                    func.date(Scan.completed_at) == today
                )
            )
        )
        
        # Get vulnerability breakdown
        vuln_breakdown_query = await db.execute(
            select(
                Vulnerability.severity,
                func.count(Vulnerability.id).label('count')
            ).where(
                Vulnerability.is_false_positive == False
            ).group_by(Vulnerability.severity)
        )
        
        vuln_breakdown = []
        total_vulns = total_vulnerabilities or 1  # Avoid division by zero
        for severity, count in vuln_breakdown_query:
            percentage = (count / total_vulns) * 100
            vuln_breakdown.append(VulnerabilitySummary(
                severity=severity,
                count=count,
                percentage=round(percentage, 2)
            ))
        
        # Get top technologies
        tech_query = await db.execute(
            select(
                TechStack.technology,
                TechStack.category,
                func.count(TechStack.id).label('count')
            ).group_by(TechStack.technology, TechStack.category)
            .order_by(func.count(TechStack.id).desc())
            .limit(10)
        )
        
        top_technologies = []
        for tech, category, count in tech_query:
            top_technologies.append(TechnologySummary(
                technology=tech,
                category=category or "unknown",
                count=count
            ))
        
        # Get recent activities
        recent_activities = []
        
        # Recent vulnerabilities
        recent_vulns = await db.execute(
            select(Vulnerability, Target.name).join(Subdomain).join(Target).where(
                Vulnerability.created_at >= datetime.utcnow() - timedelta(days=7)
            ).order_by(Vulnerability.created_at.desc()).limit(10)
        )
        
        for vuln, target_name in recent_vulns:
            recent_activities.append(RecentActivity(
                type="vulnerability",
                target_name=target_name,
                message=f"New {vuln.severity} vulnerability: {vuln.title}",
                timestamp=vuln.created_at,
                severity=vuln.severity
            ))
        
        # Recent scans
        recent_scans = await db.execute(
            select(Scan, Target.name).join(Target).where(
                Scan.completed_at >= datetime.utcnow() - timedelta(days=7)
            ).order_by(Scan.completed_at.desc()).limit(10)
        )
        
        for scan, target_name in recent_scans:
            recent_activities.append(RecentActivity(
                type="scan",
                target_name=target_name,
                message=f"Completed {scan.scan_type} scan",
                timestamp=scan.completed_at,
                severity=None
            ))
        
        # Sort activities by timestamp
        recent_activities.sort(key=lambda x: x.timestamp, reverse=True)
        recent_activities = recent_activities[:20]  # Limit to 20 most recent
        
        stats = DashboardStats(
            total_targets=total_targets or 0,
            active_targets=active_targets or 0,
            total_subdomains=total_subdomains or 0,
            active_subdomains=active_subdomains or 0,
            total_vulnerabilities=total_vulnerabilities or 0,
            critical_vulnerabilities=critical_vulnerabilities or 0,
            high_vulnerabilities=high_vulnerabilities or 0,
            running_scans=running_scans or 0,
            completed_scans_today=completed_scans_today or 0,
            failed_scans_today=failed_scans_today or 0
        )
        
        return DashboardResponse(
            stats=stats,
            vulnerability_breakdown=vuln_breakdown,
            top_technologies=top_technologies,
            recent_activities=recent_activities
        )
        
    except Exception as e:
        logger.error(f"Error getting dashboard data: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve dashboard data")

@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_database_session)
):
    """Get quick stats for widgets"""
    try:
        # Get counts for the last 30 days
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        
        new_targets = await db.scalar(
            select(func.count(Target.id)).where(Target.created_at >= thirty_days_ago)
        )
        
        new_subdomains = await db.scalar(
            select(func.count(Subdomain.id)).where(Subdomain.created_at >= thirty_days_ago)
        )
        
        new_vulnerabilities = await db.scalar(
            select(func.count(Vulnerability.id)).where(
                and_(
                    Vulnerability.created_at >= thirty_days_ago,
                    Vulnerability.is_false_positive == False
                )
            )
        )
        
        completed_scans = await db.scalar(
            select(func.count(Scan.id)).where(
                and_(
                    Scan.completed_at >= thirty_days_ago,
                    Scan.status == "completed"
                )
            )
        )
        
        return {
            "new_targets_30d": new_targets or 0,
            "new_subdomains_30d": new_subdomains or 0,
            "new_vulnerabilities_30d": new_vulnerabilities or 0,
            "completed_scans_30d": completed_scans or 0
        }
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve stats")

@router.get("/notifications")
async def get_notifications(
    db: AsyncSession = Depends(get_database_session)
):
    """Get recent notifications"""
    try:
        notifications = await db.execute(
            select(Notification).where(
                Notification.created_at >= datetime.utcnow() - timedelta(days=7)
            ).order_by(Notification.created_at.desc()).limit(50)
        )
        
        return notifications.scalars().all()
        
    except Exception as e:
        logger.error(f"Error getting notifications: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve notifications")