from celery import current_task
from core.celery_app import celery_app
from core.database import get_sync_session
from models.database import (
    Target, Scan, ScheduledScan, CVEWatch, Notification, 
    Subdomain, Vulnerability, TechStack
)
from scanners.tasks import run_subdomain_scan, run_port_scan, run_vulnerability_scan, run_full_scan
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_
from typing import Dict, List, Any
import logging
from datetime import datetime, timedelta
import requests
import json

logger = logging.getLogger(__name__)

@celery_app.task(bind=True, name="scheduler.tasks.check_scheduled_scans")
def check_scheduled_scans(self):
    """Check for scheduled scans that need to be executed"""
    try:
        current_time = datetime.utcnow()
        
        with next(get_sync_session()) as db:
            # Get scheduled scans that are due
            scheduled_scans = db.query(ScheduledScan).filter(
                ScheduledScan.is_active == True,
                ScheduledScan.next_run <= current_time
            ).all()
            
            logger.info(f"Found {len(scheduled_scans)} scheduled scans to execute")
            
            for scheduled_scan in scheduled_scans:
                try:
                    # Create new scan record
                    scan = Scan(
                        target_id=scheduled_scan.target_id,
                        scan_type=scheduled_scan.scan_type,
                        status="pending",
                        scan_config=scheduled_scan.scan_config
                    )
                    db.add(scan)
                    db.flush()  # Get the scan ID
                    
                    # Launch appropriate scan task
                    if scheduled_scan.scan_type == "subdomain":
                        run_subdomain_scan.delay(
                            scheduled_scan.target_id, 
                            scan.id, 
                            scheduled_scan.scan_config
                        )
                    elif scheduled_scan.scan_type == "port":
                        run_port_scan.delay(
                            scheduled_scan.target_id, 
                            scan.id, 
                            scheduled_scan.scan_config
                        )
                    elif scheduled_scan.scan_type == "vuln":
                        run_vulnerability_scan.delay(
                            scheduled_scan.target_id, 
                            scan.id, 
                            scheduled_scan.scan_config
                        )
                    elif scheduled_scan.scan_type == "full":
                        run_full_scan.delay(
                            scheduled_scan.target_id, 
                            scan.id, 
                            scheduled_scan.scan_config
                        )
                    
                    # Update scheduled scan
                    scheduled_scan.last_run = current_time
                    scheduled_scan.next_run = calculate_next_run(
                        scheduled_scan.schedule_type,
                        scheduled_scan.schedule_config
                    )
                    
                    logger.info(f"Launched scheduled scan {scan.id} for target {scheduled_scan.target_id}")
                    
                except Exception as e:
                    logger.error(f"Failed to launch scheduled scan {scheduled_scan.id}: {e}")
                    continue
            
            db.commit()
            return {"success": True, "scans_launched": len(scheduled_scans)}
            
    except Exception as e:
        logger.error(f"Error checking scheduled scans: {e}")
        return {"success": False, "error": str(e)}

def calculate_next_run(schedule_type: str, schedule_config: Dict[str, Any]) -> datetime:
    """Calculate next run time for scheduled scan"""
    current_time = datetime.utcnow()
    
    if schedule_type == "daily":
        # Run daily at specified hour
        hour = schedule_config.get("hour", 2)
        minute = schedule_config.get("minute", 0)
        
        next_run = current_time.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if next_run <= current_time:
            next_run += timedelta(days=1)
        
        return next_run
    
    elif schedule_type == "weekly":
        # Run weekly on specified day and time
        day_of_week = schedule_config.get("day_of_week", 0)  # 0 = Monday
        hour = schedule_config.get("hour", 2)
        minute = schedule_config.get("minute", 0)
        
        days_ahead = day_of_week - current_time.weekday()
        if days_ahead <= 0:  # Target day already happened this week
            days_ahead += 7
        
        next_run = current_time + timedelta(days=days_ahead)
        next_run = next_run.replace(hour=hour, minute=minute, second=0, microsecond=0)
        
        return next_run
    
    elif schedule_type == "monthly":
        # Run monthly on specified day
        day_of_month = schedule_config.get("day_of_month", 1)
        hour = schedule_config.get("hour", 2)
        minute = schedule_config.get("minute", 0)
        
        # Calculate next month
        if current_time.month == 12:
            next_month = current_time.replace(year=current_time.year + 1, month=1)
        else:
            next_month = current_time.replace(month=current_time.month + 1)
        
        try:
            next_run = next_month.replace(
                day=day_of_month, 
                hour=hour, 
                minute=minute, 
                second=0, 
                microsecond=0
            )
        except ValueError:
            # Handle case where day doesn't exist in next month (e.g., Feb 30)
            next_run = next_month.replace(
                day=28, 
                hour=hour, 
                minute=minute, 
                second=0, 
                microsecond=0
            )
        
        return next_run
    
    else:
        # Default to daily
        return current_time + timedelta(days=1)

@celery_app.task(bind=True, name="scheduler.tasks.update_cve_database")
def update_cve_database(self):
    """Update CVE database with latest vulnerabilities"""
    try:
        logger.info("Starting CVE database update")
        
        # This would typically fetch from NVD API or similar
        # For now, we'll simulate with a basic implementation
        
        # Example: Fetch recent CVEs from NVD
        nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "resultsPerPage": 100,
            "pubStartDate": (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000")
        }
        
        try:
            response = requests.get(nvd_url, params=params, timeout=30)
            response.raise_for_status()
            
            cve_data = response.json()
            cves = cve_data.get("vulnerabilities", [])
            
            with next(get_sync_session()) as db:
                new_cves = 0
                updated_cves = 0
                
                for cve_entry in cves:
                    cve_info = cve_entry.get("cve", {})
                    cve_id = cve_info.get("id", "")
                    
                    if not cve_id:
                        continue
                    
                    # Extract relevant information
                    descriptions = cve_info.get("descriptions", [])
                    description = ""
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")
                            break
                    
                    metrics = cve_info.get("metrics", {})
                    cvss_score = None
                    severity = None
                    
                    # Extract CVSS score
                    if "cvssMetricV31" in metrics:
                        cvss_data = metrics["cvssMetricV31"][0]
                        cvss_score = cvss_data.get("cvssData", {}).get("baseScore")
                        severity = cvss_data.get("cvssData", {}).get("baseSeverity", "").lower()
                    elif "cvssMetricV2" in metrics:
                        cvss_data = metrics["cvssMetricV2"][0]
                        cvss_score = cvss_data.get("cvssData", {}).get("baseScore")
                        severity = cvss_data.get("baseSeverity", "").lower()
                    
                    # Extract affected technologies (simplified)
                    affected_technologies = []
                    configurations = cve_info.get("configurations", [])
                    for config in configurations:
                        nodes = config.get("nodes", [])
                        for node in nodes:
                            cpe_matches = node.get("cpeMatch", [])
                            for cpe_match in cpe_matches:
                                cpe_uri = cpe_match.get("criteria", "")
                                if cpe_uri:
                                    # Extract technology from CPE URI
                                    parts = cpe_uri.split(":")
                                    if len(parts) >= 4:
                                        tech = parts[3]  # Vendor or product
                                        if tech and tech not in affected_technologies:
                                            affected_technologies.append(tech)
                    
                    published_date = cve_info.get("published")
                    if published_date:
                        published_date = datetime.strptime(published_date, "%Y-%m-%dT%H:%M:%S.%f")
                    
                    modified_date = cve_info.get("lastModified")
                    if modified_date:
                        modified_date = datetime.strptime(modified_date, "%Y-%m-%dT%H:%M:%S.%f")
                    
                    # Check if CVE already exists
                    existing_cve = db.query(CVEWatch).filter(CVEWatch.cve_id == cve_id).first()
                    
                    if existing_cve:
                        # Update existing CVE
                        existing_cve.description = description
                        existing_cve.severity = severity
                        existing_cve.cvss_score = cvss_score
                        existing_cve.modified_date = modified_date
                        existing_cve.affected_technologies = affected_technologies
                        existing_cve.updated_at = datetime.utcnow()
                        updated_cves += 1
                    else:
                        # Create new CVE
                        new_cve = CVEWatch(
                            cve_id=cve_id,
                            description=description,
                            severity=severity,
                            cvss_score=cvss_score,
                            published_date=published_date,
                            modified_date=modified_date,
                            affected_technologies=affected_technologies,
                            is_active=True
                        )
                        db.add(new_cve)
                        new_cves += 1
                
                db.commit()
                
                logger.info(f"CVE database updated: {new_cves} new CVEs, {updated_cves} updated CVEs")
                
                # Check for CVE matches with existing technology stacks
                check_cve_matches.delay()
                
                return {
                    "success": True,
                    "new_cves": new_cves,
                    "updated_cves": updated_cves
                }
                
        except requests.RequestException as e:
            logger.error(f"Failed to fetch CVE data: {e}")
            return {"success": False, "error": f"Failed to fetch CVE data: {e}"}
            
    except Exception as e:
        logger.error(f"Error updating CVE database: {e}")
        return {"success": False, "error": str(e)}

@celery_app.task(bind=True, name="scheduler.tasks.check_cve_matches")
def check_cve_matches(self):
    """Check for CVE matches with existing technology stacks"""
    try:
        logger.info("Checking for CVE matches with technology stacks")
        
        with next(get_sync_session()) as db:
            # Get recent CVEs
            recent_cves = db.query(CVEWatch).filter(
                CVEWatch.is_active == True,
                CVEWatch.published_date >= datetime.utcnow() - timedelta(days=30)
            ).all()
            
            matches_found = 0
            
            for cve in recent_cves:
                affected_technologies = cve.affected_technologies or []
                
                if not affected_technologies:
                    continue
                
                # Find technology stacks that match this CVE
                matching_tech_stacks = db.query(TechStack).join(Subdomain).join(Target).filter(
                    TechStack.technology.in_(affected_technologies),
                    Target.is_active == True
                ).all()
                
                for tech_stack in matching_tech_stacks:
                    # Create notification
                    notification = Notification(
                        title=f"CVE Match Found: {cve.cve_id}",
                        message=f"CVE {cve.cve_id} affects {tech_stack.technology} found on {tech_stack.subdomain.subdomain}",
                        notification_type="cve_match",
                        priority="high" if cve.severity in ["high", "critical"] else "medium",
                        target_id=tech_stack.subdomain.target_id,
                        is_read=False,
                        is_sent=False
                    )
                    db.add(notification)
                    matches_found += 1
            
            db.commit()
            
            logger.info(f"Found {matches_found} CVE matches")
            
            return {
                "success": True,
                "matches_found": matches_found
            }
            
    except Exception as e:
        logger.error(f"Error checking CVE matches: {e}")
        return {"success": False, "error": str(e)}

@celery_app.task(bind=True, name="scheduler.tasks.cleanup_old_scans")
def cleanup_old_scans(self):
    """Clean up old scan records and logs"""
    try:
        logger.info("Starting cleanup of old scans")
        
        cutoff_date = datetime.utcnow() - timedelta(days=90)  # Keep scans for 90 days
        
        with next(get_sync_session()) as db:
            # Delete old scans
            old_scans = db.query(Scan).filter(
                Scan.created_at < cutoff_date,
                Scan.status.in_(["completed", "failed"])
            ).count()
            
            if old_scans > 0:
                db.query(Scan).filter(
                    Scan.created_at < cutoff_date,
                    Scan.status.in_(["completed", "failed"])
                ).delete()
                
                logger.info(f"Deleted {old_scans} old scan records")
            
            # Mark old subdomains as inactive if not seen recently
            inactive_cutoff = datetime.utcnow() - timedelta(days=30)
            inactive_subdomains = db.query(Subdomain).filter(
                Subdomain.last_seen < inactive_cutoff,
                Subdomain.is_active == True
            ).count()
            
            if inactive_subdomains > 0:
                db.query(Subdomain).filter(
                    Subdomain.last_seen < inactive_cutoff,
                    Subdomain.is_active == True
                ).update({"is_active": False})
                
                logger.info(f"Marked {inactive_subdomains} subdomains as inactive")
            
            db.commit()
            
            return {
                "success": True,
                "deleted_scans": old_scans,
                "inactive_subdomains": inactive_subdomains
            }
            
    except Exception as e:
        logger.error(f"Error cleaning up old scans: {e}")
        return {"success": False, "error": str(e)}

@celery_app.task(bind=True, name="scheduler.tasks.send_pending_notifications")
def send_pending_notifications(self):
    """Send pending notifications via configured channels"""
    try:
        logger.info("Sending pending notifications")
        
        with next(get_sync_session()) as db:
            # Get unsent notifications
            notifications = db.query(Notification).filter(
                Notification.is_sent == False,
                Notification.created_at >= datetime.utcnow() - timedelta(hours=24)  # Only recent notifications
            ).order_by(Notification.priority.desc(), Notification.created_at.desc()).limit(50).all()
            
            sent_count = 0
            
            for notification in notifications:
                try:
                    # This would integrate with actual notification services
                    # For now, we'll just mark as sent
                    
                    # Example: Send to Slack
                    # if settings.SLACK_WEBHOOK_URL:
                    #     send_slack_notification(notification)
                    
                    # Example: Send via email
                    # if settings.EMAIL_CONFIG:
                    #     send_email_notification(notification)
                    
                    # Mark as sent
                    notification.is_sent = True
                    notification.sent_via = ["console"]  # Would be actual channels
                    sent_count += 1
                    
                    logger.info(f"Sent notification: {notification.title}")
                    
                except Exception as e:
                    logger.error(f"Failed to send notification {notification.id}: {e}")
                    continue
            
            db.commit()
            
            logger.info(f"Sent {sent_count} notifications")
            
            return {
                "success": True,
                "sent_count": sent_count
            }
            
    except Exception as e:
        logger.error(f"Error sending notifications: {e}")
        return {"success": False, "error": str(e)}

@celery_app.task(bind=True, name="scheduler.tasks.generate_scan_reports")
def generate_scan_reports(self):
    """Generate periodic scan reports"""
    try:
        logger.info("Generating scan reports")
        
        with next(get_sync_session()) as db:
            # Generate weekly summary
            week_ago = datetime.utcnow() - timedelta(days=7)
            
            # Count scans by type
            scan_counts = db.query(
                Scan.scan_type,
                func.count(Scan.id).label('count')
            ).filter(
                Scan.created_at >= week_ago
            ).group_by(Scan.scan_type).all()
            
            # Count vulnerabilities by severity
            vuln_counts = db.query(
                Vulnerability.severity,
                func.count(Vulnerability.id).label('count')
            ).filter(
                Vulnerability.created_at >= week_ago
            ).group_by(Vulnerability.severity).all()
            
            # Count new subdomains
            new_subdomains = db.query(func.count(Subdomain.id)).filter(
                Subdomain.created_at >= week_ago
            ).scalar()
            
            # Generate report
            report = {
                "period": "weekly",
                "start_date": week_ago.isoformat(),
                "end_date": datetime.utcnow().isoformat(),
                "scan_counts": {scan_type: count for scan_type, count in scan_counts},
                "vulnerability_counts": {severity: count for severity, count in vuln_counts},
                "new_subdomains": new_subdomains,
                "generated_at": datetime.utcnow().isoformat()
            }
            
            logger.info(f"Generated weekly report: {report}")
            
            return {
                "success": True,
                "report": report
            }
            
    except Exception as e:
        logger.error(f"Error generating scan reports: {e}")
        return {"success": False, "error": str(e)}