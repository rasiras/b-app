from celery import current_task
from core.celery_app import celery_app
from core.database import get_sync_session
from models.database import Target, Subdomain, Service, TechStack, Vulnerability, Scan, ScanLog
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Dict, List, Any, Optional
import logging
from datetime import datetime
import json

from .subdomain_scanner import CombinedSubdomainScanner
from .port_scanner import CombinedPortScanner
from .vuln_scanner import CombinedVulnScanner

logger = logging.getLogger(__name__)

def update_scan_status(scan_id: int, status: str, error_message: str = None):
    """Update scan status in database"""
    try:
        with next(get_sync_session()) as db:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = status
                if error_message:
                    scan.error_message = error_message
                if status == "running":
                    scan.started_at = datetime.utcnow()
                elif status in ["completed", "failed"]:
                    scan.completed_at = datetime.utcnow()
                db.commit()
    except Exception as e:
        logger.error(f"Failed to update scan status: {e}")

def add_scan_log(scan_id: int, level: str, message: str, details: Dict[str, Any] = None):
    """Add log entry for scan"""
    try:
        with next(get_sync_session()) as db:
            log_entry = ScanLog(
                scan_id=scan_id,
                level=level,
                message=message,
                details=details or {}
            )
            db.add(log_entry)
            db.commit()
    except Exception as e:
        logger.error(f"Failed to add scan log: {e}")

@celery_app.task(bind=True, name="scanners.tasks.run_subdomain_scan")
def run_subdomain_scan(self, target_id: int, scan_id: int, options: Dict[str, Any] = None):
    """Run subdomain enumeration scan"""
    try:
        # Update scan status
        update_scan_status(scan_id, "running")
        add_scan_log(scan_id, "info", "Starting subdomain enumeration scan")
        
        # Get target from database
        with next(get_sync_session()) as db:
            target = db.query(Target).filter(Target.id == target_id).first()
            if not target:
                raise ValueError(f"Target with ID {target_id} not found")
            
            domain = target.base_domain
            
            # Initialize scanner
            scanner = CombinedSubdomainScanner()
            
            # Run scan
            add_scan_log(scan_id, "info", f"Running subdomain scan for {domain}")
            results = scanner.scan(domain, options or {})
            
            if results.get("success"):
                subdomains = results.get("results", [])
                
                # Store results in database
                for subdomain_data in subdomains:
                    subdomain_name = subdomain_data.get("subdomain", "")
                    ip_address = subdomain_data.get("ip", "")
                    
                    if subdomain_name:
                        # Check if subdomain already exists
                        existing = db.query(Subdomain).filter(
                            Subdomain.target_id == target_id,
                            Subdomain.subdomain == subdomain_name
                        ).first()
                        
                        if existing:
                            # Update existing record
                            existing.ip_address = ip_address or existing.ip_address
                            existing.last_seen = datetime.utcnow()
                            existing.is_active = True
                        else:
                            # Create new record
                            subdomain = Subdomain(
                                target_id=target_id,
                                subdomain=subdomain_name,
                                ip_address=ip_address,
                                is_active=True,
                                last_seen=datetime.utcnow()
                            )
                            db.add(subdomain)
                
                # Update scan record
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                if scan:
                    scan.results = {
                        "total_subdomains": len(subdomains),
                        "new_subdomains": len([s for s in subdomains if s.get("subdomain")]),
                        "scanners_used": results.get("scanners_used", [])
                    }
                
                db.commit()
                
                add_scan_log(scan_id, "info", f"Found {len(subdomains)} subdomains")
                update_scan_status(scan_id, "completed")
                
                return {
                    "success": True,
                    "total_subdomains": len(subdomains),
                    "results": results
                }
            else:
                error_msg = results.get("error", "Unknown error occurred")
                add_scan_log(scan_id, "error", error_msg)
                update_scan_status(scan_id, "failed", error_msg)
                return {"success": False, "error": error_msg}
                
    except Exception as e:
        error_msg = f"Subdomain scan failed: {str(e)}"
        logger.error(error_msg)
        add_scan_log(scan_id, "error", error_msg)
        update_scan_status(scan_id, "failed", error_msg)
        return {"success": False, "error": error_msg}

@celery_app.task(bind=True, name="scanners.tasks.run_port_scan")
def run_port_scan(self, target_id: int, scan_id: int, options: Dict[str, Any] = None):
    """Run port scanning on target subdomains"""
    try:
        # Update scan status
        update_scan_status(scan_id, "running")
        add_scan_log(scan_id, "info", "Starting port scan")
        
        # Get target and its subdomains
        with next(get_sync_session()) as db:
            target = db.query(Target).filter(Target.id == target_id).first()
            if not target:
                raise ValueError(f"Target with ID {target_id} not found")
            
            subdomains = db.query(Subdomain).filter(
                Subdomain.target_id == target_id,
                Subdomain.is_active == True
            ).all()
            
            if not subdomains:
                add_scan_log(scan_id, "warning", "No active subdomains found for port scanning")
                update_scan_status(scan_id, "completed")
                return {"success": True, "message": "No subdomains to scan"}
            
            # Prepare targets list
            targets = [sub.subdomain for sub in subdomains]
            
            # Initialize scanner
            scanner = CombinedPortScanner()
            
            # Run scan
            add_scan_log(scan_id, "info", f"Running port scan on {len(targets)} targets")
            results = scanner.scan(targets, options or {})
            
            # Store port scan results
            port_results = results.get("port_scan", {}).get("results", [])
            for port_data in port_results:
                host = port_data.get("host", "")
                port = port_data.get("port", 0)
                
                # Find corresponding subdomain
                subdomain = db.query(Subdomain).filter(
                    Subdomain.target_id == target_id,
                    Subdomain.subdomain == host
                ).first()
                
                if subdomain and port:
                    # Check if service already exists
                    existing_service = db.query(Service).filter(
                        Service.subdomain_id == subdomain.id,
                        Service.port == port
                    ).first()
                    
                    if existing_service:
                        # Update existing service
                        existing_service.protocol = port_data.get("protocol", "tcp")
                        existing_service.service_name = port_data.get("service", "")
                        existing_service.version = port_data.get("version", "")
                        existing_service.banner = port_data.get("banner", "")
                        existing_service.is_active = True
                        existing_service.updated_at = datetime.utcnow()
                    else:
                        # Create new service
                        service = Service(
                            subdomain_id=subdomain.id,
                            port=port,
                            protocol=port_data.get("protocol", "tcp"),
                            service_name=port_data.get("service", ""),
                            version=port_data.get("version", ""),
                            banner=port_data.get("banner", ""),
                            is_active=True
                        )
                        db.add(service)
            
            # Store HTTP scan results and technology detection
            http_results = results.get("http_scan", {}).get("results", [])
            for http_data in http_results:
                host = http_data.get("host", "")
                technologies = http_data.get("technologies", [])
                
                # Find corresponding subdomain
                subdomain = db.query(Subdomain).filter(
                    Subdomain.target_id == target_id,
                    Subdomain.subdomain == host
                ).first()
                
                if subdomain:
                    # Store technology information
                    for tech in technologies:
                        existing_tech = db.query(TechStack).filter(
                            TechStack.subdomain_id == subdomain.id,
                            TechStack.technology == tech
                        ).first()
                        
                        if not existing_tech:
                            tech_stack = TechStack(
                                subdomain_id=subdomain.id,
                                technology=tech,
                                category="web-technology",
                                confidence=80.0,
                                source="httpx"
                            )
                            db.add(tech_stack)
            
            # Update scan record
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.results = {
                    "total_ports": len(port_results),
                    "total_services": len(http_results),
                    "summary": results.get("summary", {})
                }
            
            db.commit()
            
            add_scan_log(scan_id, "info", f"Port scan completed. Found {len(port_results)} open ports")
            update_scan_status(scan_id, "completed")
            
            return {
                "success": True,
                "total_ports": len(port_results),
                "total_services": len(http_results),
                "results": results
            }
            
    except Exception as e:
        error_msg = f"Port scan failed: {str(e)}"
        logger.error(error_msg)
        add_scan_log(scan_id, "error", error_msg)
        update_scan_status(scan_id, "failed", error_msg)
        return {"success": False, "error": error_msg}

@celery_app.task(bind=True, name="scanners.tasks.run_vulnerability_scan")
def run_vulnerability_scan(self, target_id: int, scan_id: int, options: Dict[str, Any] = None):
    """Run vulnerability scanning on target"""
    try:
        # Update scan status
        update_scan_status(scan_id, "running")
        add_scan_log(scan_id, "info", "Starting vulnerability scan")
        
        # Get target and its subdomains
        with next(get_sync_session()) as db:
            target = db.query(Target).filter(Target.id == target_id).first()
            if not target:
                raise ValueError(f"Target with ID {target_id} not found")
            
            subdomains = db.query(Subdomain).filter(
                Subdomain.target_id == target_id,
                Subdomain.is_active == True
            ).all()
            
            if not subdomains:
                add_scan_log(scan_id, "warning", "No active subdomains found for vulnerability scanning")
                update_scan_status(scan_id, "completed")
                return {"success": True, "message": "No subdomains to scan"}
            
            # Prepare targets list (URLs)
            targets = []
            for subdomain in subdomains:
                targets.extend([
                    f"http://{subdomain.subdomain}",
                    f"https://{subdomain.subdomain}"
                ])
            
            # Initialize scanner
            scanner = CombinedVulnScanner()
            
            # Run scan
            add_scan_log(scan_id, "info", f"Running vulnerability scan on {len(targets)} targets")
            results = scanner.scan(targets, options or {})
            
            # Store vulnerability results
            vuln_results = results.get("vulnerabilities", {}).get("results", [])
            for vuln_data in vuln_results:
                host = vuln_data.get("host", "")
                
                # Find corresponding subdomain
                subdomain = db.query(Subdomain).filter(
                    Subdomain.target_id == target_id,
                    Subdomain.subdomain == host
                ).first()
                
                if subdomain:
                    # Create vulnerability record
                    vulnerability = Vulnerability(
                        subdomain_id=subdomain.id,
                        title=vuln_data.get("name", ""),
                        severity=vuln_data.get("severity", "info"),
                        confidence="tentative",
                        description=vuln_data.get("description", ""),
                        reference=vuln_data.get("reference", []),
                        cvss_score=vuln_data.get("cvss_score"),
                        cve_id=vuln_data.get("cve_id"),
                        scanner_name="nuclei",
                        template_id=vuln_data.get("template_id", ""),
                        matched_at=vuln_data.get("matched_at", ""),
                        request=vuln_data.get("request", ""),
                        response=vuln_data.get("response", ""),
                        is_verified=False,
                        is_false_positive=False
                    )
                    db.add(vulnerability)
            
            # Store technology information
            tech_results = results.get("technologies", {}).get("results", [])
            for tech_data in tech_results:
                host = tech_data.get("host", "")
                
                # Find corresponding subdomain
                subdomain = db.query(Subdomain).filter(
                    Subdomain.target_id == target_id,
                    Subdomain.subdomain == host
                ).first()
                
                if subdomain:
                    # Store server technology
                    server = tech_data.get("server", "")
                    if server:
                        existing_tech = db.query(TechStack).filter(
                            TechStack.subdomain_id == subdomain.id,
                            TechStack.technology == server
                        ).first()
                        
                        if not existing_tech:
                            tech_stack = TechStack(
                                subdomain_id=subdomain.id,
                                technology=server,
                                category="web-server",
                                confidence=90.0,
                                source="nuclei"
                            )
                            db.add(tech_stack)
                    
                    # Store CMS technology
                    cms = tech_data.get("cms", "")
                    if cms:
                        existing_tech = db.query(TechStack).filter(
                            TechStack.subdomain_id == subdomain.id,
                            TechStack.technology == cms
                        ).first()
                        
                        if not existing_tech:
                            tech_stack = TechStack(
                                subdomain_id=subdomain.id,
                                technology=cms,
                                category="cms",
                                confidence=90.0,
                                source="nuclei"
                            )
                            db.add(tech_stack)
            
            # Update scan record
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.results = {
                    "total_vulnerabilities": len(vuln_results),
                    "critical_vulnerabilities": len([v for v in vuln_results if v.get("severity") == "critical"]),
                    "high_vulnerabilities": len([v for v in vuln_results if v.get("severity") == "high"]),
                    "summary": results.get("summary", {})
                }
            
            db.commit()
            
            add_scan_log(scan_id, "info", f"Vulnerability scan completed. Found {len(vuln_results)} vulnerabilities")
            update_scan_status(scan_id, "completed")
            
            return {
                "success": True,
                "total_vulnerabilities": len(vuln_results),
                "results": results
            }
            
    except Exception as e:
        error_msg = f"Vulnerability scan failed: {str(e)}"
        logger.error(error_msg)
        add_scan_log(scan_id, "error", error_msg)
        update_scan_status(scan_id, "failed", error_msg)
        return {"success": False, "error": error_msg}

@celery_app.task(bind=True, name="scanners.tasks.run_full_scan")
def run_full_scan(self, target_id: int, scan_id: int, options: Dict[str, Any] = None):
    """Run full comprehensive scan (subdomain -> port -> vulnerability)"""
    try:
        # Update scan status
        update_scan_status(scan_id, "running")
        add_scan_log(scan_id, "info", "Starting full comprehensive scan")
        
        options = options or {}
        
        # Step 1: Subdomain enumeration
        add_scan_log(scan_id, "info", "Step 1: Running subdomain enumeration")
        subdomain_result = run_subdomain_scan.apply_async(
            args=[target_id, scan_id, options.get("subdomain_options", {})],
            countdown=0
        ).get()
        
        if not subdomain_result.get("success"):
            raise Exception(f"Subdomain scan failed: {subdomain_result.get('error')}")
        
        # Step 2: Port scanning
        add_scan_log(scan_id, "info", "Step 2: Running port scanning")
        port_result = run_port_scan.apply_async(
            args=[target_id, scan_id, options.get("port_options", {})],
            countdown=0
        ).get()
        
        if not port_result.get("success"):
            logger.warning(f"Port scan failed: {port_result.get('error')}")
            add_scan_log(scan_id, "warning", f"Port scan failed: {port_result.get('error')}")
        
        # Step 3: Vulnerability scanning
        add_scan_log(scan_id, "info", "Step 3: Running vulnerability scanning")
        vuln_result = run_vulnerability_scan.apply_async(
            args=[target_id, scan_id, options.get("vuln_options", {})],
            countdown=0
        ).get()
        
        if not vuln_result.get("success"):
            logger.warning(f"Vulnerability scan failed: {vuln_result.get('error')}")
            add_scan_log(scan_id, "warning", f"Vulnerability scan failed: {vuln_result.get('error')}")
        
        # Update final scan results
        with next(get_sync_session()) as db:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.results = {
                    "subdomain_scan": subdomain_result,
                    "port_scan": port_result,
                    "vulnerability_scan": vuln_result,
                    "total_subdomains": subdomain_result.get("total_subdomains", 0),
                    "total_ports": port_result.get("total_ports", 0),
                    "total_vulnerabilities": vuln_result.get("total_vulnerabilities", 0)
                }
            db.commit()
        
        add_scan_log(scan_id, "info", "Full scan completed successfully")
        update_scan_status(scan_id, "completed")
        
        return {
            "success": True,
            "subdomain_scan": subdomain_result,
            "port_scan": port_result,
            "vulnerability_scan": vuln_result
        }
        
    except Exception as e:
        error_msg = f"Full scan failed: {str(e)}"
        logger.error(error_msg)
        add_scan_log(scan_id, "error", error_msg)
        update_scan_status(scan_id, "failed", error_msg)
        return {"success": False, "error": error_msg}