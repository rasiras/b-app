from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, JSON, Float, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
from typing import Optional, List, Dict, Any

Base = declarative_base()

class Target(Base):
    __tablename__ = "targets"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, index=True)
    base_domain = Column(String, nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    tags = Column(JSON, default=list)  # List of tags
    scope = Column(JSON, default=dict)  # In-scope and out-of-scope rules
    notes = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    subdomains = relationship("Subdomain", back_populates="target", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('idx_target_active_domain', 'is_active', 'base_domain'),
        Index('idx_target_created', 'created_at'),
    )

class Subdomain(Base):
    __tablename__ = "subdomains"
    
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    subdomain = Column(String, nullable=False, index=True)
    ip_address = Column(String, nullable=True)
    is_active = Column(Boolean, default=True, index=True)
    last_seen = Column(DateTime, default=func.now())
    created_at = Column(DateTime, default=func.now())
    
    # Relationships
    target = relationship("Target", back_populates="subdomains")
    services = relationship("Service", back_populates="subdomain", cascade="all, delete-orphan")
    tech_stack = relationship("TechStack", back_populates="subdomain", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="subdomain", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('idx_subdomain_target_active', 'target_id', 'is_active'),
        Index('idx_subdomain_last_seen', 'last_seen'),
    )

class Service(Base):
    __tablename__ = "services"
    
    id = Column(Integer, primary_key=True, index=True)
    subdomain_id = Column(Integer, ForeignKey("subdomains.id"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String, nullable=False)  # tcp, udp
    service_name = Column(String, nullable=True)
    version = Column(String, nullable=True)
    banner = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    subdomain = relationship("Subdomain", back_populates="services")
    
    # Indexes
    __table_args__ = (
        Index('idx_service_subdomain_port', 'subdomain_id', 'port'),
        Index('idx_service_active', 'is_active'),
    )

class TechStack(Base):
    __tablename__ = "tech_stacks"
    
    id = Column(Integer, primary_key=True, index=True)
    subdomain_id = Column(Integer, ForeignKey("subdomains.id"), nullable=False)
    technology = Column(String, nullable=False, index=True)
    category = Column(String, nullable=True, index=True)  # web-server, cms, framework, etc.
    version = Column(String, nullable=True)
    confidence = Column(Float, nullable=True)  # 0-100
    source = Column(String, nullable=True)  # wappalyzer, manual, etc.
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    subdomain = relationship("Subdomain", back_populates="tech_stack")
    
    # Indexes
    __table_args__ = (
        Index('idx_tech_stack_technology', 'technology'),
        Index('idx_tech_stack_category', 'category'),
        Index('idx_tech_stack_subdomain', 'subdomain_id'),
    )

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    subdomain_id = Column(Integer, ForeignKey("subdomains.id"), nullable=False)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False, index=True)  # critical, high, medium, low, info
    confidence = Column(String, nullable=False)  # certain, firm, tentative
    description = Column(Text, nullable=True)
    solution = Column(Text, nullable=True)
    reference = Column(JSON, default=list)  # URLs, CVE IDs, etc.
    cvss_score = Column(Float, nullable=True)
    cve_id = Column(String, nullable=True, index=True)
    scanner_name = Column(String, nullable=True)
    template_id = Column(String, nullable=True)
    matched_at = Column(String, nullable=True)  # URL or endpoint
    request = Column(Text, nullable=True)
    response = Column(Text, nullable=True)
    is_verified = Column(Boolean, default=False, index=True)
    is_false_positive = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    subdomain = relationship("Subdomain", back_populates="vulnerabilities")
    
    # Indexes
    __table_args__ = (
        Index('idx_vuln_severity', 'severity'),
        Index('idx_vuln_cve', 'cve_id'),
        Index('idx_vuln_subdomain_severity', 'subdomain_id', 'severity'),
        Index('idx_vuln_verified', 'is_verified'),
    )

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    scan_type = Column(String, nullable=False, index=True)  # subdomain, port, tech, vuln, full
    status = Column(String, nullable=False, index=True)  # pending, running, completed, failed
    scan_config = Column(JSON, default=dict)  # Scanner configuration
    results = Column(JSON, default=dict)  # Summary results
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())
    
    # Relationships
    target = relationship("Target", back_populates="scans")
    scan_logs = relationship("ScanLog", back_populates="scan", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('idx_scan_target_type', 'target_id', 'scan_type'),
        Index('idx_scan_status', 'status'),
        Index('idx_scan_created', 'created_at'),
    )

class ScanLog(Base):
    __tablename__ = "scan_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    level = Column(String, nullable=False)  # info, warning, error
    message = Column(Text, nullable=False)
    details = Column(JSON, default=dict)
    created_at = Column(DateTime, default=func.now())
    
    # Relationships
    scan = relationship("Scan", back_populates="scan_logs")
    
    # Indexes
    __table_args__ = (
        Index('idx_scan_log_scan_level', 'scan_id', 'level'),
        Index('idx_scan_log_created', 'created_at'),
    )

class ScheduledScan(Base):
    __tablename__ = "scheduled_scans"
    
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    scan_type = Column(String, nullable=False)
    schedule_type = Column(String, nullable=False)  # daily, weekly, monthly
    schedule_config = Column(JSON, default=dict)  # cron expression, specific times
    scan_config = Column(JSON, default=dict)  # Scanner configuration
    is_active = Column(Boolean, default=True, index=True)
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True, index=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    target = relationship("Target")
    
    # Indexes
    __table_args__ = (
        Index('idx_scheduled_scan_active_next', 'is_active', 'next_run'),
        Index('idx_scheduled_scan_target', 'target_id'),
    )

class CVEWatch(Base):
    __tablename__ = "cve_watches"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    severity = Column(String, nullable=True)
    cvss_score = Column(Float, nullable=True)
    published_date = Column(DateTime, nullable=True)
    modified_date = Column(DateTime, nullable=True)
    affected_technologies = Column(JSON, default=list)  # List of technologies
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Indexes
    __table_args__ = (
        Index('idx_cve_active', 'is_active'),
        Index('idx_cve_published', 'published_date'),
        Index('idx_cve_severity', 'severity'),
    )

class Notification(Base):
    __tablename__ = "notifications"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    notification_type = Column(String, nullable=False, index=True)  # scan_complete, vulnerability_found, cve_match
    priority = Column(String, nullable=False, index=True)  # low, medium, high, critical
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    is_read = Column(Boolean, default=False, index=True)
    is_sent = Column(Boolean, default=False, index=True)
    sent_via = Column(JSON, default=list)  # email, slack, discord
    created_at = Column(DateTime, default=func.now())
    
    # Relationships
    target = relationship("Target")
    scan = relationship("Scan")
    
    # Indexes
    __table_args__ = (
        Index('idx_notification_unread', 'is_read'),
        Index('idx_notification_priority', 'priority'),
        Index('idx_notification_type', 'notification_type'),
    )

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Indexes
    __table_args__ = (
        Index('idx_user_active', 'is_active'),
        Index('idx_user_admin', 'is_admin'),
    )