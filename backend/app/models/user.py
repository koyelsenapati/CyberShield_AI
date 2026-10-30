"""
CyberShield AI
User Model
"""

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    username = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )

    full_name = Column(
        String(100),
        nullable=False,
    )

    email = Column(
        String(120),
        unique=True,
        nullable=False,
        index=True,
    )

    hashed_password = Column(
        String(255),
        nullable=False,
    )

    role = Column(
        String(30),
        default="user",
        nullable=False,
    )

    is_active = Column(
        Boolean,
        default=True,
        nullable=False,
    )

    is_verified = Column(
        Boolean,
        default=False,
        nullable=False,
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Relationship with Alert model
    alerts = relationship(
        "Alert",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    # Relationship with ChatHistory model
    chat_history = relationship(
        "ChatHistory",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    # Relationship with DNSRecord model
    dns_records = relationship(
        "DNSRecord",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    # Relationship with LoginLog model
    login_logs = relationship(
        "LoginLog",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    # Relationship with Report model
    reports = relationship(
        "Report",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    # Relationship with SSLCertificate model
    ssl_certificates = relationship(
        "SSLCertificate",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    # Relationship with Vulnerability model
    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    # Relationship with WhoisRecord model
    whois_records = relationship(
        "WhoisRecord",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    # Relationship with WebScan model
    web_scans = relationship(
        "WebScan",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    # Relationship with PhishingScan model
    phishing_scans = relationship(
        "PhishingScan",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    # Relationship with NetworkScan model
    network_scans = relationship(
        "NetworkScan",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    # Relationship with Scan model
    scans = relationship(
        "Scan",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    # Relationship with FileIntegrity model
    file_integrity_records = relationship(
        "FileIntegrity",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    # Relationship with Master Scan
    master_scans = relationship(
        "MasterScan",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    # User মডেলের ভেতরে এটি যোগ করুন:
    incidents = relationship(
        "Incident", 
        back_populates="user", 
        cascade="all, delete-orphan")