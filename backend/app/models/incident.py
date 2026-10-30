from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship  
from app.database.database import Base

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True) # index=True যোগ করা হলো
    title = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False, default="Medium")
    status = Column(String(50), nullable=False, default="Open")
    description = Column(Text, nullable=True)
    analyst_notes = Column(Text, nullable=True)
    resolution = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    user = relationship("User", back_populates="incidents")