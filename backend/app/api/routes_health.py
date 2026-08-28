from fastapi import APIRouter, Depends
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy.sql import text

from backend.app.database import get_db
from backend.app.schemas import HealthOut
from backend.app.config import settings

router = APIRouter(prefix="/api/health", tags=["Health"])

@router.get("", response_model=HealthOut)
def health_check(db: Session = Depends(get_db)):
    db_status = "HEALTHY"
    try:
        # Perform quick query to verify DB connection is alive
        db.execute(text("SELECT 1"))
    except Exception:
        db_status = "UNHEALTHY"
        
    return {
        "status": "HEALTHY" if db_status == "HEALTHY" else "DATABASE_ERROR",
        "timestamp": datetime.utcnow(),
        "database": settings.DATABASE_URL.split(":")[0] # SQLite, postgresql, etc.
    }
