from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.analytics.service import dashboard_summary
from app.core.database import get_db
from app.security.auth import get_current_user

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
def summary(db: Session = Depends(get_db), user=Depends(get_current_user)):
    return dashboard_summary(db)
