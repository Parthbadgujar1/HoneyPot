from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import ModelVersion
from app.security.auth import get_current_user, require_role
from app.services.training_service import train_all

router = APIRouter(prefix="/models", tags=["models"])


@router.get("")
def list_models(db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = db.query(ModelVersion).order_by(ModelVersion.created_at.desc()).all()
    return {
        "items": [
            {
                "id": m.id,
                "model_type": m.model_type,
                "name": m.name,
                "version": m.version,
                "metrics": m.metrics,
                "trained_at": m.trained_at.isoformat() if m.trained_at else None,
                "is_active": m.is_active,
                "dataset_version": m.dataset_version,
                "artifact_path": m.artifact_path,
            }
            for m in rows
        ]
    }


@router.get("/{model_id}/metrics")
def model_metrics(model_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    m = db.get(ModelVersion, model_id)
    if not m:
        raise HTTPException(status_code=404, detail="Model not found")
    return {"model": m.name, "version": m.version, "metrics": m.metrics}


@router.post("/train")
def train(user=Depends(require_role("RESEARCHER")), db: Session = Depends(get_db)):
    results = train_all(db)
    return {"status": "trained", "results": results}


@router.post("/{model_id}/activate")
def activate_model(
    model_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_role("RESEARCHER")),
):
    m = db.get(ModelVersion, model_id)
    if not m:
        raise HTTPException(status_code=404, detail="Model not found")
    db.query(ModelVersion).filter(ModelVersion.model_type == m.model_type).update(
        {"is_active": False}
    )
    m.is_active = True
    db.add(m)
    db.commit()
    return {"status": "activated", "model_type": m.model_type, "version": m.version}
