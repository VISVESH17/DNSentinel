"""
Alerts API -- lists open alerts and lets analysts record feedback
(confirmed threat / false positive), per the playbook's "Investigation
& Feedback" module. This feedback is exactly what would seed a labelled
dataset for retraining the DGA/tunnel models in a real deployment.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.auth.security import require_role, get_current_user, User
from backend.database.database import get_db
from backend.database.models import Alert

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("")
def list_alerts(status: str | None = None, limit: int = 100, db: Session = Depends(get_db),
                 user: User = Depends(get_current_user)):
    query = db.query(Alert)
    if status:
        query = query.filter(Alert.status == status)
    rows = query.order_by(Alert.created_at.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "domain": r.domain,
            "client_ip": r.client_ip,
            "severity": r.severity,
            "alert_type": r.alert_type,
            "status": r.status,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


@router.get("/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {
        "id": alert.id, "domain": alert.domain, "client_ip": alert.client_ip,
        "severity": alert.severity, "alert_type": alert.alert_type,
        "status": alert.status, "created_at": alert.created_at.isoformat(),
    }


class AlertFeedback(BaseModel):
    status: str  # "resolved" | "false_positive" | "investigating"


@router.patch("/{alert_id}")
def update_alert(
    alert_id: int, feedback: AlertFeedback, db: Session = Depends(get_db),
    user=Depends(require_role("admin", "analyst")),
):
    if feedback.status not in ("open", "investigating", "resolved", "false_positive"):
        raise HTTPException(status_code=400, detail="Invalid status value")

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = feedback.status
    db.commit()

    # NOTE: in the full deployment, an analyst marking an alert
    # false_positive/resolved is exactly the labelled feedback loop
    # described in the playbook -- it would be appended to the training
    # dataset for the next DGA/tunnel model retrain.
    return {"id": alert.id, "domain": alert.domain, "status": alert.status, "updated_by": user.username}
