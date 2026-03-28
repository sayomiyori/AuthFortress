from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.audit import AuditLog
from app.models.session import UserSession
from app.models.user import User, UserRole
from app.core.security import require_role

router = APIRouter()


@router.get("/stats")
def admin_stats(
    db: Session = Depends(get_db),
    _: User = Depends(require_role(UserRole.admin)),
):
    user_count = db.query(func.count(User.id)).scalar() or 0
    active_sessions = (
        db.query(func.count(UserSession.id))
        .filter(UserSession.revoked_at.is_(None))
        .scalar()
        or 0
    )
    audit_count = db.query(func.count(AuditLog.id)).scalar() or 0
    return {
        "users": user_count,
        "active_sessions": active_sessions,
        "audit_entries": audit_count,
    }
