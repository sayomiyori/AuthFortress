from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.audit import AuditLog


def write_audit(
    db: Session,
    *,
    action: str,
    user_id: UUID | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    log = AuditLog(
        user_id=user_id,
        action=action,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details,
        created_at=datetime.now(UTC),
    )
    db.add(log)
    db.commit()
