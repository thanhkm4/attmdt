# apps/helpers/audit_helper.py

import json
from flask import current_app
from app.extensions import db
from app.models import AuditLog, get_vietnam_time


def log_audit(
    *,
    user_id: int,
    subject: str,
    action: str,
    target_id: int | None = None,
    detail: dict | str | None = None,
    auto_commit: bool = True
):
    """
    Ghi audit log dùng chung cho toàn hệ thống

    :param user_id: ID user thực hiện
    :param subject: USER / STATION / ORGANIZATION / ...
    :param action: CREATE / UPDATE / DELETE / ...
    :param target_id: ID bản ghi bị tác động
    :param detail: dict (sẽ json.dumps) hoặc string
    """

    try:
        if isinstance(detail, dict):
            detail = json.dumps(detail, ensure_ascii=False)

        log = AuditLog(
            user_id=user_id,
            subject=subject,
            action=action,
            target_id=target_id,
            detail=detail,
            timestamp=get_vietnam_time()
        )

        db.session.add(log)

        if auto_commit:
            db.session.commit()

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(
            f"[AUDIT_LOG_ERROR] {subject} {action} - {e}",
            exc_info=True
        )
