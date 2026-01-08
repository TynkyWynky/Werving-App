from __future__ import annotations

import json
import sqlite3
from typing import Any, Dict, Optional


def log_audit_event(
    database_connection: sqlite3.Connection,
    *,
    event_type: str,
    entity_type: str,
    entity_id: int,
    from_status: Optional[str] = None,
    to_status: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    performed_by_user_id: Optional[int] = None,
    performed_by_candidate_id: Optional[int] = None,
) -> None:
    database_connection.execute(
        """
        INSERT INTO audit_log (
            event_type, entity_type, entity_id,
            performed_by_user_id, performed_by_candidate_id,
            from_status, to_status, details_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_type,
            entity_type,
            entity_id,
            performed_by_user_id,
            performed_by_candidate_id,
            from_status,
            to_status,
            json.dumps(details or {}, ensure_ascii=False),
        ),
    )
