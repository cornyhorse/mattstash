"""Audit trail: who (key id, address) did what to which credential.

Never logs secrets or the API key itself -- only the key *id*. Every value is escaped to printable ASCII, so a
client cannot inject log lines.
"""

import logging
from typing import Any, Optional

from fastapi import Request

from .client_ip import client_ip
from .logsafe import printable

audit_logger = logging.getLogger("mattstash.audit")


def audit(request: Request, action: str, name: Optional[str] = None, **fields: Any) -> None:
    principal = getattr(request.state, "principal", None)
    parts = {
        "key": principal.id if principal is not None else "-",
        "ip": client_ip(request.scope),
        "action": action,
        "name": name,
        **fields,
    }
    audit_logger.info("audit " + " ".join(f"{k}={printable(v)}" for k, v in parts.items() if v is not None))
