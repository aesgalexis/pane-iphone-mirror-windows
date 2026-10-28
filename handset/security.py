"""Browser-to-local-server request checks (not a Windows malware sandbox)."""

from __future__ import annotations

import secrets
from typing import Mapping

MAX_REQUEST_BODY = 1_048_576
# One unpredictable token per Pane process. Never persist it or put it in a URL.
ACCESS_TOKEN = secrets.token_urlsafe(32)


def request_allowed(headers: Mapping[str, str], port: int, *, token_required: bool) -> bool:
    """Reject DNS rebinding, browser cross-origin requests, and tokenless API access.

    Authorization here isolates the browser UI from other web origins; a local
    process with Windows user access can still reach the iPhone through other
    OS or Apple device interfaces and is outside this protection boundary.
    """
    host = f"127.0.0.1:{port}"
    if headers.get("Host") != host:
        return False
    origin = headers.get("Origin")
    if origin is not None and origin != f"http://{host}":
        return False
    fetch_site = headers.get("Sec-Fetch-Site")
    if fetch_site is not None and fetch_site not in {"same-origin", "none"}:
        return False
    if token_required and not secrets.compare_digest(headers.get("X-Pane-Token", ""), ACCESS_TOKEN):
        return False
    return True
