"""Redact captured secrets before an event is stored.

Honeytoken matching runs first on the raw text, so reuse is still detected.
After that, typed passwords are replaced by a short SHA-256 digest (enough to
link attackers who reuse a password, useless for recovering it) and form
passwords in HTTP bodies are masked. Set ``privacy.redact_secrets`` to false
only on an isolated research machine.
"""

from __future__ import annotations

import hashlib
import re

from .events import HTTP, SSH_AUTH, Event

_FORM = re.compile(r"(?i)\b(pass(word)?|pwd|secret|token|key)=([^&\s]+)")


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def _mask(text: str) -> str:
    return _FORM.sub(lambda m: f"{m.group(1)}=<redacted>", text)


def redact_event(event: Event) -> None:
    detail = event.detail
    if event.kind == SSH_AUTH:
        if detail.get("secret_preview"):
            detail["secret_preview"] = _digest(str(detail["secret_preview"]))
        detail.pop("raw", None)
    elif event.kind == HTTP:
        for key in ("raw", "body_preview", "query"):
            if isinstance(detail.get(key), str):
                detail[key] = _mask(detail[key])
