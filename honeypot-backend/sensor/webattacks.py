"""Signature detection for application-layer attacks seen by the HTTP decoy.

The decoy never executes anything it receives. This module only inspects the
request text (path, query string, body preview) and names the attack family,
so the engine can score it like any other behaviour. Signatures are
deliberately conservative: each needs a recognisable attack construct, not a
single keyword, so ordinary search text does not match.
"""

from __future__ import annotations

import re
from urllib.parse import unquote_plus

FAMILIES: dict[str, list[re.Pattern]] = {
    "SQL_INJECTION": [re.compile(p, re.I) for p in (
        r"\bunion\b\s+(all\s+)?\bselect\b",
        r"('|\")\s*(or|and)\s+('|\"|\d)[^=<>]{0,12}(=|like)",
        r"\b(or|and)\b\s+\d+\s*=\s*\d+",
        r";\s*(drop|insert|update|delete)\b\s+\w+",
        r"\bsleep\s*\(\s*\d+\s*\)",
        r"\bbenchmark\s*\(",
        r"information_schema",
    )],
    "XSS": [re.compile(p, re.I) for p in (
        r"<\s*script\b",
        r"\bon(error|load|click|mouseover)\s*=",
        r"javascript\s*:",
        r"<\s*(img|svg|iframe)\b[^>]*(src|onload)",
    )],
    "COMMAND_INJECTION": [re.compile(p, re.I) for p in (
        r"[;|&`]\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|powershell|cmd)\b",
        r"\$\(\s*(cat|id|whoami|uname|curl|wget)\b",
        r"/bin/(ba)?sh\b",
    )],
    "PATH_TRAVERSAL": [re.compile(p, re.I) for p in (
        r"(\.\./){2,}",
        r"\.\.\\",
        r"/etc/(passwd|shadow)",
        r"\b(boot\.ini|win\.ini)\b",
    )],
    "FILE_UPLOAD_ABUSE": [re.compile(p, re.I) for p in (
        r"filename\s*=\s*['\"]?[^'\"\s]*\.(php\d?|phtml|jsp|aspx?|exe|sh)\b",
        r"<\?php",
    )],
    "SSRF_LFI": [re.compile(p, re.I) for p in (
        r"(url|file|path|page|redirect)=\s*(https?|file|gopher|ftp)://",
        r"169\.254\.169\.254",
    )],
}


def _decode(text: str) -> str:
    """Decode up to two layers of percent-encoding, a common evasion."""
    for _ in range(2):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return text


def classify_request(path: str, query: str = "", body: str = "", user_agent: str = "") -> list[str]:
    """Return the attack families whose signatures match this request."""
    text = _decode(f"{path}?{query}\n{body}\n{user_agent}")
    return [name for name, patterns in FAMILIES.items() if any(p.search(text) for p in patterns)]
