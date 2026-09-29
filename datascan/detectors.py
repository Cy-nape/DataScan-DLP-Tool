"""Sensitive-data detectors — regex, checksums, and entropy."""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import Enum


# ── Data models ──────────────────────────────────────────────────────
class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Classification(str, Enum):
    RESTRICTED = "Restricted"
    CONFIDENTIAL = "Confidential"
    INTERNAL = "Internal"


@dataclass(frozen=True)
class Finding:
    finding_type: str
    file: str
    line: int
    severity: Severity
    classification: Classification
    masked_preview: str


# ── Masking ──────────────────────────────────────────────────────────
def mask_value(value: str) -> str:
    """Return a masked preview — the full raw value is **never** stored."""
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


# ── Verhoeff checksum tables ────────────────────────────────────────
_D = [
    [0,1,2,3,4,5,6,7,8,9], [1,2,3,4,0,6,7,8,9,5],
    [2,3,4,0,1,7,8,9,5,6], [3,4,0,1,2,8,9,5,6,7],
    [4,0,1,2,3,9,5,6,7,8], [5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2], [7,6,5,9,8,2,1,0,4,3],
    [8,7,6,5,9,3,2,1,0,4], [9,8,7,6,5,4,3,2,1,0],
]
_P = [
    [0,1,2,3,4,5,6,7,8,9], [1,5,7,6,2,8,3,0,9,4],
    [5,8,0,3,7,9,6,1,4,2], [8,9,1,6,0,4,3,5,2,7],
    [9,4,5,3,1,2,6,8,7,0], [4,2,8,6,5,7,3,9,0,1],
    [2,7,9,3,8,0,6,4,1,5], [7,0,4,6,9,1,3,2,5,8],
]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_checksum(number: str) -> bool:
    """Return True if *number* passes the Verhoeff check."""
    if not number.isdigit():
        return False
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def is_valid_aadhaar(raw: str) -> bool:
    """Validate a 12-digit Aadhaar-format string (Verhoeff)."""
    clean = raw.replace(" ", "").replace("-", "")
    if len(clean) != 12 or not clean.isdigit() or clean[0] in "01":
        return False
    return verhoeff_checksum(clean)


# ── Luhn checksum ────────────────────────────────────────────────────
def luhn_checksum(number: str) -> bool:
    """Return True if *number* passes the Luhn check (13-19 digits)."""
    clean = number.replace(" ", "").replace("-", "")
    if not clean.isdigit() or not 13 <= len(clean) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(clean)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ── Shannon entropy ─────────────────────────────────────────────────
def shannon_entropy(data: str) -> float:
    """Shannon entropy in bits."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# ── Compiled patterns ────────────────────────────────────────────────
_PAN_RE     = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
_AADHAAR_RE = re.compile(r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b")
_CC_RE      = re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b")
_EMAIL_RE   = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_AWS_RE     = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_DELIM_RE   = re.compile(r"[\s=:,;\"'{}\[\]()]+")


def _mk(ftype: str, path: str, lineno: int, raw: str,
         sev: Severity, cls: Classification) -> Finding:
    return Finding(ftype, path, lineno, sev, cls, mask_value(raw))


def detect_line(text: str, path: str, lineno: int) -> list[Finding]:
    """Run every detector on one line of text and return findings."""
    results: list[Finding] = []
    seen_spans: set[tuple[int, int]] = set()

    for m in _PAN_RE.finditer(text):
        results.append(_mk("PAN", path, lineno, m.group(),
                           Severity.MEDIUM, Classification.CONFIDENTIAL))
        seen_spans.add(m.span())

    for m in _AADHAAR_RE.finditer(text):
        if is_valid_aadhaar(m.group()):
            results.append(_mk("Aadhaar", path, lineno, m.group(),
                               Severity.HIGH, Classification.RESTRICTED))
            seen_spans.add(m.span())

    for m in _CC_RE.finditer(text):
        clean = m.group().replace(" ", "").replace("-", "")
        if luhn_checksum(clean):
            results.append(_mk("CreditCard", path, lineno, clean,
                               Severity.HIGH, Classification.RESTRICTED))
            seen_spans.add(m.span())

    for m in _EMAIL_RE.finditer(text):
        results.append(_mk("Email", path, lineno, m.group(),
                           Severity.LOW, Classification.INTERNAL))
        seen_spans.add(m.span())

    for m in _AWS_RE.finditer(text):
        results.append(_mk("AWSAccessKey", path, lineno, m.group(),
                           Severity.HIGH, Classification.RESTRICTED))
        seen_spans.add(m.span())

    # High-entropy tokens — skip spans already claimed by other detectors
    for token in _DELIM_RE.split(text):
        if len(token) >= 20 and shannon_entropy(token) > 4.5:
            start = text.find(token)
            if start >= 0 and not any(s <= start < e for s, e in seen_spans):
                results.append(_mk("HighEntropySecret", path, lineno, token,
                                   Severity.HIGH, Classification.RESTRICTED))
    return results
