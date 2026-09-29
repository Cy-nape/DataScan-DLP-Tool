"""File scanner and CLI entry-point for datascan."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Sequence

from datascan.detectors import Finding, Severity, detect_line

_MAX_SIZE = 1_048_576  # 1 MB


def _is_binary(path: Path) -> bool:
    """Heuristic: file is binary if the first 1 KiB contains a null byte."""
    try:
        with open(path, "rb") as fh:
            return b"\x00" in fh.read(1024)
    except OSError:
        return True


def scan_file(path: Path) -> list[Finding]:
    """Scan a single text file for sensitive data."""
    try:
        if path.stat().st_size > _MAX_SIZE or _is_binary(path):
            return []
    except OSError:
        return []
    findings: list[Finding] = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for no, line in enumerate(fh, 1):
            findings.extend(detect_line(line, str(path), no))
    return findings


def scan_path(target: Path) -> list[Finding]:
    """Recursively scan *target* (file or directory)."""
    if target.is_file():
        return scan_file(target)
    findings: list[Finding] = []
    for root, _, files in os.walk(target):
        for name in files:
            findings.extend(scan_file(Path(root) / name))
    return findings


# ── Serialisation helpers ────────────────────────────────────────────
def _to_dicts(findings: Sequence[Finding]) -> list[dict[str, object]]:
    return [
        {
            "type": f.finding_type,
            "file": f.file,
            "line": f.line,
            "severity": f.severity.value,
            "classification": f.classification.value,
            "masked_preview": f.masked_preview,
        }
        for f in findings
    ]


def _print_table(findings: Sequence[Finding]) -> None:
    """Pretty-print findings using rich (table goes to stderr)."""
    from rich.console import Console
    from rich.table import Table

    table = Table(title="DataScan Results", show_lines=True)
    for col, style, kw in [
        ("Type", "cyan", {}), ("File", "white", {}),
        ("Line", "white", {"justify": "right"}),
        ("Severity", "bold", {}), ("Class", "magenta", {}),
        ("Preview", "dim", {}),
    ]:
        table.add_column(col, style=style, **kw)

    colors = {"high": "red", "medium": "yellow", "low": "green"}
    for f in findings:
        c = colors.get(f.severity.value, "white")
        table.add_row(
            f.finding_type, f.file, str(f.line),
            f"[{c}]{f.severity.value}[/{c}]",
            f.classification.value, f.masked_preview,
        )

    console = Console(stderr=True)
    console.print(table)
    console.print(f"\n[bold]{len(findings)}[/bold] finding(s).")


# ── CLI ──────────────────────────────────────────────────────────────
def main(argv: Sequence[str] | None = None) -> None:
    """Entry-point: ``datascan <path> [--json]``."""
    ap = argparse.ArgumentParser(
        prog="datascan",
        description="Scan files for sensitive data patterns.",
    )
    ap.add_argument("path", help="File or directory to scan")
    ap.add_argument("--json", action="store_true", dest="json_out",
                    help="Output JSON to stdout")
    args = ap.parse_args(argv)

    target = Path(args.path)
    if not target.exists():
        print(f"Error: {target} not found.", file=sys.stderr)
        sys.exit(2)

    findings = scan_path(target)

    if args.json_out:
        print(json.dumps(_to_dicts(findings), indent=2))
    elif findings:
        _print_table(findings)
    else:
        print("No sensitive data found.", file=sys.stderr)

    sys.exit(1 if any(f.severity == Severity.HIGH for f in findings) else 0)
