# datascan

A lightweight Python CLI that scans files and directories for sensitive data patterns.

## What It Does

`datascan` recursively scans text files and detects:

| Pattern | Validation | Severity | Classification |
|---------|-----------|----------|----------------|
| **PAN** (Indian Permanent Account Number) | Regex `[A-Z]{5}[0-9]{4}[A-Z]` | Medium | Confidential |
| **Aadhaar** (12-digit Indian ID) | Verhoeff checksum | High | Restricted |
| **Credit card** numbers | Luhn algorithm (13-19 digits) | High | Restricted |
| **Email addresses** | Regex | Low | Internal |
| **AWS access keys** | `AKIA` prefix + 16 alphanumeric | High | Restricted |
| **High-entropy secrets** | Shannon entropy > 4.5 on 20+ char tokens | High | Restricted |

Every finding stores only a **masked preview** (e.g. `AK****************LE`) — the raw value is never retained.

## Installation

```bash
pip install -e .
```

## Usage

```bash
# Scan a directory (rich table output)
datascan ./src

# Scan a single file, output JSON
datascan config.yaml --json

# Run as a Python module
python -m datascan ./data --json
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No high-severity findings |
| `1` | One or more high-severity findings detected |
| `2` | Target path not found |

## Project Structure

```
datascan/
├── __init__.py       # Package version
├── __main__.py       # python -m datascan entry
├── detectors.py      # All detection logic (regex, checksums, entropy)
└── scanner.py        # File walking, CLI, rich/JSON output
tests/
├── test_datascan.py  # Full test suite
└── sample_data/      # Synthetic test fixtures (FAKE data only)
.github/workflows/
└── ci.yml            # pytest + bandit + pip-audit
```

## Running Tests

```bash
pip install -e . pytest
pytest -v
```

## CI Pipeline

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs on every push and PR:

1. **pytest** — unit and integration tests
2. **bandit** — static security analysis of the `datascan/` package
3. **pip-audit** — checks installed dependencies for known vulnerabilities

## Limitations

- Regex-based detection; does not parse ASTs, binary formats, or archives.
- Files larger than 1 MB and binary files are skipped.
- High-entropy detection may produce false positives on legitimate encoded data (e.g. base64 blobs).
- PAN detection relies on format matching only (no issuing-authority validation).
- Aadhaar uses Verhoeff checksum validation but cannot confirm actual issuance.
- Not a substitute for a full DLP, SIEM, or secrets-management solution.
