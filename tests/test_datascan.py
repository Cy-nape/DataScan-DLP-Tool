"""datascan test suite."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from datascan.detectors import (
    detect_line,
    is_valid_aadhaar,
    luhn_checksum,
    mask_value,
    shannon_entropy,
    verhoeff_checksum,
)
from datascan.scanner import scan_path

SAMPLE_DIR = Path(__file__).parent / "sample_data"


# ── Luhn ──────────────────────────────────────────────────────────────
class TestLuhn:
    @pytest.mark.parametrize("num", ["4111111111111111", "5500000000000004"])
    def test_valid(self, num: str) -> None:
        assert luhn_checksum(num) is True

    @pytest.mark.parametrize("num", ["4111111111111112", "0000", ""])
    def test_invalid(self, num: str) -> None:
        assert luhn_checksum(num) is False


# ── Verhoeff / Aadhaar ───────────────────────────────────────────────
class TestVerhoeff:
    def test_valid_checksum(self) -> None:
        assert verhoeff_checksum("2363") is True

    def test_invalid_checksum(self) -> None:
        assert verhoeff_checksum("2364") is False

    def test_non_digit(self) -> None:
        assert verhoeff_checksum("23ab") is False

    def test_valid_aadhaar(self) -> None:
        assert is_valid_aadhaar("499118665246") is True

    def test_invalid_aadhaar_bad_digit(self) -> None:
        assert is_valid_aadhaar("499118665247") is False

    def test_aadhaar_starts_with_zero(self) -> None:
        assert is_valid_aadhaar("099118665246") is False

    def test_aadhaar_too_short(self) -> None:
        assert is_valid_aadhaar("49911866") is False


# ── Masking ───────────────────────────────────────────────────────────
class TestMasking:
    def test_raw_never_leaked(self) -> None:
        raw = "4111111111111111"
        assert raw not in mask_value(raw)

    def test_short_fully_masked(self) -> None:
        assert mask_value("abc") == "***"

    def test_preserves_edges(self) -> None:
        m = mask_value("ABCDEFGHIJ")
        assert m.startswith("AB") and m.endswith("IJ")
        assert m == "AB******IJ"

    def test_findings_never_contain_raw(self) -> None:
        raw = "AKIAIOSFODNN7EXAMPLE"
        for f in detect_line(f"key={raw}", "f.txt", 1):
            assert raw not in f.masked_preview


# ── Entropy ───────────────────────────────────────────────────────────
class TestEntropy:
    def test_high_entropy_value(self) -> None:
        assert shannon_entropy("aB3kL9mN2pQ5rT8uV1wX4yZ7") > 4.5

    def test_low_entropy_value(self) -> None:
        assert shannon_entropy("aaaaaaaaaa") < 1.0

    def test_empty_string(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_high_entropy_detected(self) -> None:
        token = "aB3kL9mN2pQ5rT8uV1wX4yZ7"
        findings = detect_line(f"secret={token}", "f.txt", 1)
        assert any(f.finding_type == "HighEntropySecret" for f in findings)


# ── Exit codes ────────────────────────────────────────────────────────
class TestExitCode:
    def test_exit_1_on_high_severity(self, tmp_path: Path) -> None:
        (tmp_path / "s.txt").write_text("key=AKIAIOSFODNN7EXAMPLE\n")
        r = subprocess.run(
            [sys.executable, "-m", "datascan", str(tmp_path), "--json"],
            capture_output=True, text=True,
        )
        assert r.returncode == 1

    def test_exit_0_on_clean_file(self, tmp_path: Path) -> None:
        (tmp_path / "clean.txt").write_text("nothing sensitive here\n")
        r = subprocess.run(
            [sys.executable, "-m", "datascan", str(tmp_path), "--json"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_json_output_parseable(self, tmp_path: Path) -> None:
        (tmp_path / "e.txt").write_text("email: test@example.com\n")
        r = subprocess.run(
            [sys.executable, "-m", "datascan", str(tmp_path), "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(r.stdout)
        assert isinstance(data, list) and data[0]["type"] == "Email"


# ── Sample data integration ──────────────────────────────────────────
class TestSampleData:
    def test_detects_expected_types(self) -> None:
        findings = scan_path(SAMPLE_DIR)
        types = {f.finding_type for f in findings}
        assert {"AWSAccessKey", "Email", "PAN", "CreditCard"}.issubset(types)

    def test_no_raw_values_leaked(self) -> None:
        raw_values = [
            "AKIAIOSFODNN7EXAMPLE",
            "test.user@example.com",
            "4111111111111111",
            "499118665246",
            "ABCDE1234F",
        ]
        for f in scan_path(SAMPLE_DIR):
            for raw in raw_values:
                assert raw not in f.masked_preview, (
                    f"Raw value {raw!r} leaked in finding {f}"
                )
