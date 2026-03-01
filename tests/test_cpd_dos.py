"""
Tests for CPDoS (Cache Poisoned Denial of Service) active detection module.
"""

import pytest
import hashlib
from unittest.mock import AsyncMock, patch

from cpd.logic.cpd_dos import CpDoSDetector


class MockBaseline:
    def __init__(self, url="https://example.com/page", body=b"<html>page</html>", status=200):
        self.url = url
        self.body = body
        self.body_hash = hashlib.sha256(body).hexdigest()
        self.status = status
        self.headers = {"Content-Type": "text/html"}
        self.content_type = "text/html"


def make_response(status=200, body=b"page content", headers=None):
    return {
        "status": status,
        "headers": headers or {},
        "body": body,
        "url": "https://example.com/page",
    }


# ──────────────────────────────────────────────────────────────────────────────
# HHO Attack Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_hho_attack_finds_cached_400():
    """HHO attack should detect cached 400 error triggered by oversized header."""
    baseline = MockBaseline()
    detector = CpDoSDetector(baseline)

    # Alternate poison (400) and verify (400 with cache hit) for each HHO test
    client = AsyncMock()
    client.request = AsyncMock(side_effect=[
        make_response(status=400, body=b"Request Header Too Large"),
        make_response(status=400, body=b"Request Header Too Large", headers={"X-Cache": "HIT"}),
    ] * 10)

    with patch("cpd.logic.cpd_dos.CacheGuard.cache_hit_signal", return_value=(True, ["X-Cache: HIT"])):
        findings = await detector._hho_attack(client)

    assert len(findings) > 0
    assert findings[0]["vulnerability"] == "CPDoS-HHO"
    assert findings[0]["technique_type"] == "cpd_dos"
    assert findings[0]["severity"] == "HIGH"


@pytest.mark.asyncio
async def test_hho_attack_no_finding_when_clean():
    """HHO attack should not report if verify request returns 200 (error not cached)."""
    baseline = MockBaseline()
    detector = CpDoSDetector(baseline)

    client = AsyncMock()
    client.request = AsyncMock(side_effect=[
        make_response(status=400, body=b"error"),  # Poison triggers 400
        make_response(status=200, body=b"OK"),     # Verify is clean (not cached)
    ] * 10)

    with patch("cpd.logic.cpd_dos.CacheGuard.cache_hit_signal", return_value=(False, [])):
        findings = await detector._hho_attack(client)

    assert findings == []


@pytest.mark.asyncio
async def test_hho_attack_no_finding_when_no_error():
    """HHO attack should not report if server accepts oversized headers (returns 200)."""
    baseline = MockBaseline()
    detector = CpDoSDetector(baseline)

    client = AsyncMock()
    client.request = AsyncMock(return_value=make_response(status=200))

    findings = await detector._hho_attack(client)
    assert findings == []


# ──────────────────────────────────────────────────────────────────────────────
# HMC Attack Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_hmc_attack_detects_cached_error():
    """HMC attack should detect cached 400 from meta-character in header."""
    baseline = MockBaseline()
    detector = CpDoSDetector(baseline)

    client = AsyncMock()
    client.request = AsyncMock(side_effect=[
        make_response(status=400, body=b"Bad Request"),
        make_response(status=400, body=b"Bad Request", headers={"X-Cache": "HIT"}),
    ] * 10)

    with patch("cpd.logic.cpd_dos.CacheGuard.cache_hit_signal", return_value=(True, ["X-Cache: HIT"])):
        findings = await detector._hmc_attack(client)

    assert len(findings) > 0
    assert findings[0]["vulnerability"] == "CPDoS-HMC"


@pytest.mark.asyncio
async def test_hmc_attack_no_finding_when_not_cached():
    """HMC attack should not report finding if 400 is not cached."""
    baseline = MockBaseline()
    detector = CpDoSDetector(baseline)

    client = AsyncMock()
    client.request = AsyncMock(side_effect=[
        make_response(status=400),
        make_response(status=200),
    ] * 10)

    with patch("cpd.logic.cpd_dos.CacheGuard.cache_hit_signal", return_value=(False, [])):
        findings = await detector._hmc_attack(client)

    assert findings == []


# ──────────────────────────────────────────────────────────────────────────────
# HCO Attack Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_hco_attack_reports_cached_406():
    """HCO attack should detect cached 406 from malformed Accept-Encoding."""
    baseline = MockBaseline()
    detector = CpDoSDetector(baseline)

    client = AsyncMock()
    client.request = AsyncMock(side_effect=[
        make_response(status=406, body=b"Not Acceptable"),
        make_response(status=406, body=b"Not Acceptable", headers={"Age": "5", "X-Cache": "HIT"}),
    ] * 10)

    with patch("cpd.logic.cpd_dos.CacheGuard.cache_hit_signal", return_value=(True, ["X-Cache: HIT"])):
        findings = await detector._hco_attack(client)

    assert len(findings) > 0
    assert findings[0]["vulnerability"] == "CPDoS-HCO"
    assert findings[0]["severity"] == "MEDIUM"


@pytest.mark.asyncio
async def test_hco_attack_no_finding_for_200():
    """HCO attack should not report if server accepts malformed encodings."""
    baseline = MockBaseline()
    detector = CpDoSDetector(baseline)

    client = AsyncMock()
    client.request = AsyncMock(return_value=make_response(status=200))

    findings = await detector._hco_attack(client)
    assert findings == []


# ──────────────────────────────────────────────────────────────────────────────
# Method DoS Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_method_dos_cached_405():
    """Method DoS should detect cached 405 from forbidden method override."""
    baseline = MockBaseline()
    detector = CpDoSDetector(baseline)

    client = AsyncMock()
    # First pair: CONNECT override → 405 (cached)
    client.request = AsyncMock(side_effect=[
        make_response(status=405, body=b"Method Not Allowed"),
        make_response(status=405, body=b"Method Not Allowed", headers={"X-Cache": "HIT"}),
    ] * 5)

    with patch("cpd.logic.cpd_dos.CacheGuard.cache_hit_signal", return_value=(True, ["X-Cache: HIT"])):
        findings = await detector._method_dos(client)

    assert len(findings) > 0
    assert findings[0]["vulnerability"] == "CPDoS-MethodOverride"
    assert findings[0]["severity"] == "HIGH"


@pytest.mark.asyncio
async def test_method_dos_no_finding_not_cached():
    """Method DoS should not report if 405 is not cached."""
    baseline = MockBaseline()
    detector = CpDoSDetector(baseline)

    client = AsyncMock()
    client.request = AsyncMock(side_effect=[
        make_response(status=405),  # Poison triggers error
        make_response(status=200),  # Verify is clean
    ] * 5)

    with patch("cpd.logic.cpd_dos.CacheGuard.cache_hit_signal", return_value=(False, [])):
        findings = await detector._method_dos(client)

    assert findings == []


# ──────────────────────────────────────────────────────────────────────────────
# Integration / run() Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_returns_list_no_findings():
    """run() should return an empty list when server is not vulnerable."""
    baseline = MockBaseline()
    detector = CpDoSDetector(baseline)

    client = AsyncMock()
    client.request = AsyncMock(return_value=make_response(status=200))

    with patch("cpd.logic.cpd_dos.CacheGuard.cache_hit_signal", return_value=(False, [])):
        findings = await detector.run(client)

    assert isinstance(findings, list)
    assert findings == []


@pytest.mark.asyncio
async def test_run_handles_client_exceptions_gracefully():
    """run() should not raise when HTTP client raises exceptions."""
    baseline = MockBaseline()
    detector = CpDoSDetector(baseline)

    client = AsyncMock()
    client.request = AsyncMock(side_effect=Exception("Connection refused"))

    findings = await detector.run(client)
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_run_handles_none_response():
    """run() should not raise when HTTP client returns None."""
    baseline = MockBaseline()
    detector = CpDoSDetector(baseline)

    client = AsyncMock()
    client.request = AsyncMock(return_value=None)

    findings = await detector.run(client)
    assert isinstance(findings, list)


def test_finding_structure():
    """Verify finding dict has required fields."""
    baseline = MockBaseline()
    detector = CpDoSDetector(baseline)

    finding = detector._make_finding(
        "CPDoS-HHO",
        "HIGH",
        "Test details",
        {"name": "HHO-Test", "header": "X-Test", "value": "A" * 50},
        "https://example.com/page?cb=123",
        verify_url="https://example.com/page?cb=456",
        cached_status=400,
        cache_evidence=["X-Cache: HIT"],
    )

    assert finding["vulnerability"] == "CPDoS-HHO"
    assert finding["severity"] == "HIGH"
    assert finding["url"] == baseline.url
    assert finding["technique_type"] == "cpd_dos"
    assert "payload_id" in finding
    assert "cached_status" in finding
