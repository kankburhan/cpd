"""
Tests for host-blind cache key detection (CVE-2026-2836 class).

The probe issues a fixed sequence of requests, so each test scripts them in
order:
    1. control probe          (clean)
    2. control probe again    (clean, stability check)
    3. poison attempt         (spoofed Host)
    4. verify                 (clean)
    5. verify again           (clean, stability check)
    6. fresh control          (clean, drift guard)
"""

import hashlib

import pytest
from unittest.mock import AsyncMock, MagicMock

from cpd.logic.baseline import Baseline
from cpd.logic.host_key import HostKeyProbe

LEGIT = b"<html><body>Legitimate tenant content, long enough to be real.</body></html>"
SPOOFED = b"<html><body>Attacker tenant content, served for the wrong Host.</body></html>"


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.request = AsyncMock()
    return client


@pytest.fixture
def baseline():
    return Baseline(
        url="http://example.com/page",
        status=200,
        headers={"Content-Type": "text/html"},
        body_hash=hashlib.sha256(LEGIT).hexdigest(),
        body=LEGIT,
    )


def _resp(body, headers=None):
    return {"status": 200, "headers": headers or {}, "body": body, "url": "http://example.com/page"}


@pytest.mark.asyncio
async def test_host_blind_cache_key_detected(mock_client, baseline):
    """Clean request re-serves the spoofed-Host response -> Host is not keyed."""
    probe = HostKeyProbe(baseline)
    mock_client.request.side_effect = [
        _resp(LEGIT),                                # control
        _resp(LEGIT),                                # control (stable)
        _resp(SPOOFED),                              # poison attempt
        _resp(SPOOFED, {"X-Cache": "HIT"}),          # verify -> poisoned
        _resp(SPOOFED, {"X-Cache": "HIT"}),          # verify (stable)
        _resp(LEGIT),                                # fresh key -> unaffected
    ]

    findings = await probe.run(mock_client)

    assert len(findings) == 1
    assert findings[0]["vulnerability"] == "HostBlindCacheKey"
    assert findings[0]["cve"] == "CVE-2026-2836"
    # Cache-hit evidence present, so this is the confirmed-serving case.
    assert findings[0]["severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_no_finding_without_cache_hit_evidence_is_high(mock_client, baseline):
    """Poisoning proven by content but no HIT header -> HIGH, not CRITICAL."""
    probe = HostKeyProbe(baseline)
    mock_client.request.side_effect = [
        _resp(LEGIT),
        _resp(LEGIT),
        _resp(SPOOFED),
        _resp(SPOOFED),
        _resp(SPOOFED),
        _resp(LEGIT),
    ]

    findings = await probe.run(mock_client)

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


@pytest.mark.asyncio
async def test_host_ignored_by_origin_is_not_a_finding(mock_client, baseline):
    """Spoofed Host produced no distinct response, so nothing could be poisoned."""
    probe = HostKeyProbe(baseline)
    mock_client.request.side_effect = [
        _resp(LEGIT),
        _resp(LEGIT),
        _resp(LEGIT),  # poison attempt returns the same content
    ]

    assert await probe.run(mock_client) == []


@pytest.mark.asyncio
async def test_clean_request_unaffected_is_not_a_finding(mock_client, baseline):
    """Host IS in the cache key: the clean request still gets legit content."""
    probe = HostKeyProbe(baseline)
    mock_client.request.side_effect = [
        _resp(LEGIT),
        _resp(LEGIT),
        _resp(SPOOFED),
        _resp(LEGIT),  # verify unaffected -> correctly keyed
    ]

    assert await probe.run(mock_client) == []


@pytest.mark.asyncio
async def test_unstable_endpoint_is_skipped(mock_client, baseline):
    """Two identical control requests disagree -> too dynamic to conclude anything."""
    probe = HostKeyProbe(baseline)
    mock_client.request.side_effect = [
        _resp(b"<html>dynamic one</html>"),
        _resp(b"<html>dynamic two, totally different</html>"),
    ]

    assert await probe.run(mock_client) == []
    # Bailed out before spending a poison attempt.
    assert mock_client.request.call_count == 2


@pytest.mark.asyncio
async def test_site_wide_drift_is_not_reported(mock_client, baseline):
    """A brand-new cache key also serves the probe body -> the site just changed."""
    probe = HostKeyProbe(baseline)
    mock_client.request.side_effect = [
        _resp(LEGIT),
        _resp(LEGIT),
        _resp(SPOOFED),
        _resp(SPOOFED),
        _resp(SPOOFED),
        _resp(SPOOFED),  # fresh key serves it too -> drift, not poisoning
    ]

    assert await probe.run(mock_client) == []


@pytest.mark.asyncio
async def test_transport_failure_is_a_skip_not_a_crash(mock_client, baseline):
    """Losing a response mid-sequence must not abort the scan."""
    probe = HostKeyProbe(baseline)
    mock_client.request.side_effect = [
        _resp(LEGIT),
        _resp(LEGIT),
        None,  # poison attempt failed
    ]

    assert await probe.run(mock_client) == []
