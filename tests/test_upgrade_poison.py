"""
Tests for HTTP Upgrade header poisoning detection module.

Tests detection of cache poisoning via protocol upgrade header confusion
(h2c, WebSocket, invalid protocols, hop-by-hop stripping failures).
"""

import pytest
import hashlib
from unittest.mock import AsyncMock, patch

from cpd.logic.upgrade_poison import UpgradePoisoner


class MockBaseline:
    def __init__(self, url="https://example.com/page",
                 body=b"<html>Normal Page Content</html>",
                 status=200):
        self.url = url
        self.body = body
        self.body_hash = hashlib.sha256(body).hexdigest()
        self.status = status
        self.headers = {"Content-Type": "text/html"}
        self.content_type = "text/html"


def make_response(status=200, body=b"<html>Normal Page Content</html>", headers=None):
    return {
        "status": status,
        "headers": headers or {},
        "body": body,
        "url": "https://example.com/page",
    }


# ──────────────────────────────────────────────────────────────────────────────
# h2c Upgrade Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_h2c_detects_cached_426():
    """Should detect when Upgrade: h2c causes cached 426 Upgrade Required response."""
    baseline = MockBaseline()
    poisoner = UpgradePoisoner(baseline)

    client = AsyncMock()
    client.request = AsyncMock(side_effect=[
        make_response(status=426, body=b"Upgrade Required"),
        make_response(status=426, body=b"Upgrade Required", headers={"X-Cache": "HIT"}),
    ])

    with patch("cpd.logic.upgrade_poison.CacheGuard.cache_hit_signal",
               return_value=(True, ["X-Cache: HIT"])):
        finding = await poisoner._h2c_upgrade_poison(client)

    assert finding is not None
    assert finding["vulnerability"] == "UpgradePoisoning-h2c"
    assert finding["severity"] == "HIGH"
    assert finding["technique_type"] == "upgrade_poison"


@pytest.mark.asyncio
async def test_h2c_detects_cached_101():
    """Should detect when Upgrade: h2c causes cached 101 Switching Protocols."""
    baseline = MockBaseline()
    poisoner = UpgradePoisoner(baseline)

    client = AsyncMock()
    client.request = AsyncMock(side_effect=[
        make_response(status=101, body=b""),
        make_response(status=101, body=b"", headers={"X-Cache": "HIT"}),
    ])

    with patch("cpd.logic.upgrade_poison.CacheGuard.cache_hit_signal",
               return_value=(True, ["X-Cache: HIT"])):
        finding = await poisoner._h2c_upgrade_poison(client)

    assert finding is not None
    assert finding["vulnerability"] == "UpgradePoisoning-h2c"


@pytest.mark.asyncio
async def test_h2c_no_finding_if_not_cached():
    """Should not report finding if error response is not cached."""
    baseline = MockBaseline()
    poisoner = UpgradePoisoner(baseline)

    client = AsyncMock()
    # The function makes up to 4 requests:
    # 1. Poison attempt → 426
    # 2. Verify for cached error status → 200 (not cached, passes through)
    # 3. Control probe (cache-busted, clean headers) → baseline content
    # 4. Secondary content-mismatch verify → same baseline body (no mismatch)
    client.request = AsyncMock(side_effect=[
        make_response(status=426, body=b"Upgrade Required"),  # Poison triggers error
        make_response(status=200),                            # Verify is clean (not cached)
        make_response(status=200),                            # Control
        make_response(status=200),                            # Secondary check - baseline content
    ])

    with patch("cpd.logic.upgrade_poison.CacheGuard.cache_hit_signal",
               return_value=(False, [])):
        finding = await poisoner._h2c_upgrade_poison(client)

    assert finding is None


@pytest.mark.asyncio
async def test_h2c_detects_content_mismatch():
    """Should detect content mismatch caused by h2c upgrade (secondary check)."""
    baseline = MockBaseline()
    poisoner = UpgradePoisoner(baseline)

    altered_body = b"<html>Upgrade redirect page</html>"
    client = AsyncMock()
    client.request = AsyncMock(side_effect=[
        make_response(status=200, body=altered_body),  # Different content from h2c
        make_response(status=200),                     # Control (clean headers, cache-busted)
        make_response(status=200, body=altered_body),  # Verify serves same altered content
    ])

    with patch("cpd.logic.upgrade_poison.CacheGuard.cache_hit_signal",
               return_value=(True, ["X-Cache: HIT"])):
        finding = await poisoner._h2c_upgrade_poison(client)

    assert finding is not None
    assert finding["vulnerability"] == "UpgradePoisoning-h2c-ContentMismatch"
    assert finding["severity"] == "MEDIUM"


@pytest.mark.asyncio
async def test_h2c_content_mismatch_needs_cache_hit():
    """
    Altered content that is never actually cached is origin behaviour, not
    poisoning. Without this gate the check fires on any target whose response
    varies for reasons unrelated to the cache.
    """
    baseline = MockBaseline()
    poisoner = UpgradePoisoner(baseline)

    altered_body = b"<html>Upgrade redirect page</html>"
    client = AsyncMock()
    client.request = AsyncMock(side_effect=[
        make_response(status=200, body=altered_body),
        make_response(status=200),
        make_response(status=200, body=altered_body),
    ])

    with patch("cpd.logic.upgrade_poison.CacheGuard.cache_hit_signal",
               return_value=(False, [])):
        finding = await poisoner._h2c_upgrade_poison(client)

    assert finding is None


@pytest.mark.asyncio
async def test_h2c_no_finding_when_normal_response():
    """Should not report if h2c upgrade returns normal 200 with baseline content."""
    baseline = MockBaseline()
    poisoner = UpgradePoisoner(baseline)

    client = AsyncMock()
    # Both requests return the same baseline content — no mismatch
    client.request = AsyncMock(return_value=make_response(status=200))

    finding = await poisoner._h2c_upgrade_poison(client)
    assert finding is None


# ──────────────────────────────────────────────────────────────────────────────
# WebSocket Upgrade Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_websocket_detects_cached_400():
    """Should detect cached 400 from malformed WebSocket key."""
    baseline = MockBaseline()
    poisoner = UpgradePoisoner(baseline)

    client = AsyncMock()
    client.request = AsyncMock(side_effect=[
        make_response(status=400, body=b"Bad Request - invalid WebSocket key"),
        make_response(status=400, body=b"Bad Request", headers={"X-Cache": "HIT"}),
    ])

    with patch("cpd.logic.upgrade_poison.CacheGuard.cache_hit_signal",
               return_value=(True, ["X-Cache: HIT"])):
        finding = await poisoner._websocket_upgrade_poison(client)

    assert finding is not None
    assert finding["vulnerability"] == "UpgradePoisoning-WebSocket"
    assert finding["severity"] == "HIGH"


@pytest.mark.asyncio
async def test_websocket_no_finding_for_normal_200():
    """Should not report WebSocket finding if server returns 200."""
    baseline = MockBaseline()
    poisoner = UpgradePoisoner(baseline)

    client = AsyncMock()
    client.request = AsyncMock(return_value=make_response(status=200))

    finding = await poisoner._websocket_upgrade_poison(client)
    assert finding is None


@pytest.mark.asyncio
async def test_websocket_no_finding_if_not_cached():
    """Should not report WebSocket finding if error is not cached."""
    baseline = MockBaseline()
    poisoner = UpgradePoisoner(baseline)

    client = AsyncMock()
    client.request = AsyncMock(side_effect=[
        make_response(status=400, body=b"Bad Request"),  # Poison
        make_response(status=200),  # Verify is clean
    ])

    with patch("cpd.logic.upgrade_poison.CacheGuard.cache_hit_signal",
               return_value=(False, [])):
        finding = await poisoner._websocket_upgrade_poison(client)

    assert finding is None


# ──────────────────────────────────────────────────────────────────────────────
# Invalid Protocol Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_invalid_protocol_detects_cached_426():
    """Should detect cached 426 from unknown Upgrade protocol."""
    baseline = MockBaseline()
    poisoner = UpgradePoisoner(baseline)

    client = AsyncMock()
    client.request = AsyncMock(side_effect=[
        make_response(status=426, body=b"Upgrade Required"),
        make_response(status=426, body=b"Upgrade Required", headers={"X-Cache": "HIT"}),
    ] * 5)

    with patch("cpd.logic.upgrade_poison.CacheGuard.cache_hit_signal",
               return_value=(True, ["X-Cache: HIT"])):
        findings = await poisoner._invalid_upgrade_poison(client)

    assert len(findings) > 0
    assert findings[0]["vulnerability"] == "UpgradePoisoning-InvalidProtocol"
    assert findings[0]["severity"] == "MEDIUM"


@pytest.mark.asyncio
async def test_invalid_protocol_returns_list():
    """Invalid protocol method should always return a list."""
    baseline = MockBaseline()
    poisoner = UpgradePoisoner(baseline)

    client = AsyncMock()
    client.request = AsyncMock(return_value=make_response(status=200))

    with patch("cpd.logic.upgrade_poison.CacheGuard.cache_hit_signal",
               return_value=(False, [])):
        findings = await poisoner._invalid_upgrade_poison(client)

    assert isinstance(findings, list)


# ──────────────────────────────────────────────────────────────────────────────
# Connection Hop-by-Hop Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_connection_hop_by_hop_detects_leaked_header():
    """Should detect when hop-by-hop header leaks into cached response."""
    baseline = MockBaseline()
    poisoner = UpgradePoisoner(baseline)

    # The payload_id is determined inside the UpgradePoisoner instance.
    # We simulate caching: both the poison request and the verify request
    # return a body containing the poison marker (simulating it being cached).
    poison_marker_placeholder = "evil-"  # partial match, payload_id appended at runtime

    client = AsyncMock()

    # First call (poison): returns body with the marker (simulates backend reflecting it)
    # Second call (verify): also returns body with marker (simulates cached response)
    async def mock_request(method, url, headers=None, **kwargs):
        # Any response that contains the poison marker value
        marker = f"evil-{poisoner.payload_id}"
        return {
            "status": 200,
            "headers": {},
            "body": f"<html>debug: {marker}</html>".encode(),
            "url": url,
        }

    client.request = mock_request

    with patch("cpd.logic.upgrade_poison.CacheGuard.cache_hit_signal",
               return_value=(True, ["X-Cache: HIT"])):
        finding = await poisoner._connection_upgrade_confusion(client)

    assert finding is not None
    assert finding["vulnerability"] == "UpgradePoisoning-ConnectionHopByHop"


@pytest.mark.asyncio
async def test_connection_hop_by_hop_no_finding_when_no_leakage():
    """Should not report if custom header does not leak into response."""
    baseline = MockBaseline()
    poisoner = UpgradePoisoner(baseline)

    client = AsyncMock()
    client.request = AsyncMock(return_value=make_response(status=200))

    with patch("cpd.logic.upgrade_poison.CacheGuard.cache_hit_signal",
               return_value=(False, [])):
        finding = await poisoner._connection_upgrade_confusion(client)

    assert finding is None


# ──────────────────────────────────────────────────────────────────────────────
# Integration / run() Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_returns_list_no_findings():
    """run() should return an empty list when server is not vulnerable."""
    baseline = MockBaseline()
    poisoner = UpgradePoisoner(baseline)

    client = AsyncMock()
    client.request = AsyncMock(return_value=make_response(status=200))

    with patch("cpd.logic.upgrade_poison.CacheGuard.cache_hit_signal",
               return_value=(False, [])):
        findings = await poisoner.run(client)

    assert isinstance(findings, list)
    assert findings == []


@pytest.mark.asyncio
async def test_run_handles_exceptions_gracefully():
    """run() should not raise when client raises exceptions."""
    baseline = MockBaseline()
    poisoner = UpgradePoisoner(baseline)

    client = AsyncMock()
    client.request = AsyncMock(side_effect=Exception("Connection timeout"))

    findings = await poisoner.run(client)
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_run_handles_none_response():
    """run() should not raise when client returns None."""
    baseline = MockBaseline()
    poisoner = UpgradePoisoner(baseline)

    client = AsyncMock()
    client.request = AsyncMock(return_value=None)

    findings = await poisoner.run(client)
    assert isinstance(findings, list)


def test_finding_structure():
    """Verify finding dict has all required fields."""
    baseline = MockBaseline()
    poisoner = UpgradePoisoner(baseline)

    finding = poisoner._make_finding(
        "UpgradePoisoning-h2c",
        "HIGH",
        "Upgrade: h2c triggered a cached 426 response.",
        {"name": "Upgrade-h2c", "header": "Upgrade", "value": "h2c"},
        "https://example.com/page?cb=123",
        verify_url="https://example.com/page?cb=123",
        cached_status=426,
        cache_evidence=["X-Cache: HIT"],
    )

    assert finding["vulnerability"] == "UpgradePoisoning-h2c"
    assert finding["severity"] == "HIGH"
    assert finding["url"] == baseline.url
    assert finding["technique_type"] == "upgrade_poison"
    assert "payload_id" in finding
    assert "cached_status" in finding
