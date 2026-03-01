"""
Tests for Cache Deception v2 (URL parser confusion) detection module.

Based on 2024 "Gotta Cache 'em All" research: CDNs and origins parse
path delimiters differently, enabling cache deception on authenticated endpoints.
"""

import pytest
import hashlib
from unittest.mock import AsyncMock, patch

from cpd.logic.cache_deception_v2 import CacheDeceptionV2


class MockBaseline:
    def __init__(self, url="https://example.com/api/profile",
                 body=b'{"user":"admin","email":"admin@example.com"}',
                 status=200):
        self.url = url
        self.body = body
        self.body_hash = hashlib.sha256(body).hexdigest()
        self.status = status
        self.headers = {"Content-Type": "application/json"}
        self.content_type = "application/json"


def make_response(status=200, body=None, headers=None, cached=False):
    if body is None:
        body = b'{"user":"admin","email":"admin@example.com"}'
    h = headers or {}
    if cached:
        h["X-Cache"] = "HIT"
        h["Age"] = "10"
    return {
        "status": status,
        "headers": h,
        "body": body,
        "url": "https://example.com/api/profile",
    }


def make_response_different(status=200):
    """Response with different body (not same as baseline)."""
    return {
        "status": status,
        "headers": {},
        "body": b"<html>Not Found</html>",
        "url": "https://example.com/api/profile",
    }


# ──────────────────────────────────────────────────────────────────────────────
# Delimiter Confusion Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_delimiter_confusion_critical_when_cached():
    """Should detect CRITICAL finding when delimiter causes CDN to cache authenticated response."""
    baseline = MockBaseline()
    detector = CacheDeceptionV2(baseline)

    # Same body as baseline + cache hit
    client = AsyncMock()
    client.request = AsyncMock(return_value=make_response(cached=True))

    with patch("cpd.logic.cache_deception_v2.CacheGuard.cache_hit_signal",
               return_value=(True, ["X-Cache: HIT"])), \
         patch("cpd.logic.cache_deception_v2.CacheGuard.is_cacheable",
               return_value=(True, "public")):
        findings = await detector._test_delimiter_confusion(client)

    assert len(findings) > 0
    finding = findings[0]
    assert finding["vulnerability"].startswith("CacheDeceptionV2")
    assert finding["severity"] == "CRITICAL"
    assert finding["technique_type"] == "cache_deception_v2"


@pytest.mark.asyncio
async def test_delimiter_confusion_high_when_public_no_hit_header():
    """Should detect HIGH finding when Cache-Control: public even without explicit cache hit header."""
    baseline = MockBaseline()
    detector = CacheDeceptionV2(baseline)

    # Same body as baseline, Cache-Control: public but no X-Cache: HIT
    client = AsyncMock()
    client.request = AsyncMock(return_value=make_response(
        headers={"cache-control": "public, max-age=3600"}
    ))

    with patch("cpd.logic.cache_deception_v2.CacheGuard.cache_hit_signal",
               return_value=(False, [])), \
         patch("cpd.logic.cache_deception_v2.CacheGuard.is_cacheable",
               return_value=(True, "public")):
        findings = await detector._test_delimiter_confusion(client)

    assert len(findings) > 0
    assert findings[0]["severity"] == "HIGH"


@pytest.mark.asyncio
async def test_delimiter_confusion_no_finding_when_body_differs():
    """Should not report finding when response body differs from authenticated baseline."""
    baseline = MockBaseline()
    detector = CacheDeceptionV2(baseline)

    # Different body (e.g. 404 page)
    client = AsyncMock()
    client.request = AsyncMock(return_value=make_response_different(status=404))

    with patch("cpd.logic.cache_deception_v2.CacheGuard.cache_hit_signal",
               return_value=(False, [])), \
         patch("cpd.logic.cache_deception_v2.CacheGuard.is_cacheable",
               return_value=(False, "no-store")):
        findings = await detector._test_delimiter_confusion(client)

    assert findings == []


@pytest.mark.asyncio
async def test_delimiter_confusion_no_finding_when_not_200():
    """Should skip non-200 responses."""
    baseline = MockBaseline()
    detector = CacheDeceptionV2(baseline)

    client = AsyncMock()
    client.request = AsyncMock(return_value=make_response(status=404, body=b"Not Found"))

    findings = await detector._test_delimiter_confusion(client)
    assert findings == []


# ──────────────────────────────────────────────────────────────────────────────
# Path Traversal Static Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_path_traversal_static_finds_matching_content():
    """Should detect when traversal path returns same content as authenticated endpoint."""
    baseline = MockBaseline()
    detector = CacheDeceptionV2(baseline)

    client = AsyncMock()
    client.request = AsyncMock(return_value=make_response(cached=True))

    with patch("cpd.logic.cache_deception_v2.CacheGuard.cache_hit_signal",
               return_value=(True, ["X-Cache: HIT"])):
        findings = await detector._test_path_traversal_static(client)

    assert len(findings) > 0
    assert findings[0]["vulnerability"] == "CacheDeceptionV2-PathTraversal"
    assert findings[0]["severity"] == "HIGH"


@pytest.mark.asyncio
async def test_path_traversal_no_finding_for_404():
    """Should not report when traversal returns 404."""
    baseline = MockBaseline()
    detector = CacheDeceptionV2(baseline)

    client = AsyncMock()
    client.request = AsyncMock(return_value=make_response(status=404, body=b"Not Found"))

    with patch("cpd.logic.cache_deception_v2.CacheGuard.cache_hit_signal",
               return_value=(False, [])):
        findings = await detector._test_path_traversal_static(client)

    assert findings == []


# ──────────────────────────────────────────────────────────────────────────────
# Double Extension Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_double_extension_detects_cached_authenticated_response():
    """Should detect when .php.css double extension causes cache deception."""
    baseline = MockBaseline()
    detector = CacheDeceptionV2(baseline)

    client = AsyncMock()
    client.request = AsyncMock(return_value=make_response(cached=True))

    with patch("cpd.logic.cache_deception_v2.CacheGuard.cache_hit_signal",
               return_value=(True, ["X-Cache: HIT"])):
        findings = await detector._test_double_extension(client)

    assert len(findings) > 0
    assert findings[0]["vulnerability"] == "CacheDeceptionV2-DoubleExtension"


@pytest.mark.asyncio
async def test_double_extension_no_finding_without_cache_hit():
    """Should not report if response is not cached."""
    baseline = MockBaseline()
    detector = CacheDeceptionV2(baseline)

    client = AsyncMock()
    client.request = AsyncMock(return_value=make_response(cached=False))

    with patch("cpd.logic.cache_deception_v2.CacheGuard.cache_hit_signal",
               return_value=(False, [])):
        findings = await detector._test_double_extension(client)

    assert findings == []


# ──────────────────────────────────────────────────────────────────────────────
# Matrix Parameter Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_matrix_parameter_detects_cached_response():
    """Should detect when ;version=1.0.css causes CDN to cache dynamic content."""
    baseline = MockBaseline()
    detector = CacheDeceptionV2(baseline)

    client = AsyncMock()
    client.request = AsyncMock(return_value=make_response(cached=True))

    with patch("cpd.logic.cache_deception_v2.CacheGuard.cache_hit_signal",
               return_value=(True, ["X-Cache: HIT"])):
        findings = await detector._test_matrix_parameter_confusion(client)

    assert len(findings) > 0
    assert findings[0]["vulnerability"] == "CacheDeceptionV2-MatrixParameter"


@pytest.mark.asyncio
async def test_matrix_parameter_no_finding_without_cache_hit():
    """Should not report matrix parameter finding if not cached."""
    baseline = MockBaseline()
    detector = CacheDeceptionV2(baseline)

    client = AsyncMock()
    client.request = AsyncMock(return_value=make_response(cached=False))

    with patch("cpd.logic.cache_deception_v2.CacheGuard.cache_hit_signal",
               return_value=(False, [])):
        findings = await detector._test_matrix_parameter_confusion(client)

    assert findings == []


# ──────────────────────────────────────────────────────────────────────────────
# Integration / run() Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_returns_list():
    """run() should always return a list."""
    baseline = MockBaseline()
    detector = CacheDeceptionV2(baseline)

    client = AsyncMock()
    client.request = AsyncMock(return_value=make_response(status=404, body=b"Not Found"))

    with patch("cpd.logic.cache_deception_v2.CacheGuard.cache_hit_signal",
               return_value=(False, [])), \
         patch("cpd.logic.cache_deception_v2.CacheGuard.is_cacheable",
               return_value=(False, "no-store")):
        findings = await detector.run(client)

    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_run_handles_exceptions_gracefully():
    """run() should not raise when client raises exceptions."""
    baseline = MockBaseline()
    detector = CacheDeceptionV2(baseline)

    client = AsyncMock()
    client.request = AsyncMock(side_effect=Exception("Network error"))

    findings = await detector.run(client)
    assert isinstance(findings, list)


def test_finding_structure():
    """Verify finding dict has all required fields."""
    baseline = MockBaseline()
    detector = CacheDeceptionV2(baseline)

    finding = detector._make_finding(
        "CacheDeceptionV2-DelimiterConfusion",
        "CRITICAL",
        "Test details about delimiter confusion",
        {"name": "semicolon-css", "type": "path_delimiter", "delimiter": ";", "extension": ".css"},
        "https://example.com/api/profile;.css?cb=123",
        cache_evidence=["X-Cache: HIT"],
    )

    assert finding["vulnerability"] == "CacheDeceptionV2-DelimiterConfusion"
    assert finding["severity"] == "CRITICAL"
    assert finding["url"] == baseline.url
    assert finding["technique_type"] == "cache_deception_v2"
    assert "payload_id" in finding
    assert "cache_evidence" in finding
