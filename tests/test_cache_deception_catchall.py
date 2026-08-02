"""
Regression tests for the catch-all / non-cacheable false positives in
cache_deception_v2.

Both reproduce a real scan of an Imperva-protected site, which reported five
HIGH CacheDeceptionV2-PathTraversal findings when the WAF was in fact serving
one identical challenge page for every path, marked no-cache, no-store.
"""

import hashlib

import pytest
from unittest.mock import AsyncMock, MagicMock

from cpd.logic.baseline import Baseline
from cpd.logic.cache_deception_v2 import CacheDeceptionV2

# The actual Imperva interstitial served for every path on the observed target.
WAF_PAGE = (
    b'<html>\n<head>\n<META NAME="robots" CONTENT="noindex,nofollow">\n'
    b'<script src="/_Incapsula_Resource?SWJIYLWA=5074a744"></script>\n'
    b"</head><body></body></html>"
)
REAL_PAGE = b"<html><body>Genuine authenticated account page with real content.</body></html>"

NO_STORE = {"Content-Type": "text/html", "Cache-Control": "no-cache, no-store"}
PUBLIC = {"Content-Type": "text/html", "Cache-Control": "public, max-age=60"}


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.request = AsyncMock()
    return client


@pytest.fixture
def baseline():
    return Baseline(
        url="https://example.com/remerciements-formulaires",
        status=200,
        headers=dict(NO_STORE),
        body_hash=hashlib.sha256(WAF_PAGE).hexdigest(),
        body=WAF_PAGE,
    )


def _resp(body, headers):
    return {"status": 200, "headers": dict(headers), "body": body,
            "url": "https://example.com/x"}


@pytest.mark.asyncio
async def test_waf_interstitial_produces_no_findings(mock_client, baseline):
    """
    Every path returns the same WAF page, so a body match proves nothing.
    This is the exact shape that produced five false HIGH findings.
    """
    mock_client.request.return_value = _resp(WAF_PAGE, NO_STORE)

    findings = await CacheDeceptionV2(baseline).run(mock_client)

    assert findings == []


@pytest.mark.asyncio
async def test_catch_all_detected_before_spending_probes(mock_client, baseline):
    """The negative control must short-circuit the module, not just filter output."""
    mock_client.request.return_value = _resp(WAF_PAGE, NO_STORE)
    probe = CacheDeceptionV2(baseline)

    await probe.run(mock_client)

    # One shared control probe + one nonexistent-path probe, then bail. Without
    # the guard this module fires dozens of mutation requests.
    assert mock_client.request.call_count == 2


@pytest.mark.asyncio
async def test_non_cacheable_traversal_is_not_reported(mock_client, baseline):
    """
    Not a catch-all target, but the matched response is no-store. A response the
    cache may not store cannot be cache deception.
    """
    probe = CacheDeceptionV2(baseline)

    def route(method, url, **kwargs):
        if "cpd-nonexistent" in url:
            # Distinct body -> not a catch-all, module proceeds.
            return _resp(b"<html>404 not found, a genuinely different page</html>", NO_STORE)
        return _resp(WAF_PAGE, NO_STORE)

    mock_client.request.side_effect = route

    findings = await probe._test_path_traversal_static(mock_client)

    assert findings == []


@pytest.mark.asyncio
async def test_cacheable_traversal_is_reported_as_medium(mock_client, baseline):
    """A real match that the cache is allowed to store is still worth reporting."""
    probe = CacheDeceptionV2(baseline)

    def route(method, url, **kwargs):
        if "cpd-nonexistent" in url:
            return _resp(b"<html>404 not found, a genuinely different page</html>", NO_STORE)
        if "poison" in url:
            return _resp(WAF_PAGE, PUBLIC)
        return _resp(WAF_PAGE, NO_STORE)

    mock_client.request.side_effect = route

    findings = await probe._test_path_traversal_static(mock_client)

    assert len(findings) == 5
    assert all(f["severity"] == "MEDIUM" for f in findings)
    assert all("cacheable" in f["details"] for f in findings)


@pytest.mark.asyncio
async def test_cache_hit_traversal_is_reported_as_high(mock_client, baseline):
    """An actual cache HIT on the traversal path is the strong signal."""
    probe = CacheDeceptionV2(baseline)
    hit = {**PUBLIC, "X-Cache": "HIT"}

    def route(method, url, **kwargs):
        if "cpd-nonexistent" in url:
            return _resp(b"<html>404 not found, a genuinely different page</html>", NO_STORE)
        if "poison" in url:
            return _resp(WAF_PAGE, hit)
        return _resp(WAF_PAGE, NO_STORE)

    mock_client.request.side_effect = route

    findings = await probe._test_path_traversal_static(mock_client)

    assert len(findings) == 5
    assert all(f["severity"] == "HIGH" for f in findings)
    assert all(f["cache_evidence"] for f in findings)


@pytest.mark.asyncio
async def test_genuine_target_still_scanned(mock_client, baseline):
    """A target with a real 404 must not be skipped by the catch-all guard."""
    probe = CacheDeceptionV2(baseline)
    mock_client.request.return_value = _resp(REAL_PAGE, NO_STORE)

    # Control returns REAL_PAGE, nonexistent path returns REAL_PAGE too ->
    # that IS a catch-all. Use distinct bodies to prove the guard is selective.
    def route(method, url, **kwargs):
        if "cpd-nonexistent" in url:
            return _resp(b"<html>genuine 404 page</html>", NO_STORE)
        return _resp(REAL_PAGE, NO_STORE)

    mock_client.request.side_effect = route

    assert await probe._serves_identical_content_for_any_path(mock_client) is False
