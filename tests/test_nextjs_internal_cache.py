"""
Tests for Next.js internal cache poisoning (CVE-2024-46982).

The technique probes two variants in order, so requests are scripted as:
    1. control probe                    (clean)
    2. x-now-route-matches probe
    3. x-now-route-matches verify       (only if the probe flipped Cache-Control)
    4. __nextDataReq probe
    5. __nextDataReq verify             (only if the probe flipped Cache-Control)
"""

import hashlib

import pytest
from unittest.mock import AsyncMock, MagicMock

from cpd.logic.baseline import Baseline
from cpd.logic.nextjs_poisoning import NextJsPoisoner

SSR_CC = "private, no-cache, no-store, max-age=0, must-revalidate"
SSG_CC = "s-maxage=1, stale-while-revalidate"

HTML = b"<html><body>Server-rendered, per-user content of a decent length.</body></html>"
JSON = b'{"pageProps":{"leaked":"this was meant to be private"},"__N_SSP":true}'


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.request = AsyncMock()
    return client


@pytest.fixture
def baseline():
    return Baseline(
        url="http://example.com/account",
        status=200,
        headers={"Content-Type": "text/html", "Cache-Control": SSR_CC},
        body_hash=hashlib.sha256(HTML).hexdigest(),
        body=HTML,
    )


def _resp(body, cache_control, extra_headers=None):
    headers = {"Content-Type": "text/html", "Cache-Control": cache_control}
    headers.update(extra_headers or {})
    return {"status": 200, "headers": headers, "body": body, "url": "http://example.com/account"}


@pytest.mark.asyncio
async def test_now_route_matches_poisoning_detected(mock_client, baseline):
    """SSR -> SSG flip and the clean request re-serves it from cache."""
    poisoner = NextJsPoisoner(baseline)
    mock_client.request.side_effect = [
        _resp(HTML, SSR_CC),                              # control: not cacheable
        _resp(JSON, SSG_CC),                              # probe: flipped
        _resp(JSON, SSG_CC, {"X-Cache": "HIT"}),          # verify: poisoned + hit
        _resp(HTML, SSR_CC),                              # __nextDataReq probe: no flip
    ]

    findings = await poisoner._internal_ssr_to_ssg_poison(mock_client)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["vulnerability"] == "NextJS-InternalCachePoisoning"
    assert finding["cve"] == "CVE-2024-46982"
    assert finding["severity"] == "CRITICAL"
    assert "x-now-route-matches" in finding["details"]
    assert finding["probe_cache_control"] == SSG_CC


@pytest.mark.asyncio
async def test_flip_without_reserving_is_medium(mock_client, baseline):
    """Cache-Control flipped, but the clean request did not get the entry back."""
    poisoner = NextJsPoisoner(baseline)
    mock_client.request.side_effect = [
        _resp(HTML, SSR_CC),      # control
        _resp(JSON, SSG_CC),      # probe: flipped
        _resp(HTML, SSR_CC),      # verify: unaffected
        _resp(HTML, SSR_CC),      # __nextDataReq probe: no flip
    ]

    findings = await poisoner._internal_ssr_to_ssg_poison(mock_client)

    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert "poisoning is not" in findings[0]["details"]


@pytest.mark.asyncio
async def test_nextdatareq_reported_as_unpatched(mock_client, baseline):
    """The __nextDataReq vector is flagged as outside the CVE's fix."""
    poisoner = NextJsPoisoner(baseline)
    mock_client.request.side_effect = [
        _resp(HTML, SSR_CC),      # control
        _resp(HTML, SSR_CC),      # x-now-route-matches probe: no flip
        _resp(JSON, SSG_CC),      # __nextDataReq probe: flipped
        _resp(JSON, SSG_CC),      # verify: poisoned, no hit header
    ]

    findings = await poisoner._internal_ssr_to_ssg_poison(mock_client)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "HIGH"
    assert finding["cve"] is None
    assert "remains unpatched" in finding["details"]
    assert "__nextDataReq" in finding["details"]


@pytest.mark.asyncio
async def test_already_cacheable_route_is_skipped(mock_client, baseline):
    """A route that is already shared-cacheable has nothing to flip."""
    poisoner = NextJsPoisoner(baseline)
    mock_client.request.side_effect = [_resp(HTML, SSG_CC)]

    assert await poisoner._internal_ssr_to_ssg_poison(mock_client) == []
    # Bailed out after the control, without spending probes.
    assert mock_client.request.call_count == 1


@pytest.mark.asyncio
async def test_no_flip_is_not_a_finding(mock_client, baseline):
    """Neither variant changes Cache-Control -> nothing to report."""
    poisoner = NextJsPoisoner(baseline)
    mock_client.request.side_effect = [
        _resp(HTML, SSR_CC),
        _resp(HTML, SSR_CC),
        _resp(HTML, SSR_CC),
    ]

    assert await poisoner._internal_ssr_to_ssg_poison(mock_client) == []


@pytest.mark.asyncio
async def test_max_age_alone_does_not_count_as_cacheable(mock_client, baseline):
    """
    Only shared-cache directives matter. A plain max-age is browser caching and
    must not be mistaken for the SSG flip.
    """
    poisoner = NextJsPoisoner(baseline)
    mock_client.request.side_effect = [
        _resp(HTML, SSR_CC),
        _resp(JSON, "max-age=60"),   # not a shared-cache directive
        _resp(HTML, SSR_CC),
    ]

    assert await poisoner._internal_ssr_to_ssg_poison(mock_client) == []
