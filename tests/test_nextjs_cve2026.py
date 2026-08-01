import pytest
import hashlib
from unittest.mock import AsyncMock, MagicMock
from cpd.logic.nextjs_poisoning import NextJsPoisoner
from cpd.logic.baseline import Baseline


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.request = AsyncMock()
    return client


@pytest.fixture
def baseline_html():
    body = b"<html><body>Normal HTML page content here for testing</body></html>"
    return Baseline(
        url="http://example.com/dashboard",
        status=200,
        headers={"Content-Type": "text/html"},
        body_hash=hashlib.sha256(body).hexdigest(),
        body=body,
    )


@pytest.fixture
def baseline_redirect():
    body = b""
    return Baseline(
        url="http://example.com/old-page",
        status=307,
        headers={"Content-Type": "text/html", "Location": "/new-page"},
        body_hash=hashlib.sha256(body).hexdigest(),
        body=body,
    )


class TestCVE2026_44572:
    """x-nextjs-data redirect cache poisoning."""

    @pytest.mark.asyncio
    async def test_xnextjs_data_redirect_detected(self, mock_client, baseline_redirect):
        poisoner = NextJsPoisoner(baseline_redirect)

        mock_client.request.side_effect = [
            # Poison: x-nextjs-data causes 200 with x-nextjs-redirect
            {"status": 200, "headers": {"Content-Type": "application/json",
                                         "x-nextjs-redirect": "/new-page"},
             "body": b'{}'},
            # Verify: clean request still gets cached 200
            {"status": 200, "headers": {"Content-Type": "application/json",
                                         "x-nextjs-redirect": "/new-page",
                                         "X-Cache": "HIT"},
             "body": b'{}'},
        ]

        findings = await poisoner._xnextjs_data_redirect_poison(mock_client)
        assert findings is not None
        assert findings["vulnerability"] == "NextJS-XData-RedirectPoisoning"
        assert "CVE-2026-44572" in findings["details"]

    @pytest.mark.asyncio
    async def test_xnextjs_data_no_redirect_safe(self, mock_client, baseline_html):
        poisoner = NextJsPoisoner(baseline_html)

        mock_client.request.side_effect = [
            {"status": 200, "headers": {"Content-Type": "text/html"},
             "body": b"<html>normal</html>"},
        ]

        findings = await poisoner._xnextjs_data_redirect_poison(mock_client)
        assert findings is None


class TestCVE2026_44576:
    """RSC/HTML cache confusion."""

    @pytest.mark.asyncio
    async def test_rsc_cache_confusion_detected(self, mock_client, baseline_html):
        poisoner = NextJsPoisoner(baseline_html)
        rsc_payload = b'0:["$","div",null,{"children":"poisoned"}]'

        mock_client.request.side_effect = [
            # RSC=1: returns RSC payload
            {"status": 200, "headers": {"Content-Type": "text/x-component"},
             "body": rsc_payload},
            # Verify: clean request returns same RSC payload (cached!)
            {"status": 200, "headers": {"Content-Type": "text/x-component",
                                         "X-Cache": "HIT"},
             "body": rsc_payload},
        ]

        findings = await poisoner._rsc_html_cache_confusion(mock_client)
        assert len(findings) == 1
        assert findings[0]["vulnerability"] == "NextJS-RSC-CacheConfusion"
        assert findings[0]["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_rsc_not_cached_safe(self, mock_client, baseline_html):
        poisoner = NextJsPoisoner(baseline_html)
        rsc_payload = b'0:["$","div",null,{}]'
        normal_html = b"<html><body>Normal HTML page content here for testing</body></html>"

        # 3 RSC header variants × 2 requests each (poison + verify)
        mock_client.request.side_effect = [
            {"status": 200, "headers": {"Content-Type": "text/x-component"},
             "body": rsc_payload},
            {"status": 200, "headers": {"Content-Type": "text/html"},
             "body": normal_html},
            {"status": 200, "headers": {"Content-Type": "text/x-component"},
             "body": rsc_payload},
            {"status": 200, "headers": {"Content-Type": "text/html"},
             "body": normal_html},
            {"status": 200, "headers": {"Content-Type": "text/x-component"},
             "body": rsc_payload},
            {"status": 200, "headers": {"Content-Type": "text/html"},
             "body": normal_html},
        ]

        findings = await poisoner._rsc_html_cache_confusion(mock_client)
        assert len(findings) == 0


class TestCVE2026_44575:
    """Middleware bypass via .rsc suffix."""

    @pytest.mark.asyncio
    async def test_rsc_suffix_bypass_detected(self, mock_client, baseline_html):
        poisoner = NextJsPoisoner(baseline_html)

        mock_client.request.side_effect = [
            # .rsc suffix: returns RSC payload with sensitive data
            {"status": 200, "headers": {"Content-Type": "text/x-component"},
             "body": b'0:["$","div",null,{"email":"user@test.com","token":"abc123"}]'},
            # .segments/... suffix
            {"status": 404, "headers": {}, "body": b"not found"},
            # /index.rsc
            {"status": 404, "headers": {}, "body": b"not found"},
        ]

        findings = await poisoner._rsc_suffix_middleware_bypass(mock_client)
        assert len(findings) == 1
        assert findings[0]["vulnerability"] == "NextJS-RSC-MiddlewareBypass"
        assert findings[0]["severity"] == "CRITICAL"
        assert "CVE-2026-44575" in findings[0]["details"]


class TestCVE2026_44574:
    """nxtP parameter injection."""

    @pytest.mark.asyncio
    async def test_nxtp_injection_detected(self, mock_client, baseline_html):
        poisoner = NextJsPoisoner(baseline_html)
        different_body = b"<html><body>Admin panel - completely different content</body></html>"

        mock_client.request.side_effect = [
            # Control probe: cache-busted copy fetched with clean headers
            {"status": 200, "headers": {"Content-Type": "text/html"},
             "body": b"<html><body>Normal HTML page content here for testing</body></html>"},
            # nxtPslug: returns different content
            {"status": 200, "headers": {"Content-Type": "text/html"},
             "body": different_body},
            # Verify: cached different content
            {"status": 200, "headers": {"Content-Type": "text/html", "X-Cache": "HIT"},
             "body": different_body},
            # nxtIslug: normal
            {"status": 200, "headers": {"Content-Type": "text/html"},
             "body": b"<html><body>Normal HTML page content here for testing</body></html>"},
            # __NEXT_PRIVATE_NO_MIDDLEWARE_RUN
            {"status": 200, "headers": {"Content-Type": "text/html"},
             "body": b"<html><body>Normal HTML page content here for testing</body></html>"},
        ]

        findings = await poisoner._nxtp_parameter_injection(mock_client)
        assert len(findings) >= 1
        assert any(f["vulnerability"] == "NextJS-nxtP-CachePoisoning" for f in findings)


class TestCVE2026_44579:
    """next-resume header injection."""

    @pytest.mark.asyncio
    async def test_next_resume_poison_detected(self, mock_client, baseline_html):
        poisoner = NextJsPoisoner(baseline_html)
        different_body = b"<html><body>PPR resume rendered - different content entirely</body></html>"

        mock_client.request.side_effect = [
            # Poison: next-resume causes different content
            {"status": 200, "headers": {"Content-Type": "text/html"},
             "body": different_body},
            # Control probe: cache-busted copy fetched with clean headers
            {"status": 200, "headers": {"Content-Type": "text/html"},
             "body": b"<html><body>Normal HTML page content here for testing</body></html>"},
            # Verify: cached different content
            {"status": 200, "headers": {"Content-Type": "text/html", "X-Cache": "HIT"},
             "body": different_body},
        ]

        findings = await poisoner._next_resume_poison(mock_client)
        assert findings is not None
        assert findings["vulnerability"] == "NextJS-ResumePoisoning"
        assert "CVE-2026-44579" in findings["details"]

    @pytest.mark.asyncio
    async def test_next_resume_cpdos_detected(self, mock_client, baseline_html):
        poisoner = NextJsPoisoner(baseline_html)

        mock_client.request.side_effect = [
            # Poison: next-resume triggers 500
            {"status": 500, "headers": {}, "body": b"Internal Server Error"},
            # Verify: cached 500
            {"status": 500, "headers": {"X-Cache": "HIT"}, "body": b"Internal Server Error"},
        ]

        findings = await poisoner._next_resume_poison(mock_client)
        assert findings is not None
        assert findings["vulnerability"] == "NextJS-Resume-CPDoS"


class TestCVE2026_44581:
    """CSP nonce injection."""

    @pytest.mark.asyncio
    async def test_csp_nonce_injection_detected(self, mock_client, baseline_html):
        poisoner = NextJsPoisoner(baseline_html)
        marker = f"cpd{poisoner.payload_id}"

        mock_client.request.side_effect = [
            # Poison: CSP nonce reflected in body
            {"status": 200, "headers": {"Content-Type": "text/html"},
             "body": f'<script nonce="" onerror="{marker}">'.encode()},
            # Verify: cached with injection
            {"status": 200, "headers": {"Content-Type": "text/html", "X-Cache": "HIT"},
             "body": f'<script nonce="" onerror="{marker}">'.encode()},
        ]

        findings = await poisoner._csp_nonce_reflection(mock_client)
        assert findings is not None
        assert findings["vulnerability"] == "NextJS-CSP-NoncePoisoning"
        assert findings["severity"] == "CRITICAL"


class TestCVE2026_44573:
    """i18n data-route bypass."""

    @pytest.mark.asyncio
    async def test_i18n_bypass_detected(self, mock_client, baseline_html):
        poisoner = NextJsPoisoner(baseline_html)
        # HTML with i18n signals (locales + buildId) and a protected data route
        html_with_i18n = (
            b'<script>__NEXT_DATA__={"buildId":"abc123XYZ","props":{},'
            b'"locales":["en","fr"],"locale":"en"}</script>'
            b'<link rel="alternate" hreflang="fr" href="/fr/dashboard">'
        )

        mock_client.request.side_effect = [
            # Initial fetch to extract buildId + i18n signals
            {"status": 200, "headers": {"Content-Type": "text/html"},
             "body": html_with_i18n},
            # Data-route WITHOUT bypass header → gated (401)
            {"status": 401, "headers": {}, "body": b"Unauthorized"},
            # Data-route WITH x-nextjs-data: 1 → 200 with sensitive props
            {"status": 200, "headers": {"Content-Type": "application/json"},
             "body": b'{"pageProps":{"user":"admin@corp.com","token":"s3cr3t-jwt"}}'},
        ]

        findings = await poisoner._i18n_data_route_bypass(mock_client)
        assert findings is not None
        assert findings["vulnerability"] == "NextJS-i18n-DataRouteBypass"
        assert findings["cve"] == "CVE-2026-44573"
        assert findings["normal_status"] == 401

    @pytest.mark.asyncio
    async def test_i18n_bypass_no_finding_public_route(self, mock_client, baseline_html):
        """Public data routes (200 without bypass header) must NOT be flagged."""
        poisoner = NextJsPoisoner(baseline_html)
        html_with_i18n = (
            b'<script>__NEXT_DATA__={"buildId":"abc123XYZ","props":{},'
            b'"locales":["en","fr"]}</script>'
        )

        mock_client.request.side_effect = [
            {"status": 200, "headers": {"Content-Type": "text/html"},
             "body": html_with_i18n},
            # Data-route accessible without header → public, not a bypass
            {"status": 200, "headers": {"Content-Type": "application/json"},
             "body": b'{"pageProps":{"title":"Home"}}'},
        ]

        findings = await poisoner._i18n_data_route_bypass(mock_client)
        assert findings is None

    @pytest.mark.asyncio
    async def test_i18n_bypass_no_finding_without_i18n(self, mock_client, baseline_html):
        """Sites without i18n config must NOT be flagged."""
        poisoner = NextJsPoisoner(baseline_html)
        # No locale signals in HTML
        html_no_i18n = b'<script>__NEXT_DATA__={"buildId":"abc123XYZ","props":{}}</script>'

        mock_client.request.side_effect = [
            {"status": 200, "headers": {"Content-Type": "text/html"},
             "body": html_no_i18n},
        ]

        findings = await poisoner._i18n_data_route_bypass(mock_client)
        assert findings is None

    @pytest.mark.asyncio
    async def test_i18n_bypass_no_finding_no_sensitive_data(self, mock_client, baseline_html):
        """Gated route that returns only non-sensitive props must NOT be flagged."""
        poisoner = NextJsPoisoner(baseline_html)
        html_with_i18n = (
            b'<script>__NEXT_DATA__={"buildId":"abc123XYZ","locales":["en","fr"]}</script>'
        )

        mock_client.request.side_effect = [
            {"status": 200, "headers": {"Content-Type": "text/html"},
             "body": html_with_i18n},
            # Gated without bypass header
            {"status": 403, "headers": {}, "body": b"Forbidden"},
            # Accessible with bypass header but only public/safe props
            {"status": 200, "headers": {"Content-Type": "application/json"},
             "body": b'{"pageProps":{"title":"Dashboard","menuItems":[]}}'},
        ]

        findings = await poisoner._i18n_data_route_bypass(mock_client)
        assert findings is None


class TestNextJsPoisonerIntegration:
    """Integration test for the full NextJsPoisoner.run()."""

    @pytest.mark.asyncio
    async def test_run_returns_findings(self, mock_client, baseline_html):
        poisoner = NextJsPoisoner(baseline_html)

        mock_client.request.return_value = {
            "status": 200,
            "headers": {"Content-Type": "text/html"},
            "body": b"<html><body>Normal HTML page content here for testing</body></html>",
        }

        findings = await poisoner.run(mock_client)
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_run_handles_connection_errors(self, mock_client, baseline_html):
        poisoner = NextJsPoisoner(baseline_html)
        mock_client.request.return_value = None

        findings = await poisoner.run(mock_client)
        assert isinstance(findings, list)
        assert len(findings) == 0
