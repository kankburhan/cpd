"""
Regression tests for the cache-buster / baseline mismatch false-positive class.

Reproduces the real-world case that motivated cpd/logic/control.py: a Drupal 11
page that echoes the query string back into `drupal-settings-json`. Every probe
appends its own `?cb=...`, so every probe body differs from the clean-URL
baseline -- which used to make all five Accept signatures fire at HIGH on a
target where the Accept header provably does nothing.
"""

import hashlib
import re

import pytest

from cpd.logic.control import add_cb, control_probe, new_cb, stable_hash
from cpd.logic.exotic_poisoning import ExoticPoisoner


class ReflectingBaseline:
    """Baseline captured on the clean URL, exactly as BaselineAnalyzer does."""

    def __init__(self, url="https://example.com/agences/agence-de-annecy"):
        self.url = url
        self.body = render(None)
        self.body_hash = hashlib.sha256(self.body).hexdigest()
        self.status = 200
        self.headers = {"Content-Type": "text/html", "X-Drupal-Cache": "HIT"}
        self.content_type = "text/html"


def render(cb_value):
    """Page body that reflects the cb query param, like drupal-settings-json."""
    query = f'{{"cb":"{cb_value}"}}' if cb_value else "{}"
    return f'<html><script>{{"currentQuery":{query}}}</script>body</html>'.encode()


class ReflectingClient:
    """
    Server that reflects `?cb=` into the body and ignores every request header.

    A correct scanner must find nothing here: no header changes the response.
    """

    def __init__(self):
        self.requests = []

    async def request(self, method, url, headers=None, data=None):
        self.requests.append({"method": method, "url": url, "headers": headers})
        match = re.search(r"[?&]cb=([^&]*)", url)
        return {
            "status": 200,
            "headers": {
                "Content-Type": "text/html",
                "X-Drupal-Cache": "HIT",
                "Cache-Control": "max-age=86400, public",
                "Vary": "Cookie",
            },
            "body": render(match.group(1) if match else None),
        }


# --- primitives -------------------------------------------------------------


def test_stable_hash_neutralises_reflected_buster():
    a_name, a_value = new_cb()
    b_name, b_value = new_cb()
    assert a_value != b_value

    # Raw hashes differ purely because of the reflected buster...
    assert hashlib.sha256(render(a_value)).digest() != hashlib.sha256(render(b_value)).digest()
    # ...but the buster-neutralised hashes agree.
    assert stable_hash(render(a_value), a_value) == stable_hash(render(b_value), b_value)


def test_stable_hash_still_sees_real_changes():
    _, value = new_cb()
    original = render(value)
    poisoned = original.replace(b"body", b"<script>alert(1)</script>")
    assert stable_hash(original, value) != stable_hash(poisoned, value)


def test_new_cb_is_fixed_width():
    """A reflected buster must not shift response length between probes."""
    widths = {len(new_cb()[1]) for _ in range(50)}
    assert len(widths) == 1


def test_add_cb_respects_existing_query():
    assert add_cb("https://x.test/a", "cb", "1") == "https://x.test/a?cb=1"
    assert add_cb("https://x.test/a?b=2", "cb", "1") == "https://x.test/a?b=2&cb=1"


@pytest.mark.asyncio
async def test_control_probe_is_buster_stable():
    client = ReflectingClient()
    first = await control_probe(client, "https://example.com/p", {})
    second = await control_probe(client, "https://example.com/p", {})
    assert first and second
    assert first[0] == second[0], "control hash must not depend on the buster value"


# --- the regression itself --------------------------------------------------


@pytest.mark.asyncio
async def test_accept_polymorphism_no_fp_on_query_reflecting_target():
    """
    The la-france-mutualiste.fr case: Accept is provably unkeyed AND has no
    effect, yet the old code reported all five signatures as HIGH.
    """
    poisoner = ExoticPoisoner(ReflectingBaseline(), safe_headers={})
    findings = await poisoner._accept_header_polymorphism(ReflectingClient())
    assert findings == [], f"expected no findings, got {[f['signature']['name'] for f in findings]}"


@pytest.mark.asyncio
async def test_unicode_confusion_no_fp_on_query_reflecting_target():
    poisoner = ExoticPoisoner(ReflectingBaseline(), safe_headers={})
    findings = await poisoner._unicode_normalization_confusion(ReflectingClient())
    assert findings == [], f"expected no findings, got {[f['signature']['name'] for f in findings]}"


@pytest.mark.asyncio
async def test_accept_polymorphism_still_detects_a_real_bug():
    """A genuinely unkeyed Accept that changes one variant must still be caught."""

    class OneVariantVulnerable(ReflectingClient):
        def __init__(self):
            super().__init__()
            self.poisoned_urls = set()

        async def request(self, method, url, headers=None, data=None):
            resp = await super().request(method, url, headers, data)
            accept = (headers or {}).get("Accept", "")
            if accept == "application/json":
                self.poisoned_urls.add(url)
            if url in self.poisoned_urls:
                resp["body"] = resp["body"].replace(b"body", b"POISONED")
            return resp

    poisoner = ExoticPoisoner(ReflectingBaseline(), safe_headers={})
    findings = await poisoner._accept_header_polymorphism(OneVariantVulnerable())

    assert len(findings) == 1
    assert findings[0]["vulnerability"] == "AcceptHeaderPoisoning"
    assert findings[0]["signature"]["value"] == "application/json"


@pytest.mark.asyncio
async def test_accept_polymorphism_saturation_is_suppressed():
    """All variants "working" means the methodology broke, not five bugs."""

    class EverythingLooksVulnerable(ReflectingClient):
        def __init__(self):
            super().__init__()
            self.poisoned_urls = set()

        async def request(self, method, url, headers=None, data=None):
            resp = await super().request(method, url, headers, data)
            if (headers or {}).get("Accept"):
                self.poisoned_urls.add(url)
            if url in self.poisoned_urls:
                resp["body"] = resp["body"].replace(b"body", b"CHANGED")
            return resp

    poisoner = ExoticPoisoner(ReflectingBaseline(), safe_headers={})
    findings = await poisoner._accept_header_polymorphism(EverythingLooksVulnerable())
    assert findings == []


@pytest.mark.asyncio
async def test_no_middleware_param_needs_verify_and_hit():
    """
    Appending a query param changes the body of any query-reflecting site.
    That is not evidence the canonical URL was poisoned.
    """
    from cpd.logic.nextjs_poisoning import NextJsPoisoner

    poisoner = NextJsPoisoner(ReflectingBaseline(), safe_headers={})
    findings = await poisoner._nxtp_parameter_injection(ReflectingClient())
    names = [f["vulnerability"] for f in findings]
    assert "NextJS-PrivateMiddlewareSkip" not in names, names


@pytest.mark.asyncio
async def test_hop_by_hop_probes_do_not_contaminate_each_other():
    """
    One unkeyed header must yield one finding. Sharing a cache-busted URL across
    the five sub-tests let the first poison sit in the cache and be re-read by
    the rest, turning a single bug into five.
    """
    poisoner = ExoticPoisoner(ReflectingBaseline(), safe_headers={})

    class OnlyXfhIsUnkeyed(ReflectingClient):
        """Reflects X-Forwarded-Host only; caches per URL, ignoring headers."""

        def __init__(self):
            super().__init__()
            self.cache = {}

        async def request(self, method, url, headers=None, data=None):
            resp = await super().request(method, url, headers, data)
            if url not in self.cache:
                xfh = (headers or {}).get("X-Forwarded-Host", "lab.local")
                self.cache[url] = resp["body"].replace(b"body", xfh.encode())
            resp["body"] = self.cache[url]
            return resp

    findings = await poisoner._connection_hop_by_hop(OnlyXfhIsUnkeyed())
    headers_flagged = [f["signature"]["value"] for f in findings]
    assert len(findings) == 1, headers_flagged
    assert "X-Forwarded-Host" in headers_flagged[0]


def test_normalization_ignores_followed_redirects():
    """
    An uppercase variant that 301s to the canonical URL is the redirect
    working, not a cache-key collision.
    """
    from cpd.logic.normalization import NormalizationTester

    t = NormalizationTester()
    canonical = "https://example.com/agences/agence-de-annecy"

    # Redirected away from the requested path -> not a collision.
    assert t._followed_redirect("https://EXAMPLE.COM/AGENCES/AGENCE-DE-ANNECY", canonical)
    # Host/scheme case is normalised by the client, so that alone is not a redirect.
    assert not t._followed_redirect("HTTPS://EXAMPLE.COM/agences/agence-de-annecy", canonical)
    # Same URL back -> no redirect.
    assert not t._followed_redirect(canonical, canonical)
    # Cross-host redirect.
    assert t._followed_redirect(canonical, "https://other.example.net/agences/agence-de-annecy")
    # Missing final URL must not be treated as a redirect.
    assert not t._followed_redirect(canonical, "")


@pytest.mark.asyncio
async def test_accept_polymorphism_requires_cache_hit():
    """Content change without a cache hit is origin behaviour, not poisoning."""

    class ChangesButNeverCaches(ReflectingClient):
        async def request(self, method, url, headers=None, data=None):
            resp = await super().request(method, url, headers, data)
            resp["headers"] = {"Content-Type": "text/html", "Cache-Control": "no-store"}
            if (headers or {}).get("Accept") == "application/json":
                resp["body"] = resp["body"].replace(b"body", b"JSONISH")
            return resp

    poisoner = ExoticPoisoner(ReflectingBaseline(), safe_headers={})
    findings = await poisoner._accept_header_polymorphism(ChangesButNeverCaches())
    assert findings == []
