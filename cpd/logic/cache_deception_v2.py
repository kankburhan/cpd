"""
Cache Deception v2: URL Parser Confusion Detection Module

Based on 2024 research "Gotta Cache 'em All" (PortSwigger) and the ACM CCS 2024
paper on detecting cache poisoning in the wild, this module tests for mismatches
between how CDN/cache servers and origin servers parse URL path delimiters.

When a CDN interprets a path differently than the origin server, attackers can
trick the cache into storing sensitive authenticated responses as static content,
exposing private data to unauthenticated users (Cache Deception attack).

Attack variants tested:
- Path delimiter confusion: semicolons, null bytes, encoded chars
- Path traversal to static directories
- Double extension confusion (.php.css)
- Matrix parameter (/path;key=value.css) confusion

References:
- https://portswigger.net/research/gotta-cache-em-all
- https://dl.acm.org/doi/10.1145/3658644.3690361
- https://portswigger.net/web-security/web-cache-deception
"""

import time
import uuid
import random
import hashlib
import asyncio
from typing import Dict, List, Optional
from urllib.parse import urlparse

from cpd.http_client import HttpClient
from cpd.logic.baseline import Baseline
from cpd.logic.cache_guard import CacheGuard
from cpd.utils.logger import logger


# Static file extensions that CDNs commonly cache by default
STATIC_EXTENSIONS = [".css", ".js", ".jpg", ".png", ".gif", ".svg", ".woff2", ".ico"]

# Path delimiter characters: (name, delimiter, description)
PATH_DELIMITERS = [
    ("semicolon", ";", "Semicolon — cache sees static suffix, origin strips it"),
    ("encoded-semicolon", "%3B", "Encoded semicolon"),
    ("null-byte", "%00", "Null byte — terminates path at CDN level"),
    ("encoded-hash", "%23", "Encoded fragment — CDN may strip hash and cache"),
    ("encoded-question", "%3F", "Encoded question mark — CDN may treat as query start"),
    ("double-slash", "//", "Double slash — some CDNs normalize, origins preserve"),
    ("backslash", "\\", "Backslash — IIS/Windows path separator confusion"),
    ("encoded-backslash", "%5C", "Encoded backslash"),
    ("newline-lf", "%0A", "Line feed in path — header injection / path confusion"),
    ("dot-suffix", ".", "Trailing dot — some parsers strip, others preserve"),
]


class CacheDeceptionV2:
    """
    URL Parser Confusion-based Cache Deception detection.

    Tests whether path delimiters cause CDN/cache servers to classify dynamic
    pages as static, resulting in private authenticated responses being cached
    publicly and accessible to unauthenticated users.
    """

    def __init__(self, baseline: Baseline, safe_headers: Dict[str, str] = None):
        self.baseline = baseline
        self.safe_headers = safe_headers or {}
        self.payload_id = str(uuid.uuid4())[:8]
        self._parsed = urlparse(baseline.url)

    async def run(self, client: HttpClient) -> List[Dict]:
        """Execute all cache deception v2 detection techniques."""
        findings = []

        tasks = [
            asyncio.create_task(self._test_delimiter_confusion(client)),
            asyncio.create_task(self._test_path_traversal_static(client)),
            asyncio.create_task(self._test_double_extension(client)),
            asyncio.create_task(self._test_matrix_parameter_confusion(client)),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.debug(f"Cache deception v2 technique failed: {result}")
            elif result:
                if isinstance(result, list):
                    findings.extend(result)
                elif isinstance(result, dict):
                    findings.append(result)

        return findings

    async def _test_delimiter_confusion(self, client: HttpClient) -> List[Dict]:
        """
        Test path delimiter characters that cache and origin parse differently.

        A CDN may classify /api/user;.js as a .js static file and cache it publicly,
        while the origin strips the ;.js suffix and returns authenticated user data.
        This exposes sensitive content to unauthenticated attackers.
        """
        findings = []
        path = self._parsed.path or "/"
        scheme_host = f"{self._parsed.scheme}://{self._parsed.netloc}"

        # Test 3 extensions × all delimiters, stop on first finding per delimiter
        for ext in STATIC_EXTENSIONS[:3]:
            for delim_name, delim, description in PATH_DELIMITERS:
                mal_path = path.rstrip("/") + delim + ext
                cb = f"cb={int(time.time())}_{random.randint(1000, 9999)}"
                target_url = f"{scheme_host}{mal_path}?{cb}"

                try:
                    deception_resp = await client.request(
                        "GET", target_url, headers=self.safe_headers
                    )
                except Exception:
                    continue

                if not deception_resp or deception_resp["status"] != 200:
                    continue

                resp_hash = hashlib.sha256(deception_resp.get("body", b"")).hexdigest()
                is_cached, cache_evidence = CacheGuard.cache_hit_signal(deception_resp)
                _, cacheable_reason = CacheGuard.is_cacheable(
                    deception_resp, deception_resp["status"]
                )

                # Strong signal: same body as authenticated endpoint + cache hit
                if resp_hash == self.baseline.body_hash and is_cached:
                    findings.append(self._make_finding(
                        "CacheDeceptionV2-DelimiterConfusion",
                        "CRITICAL",
                        f"Path delimiter '{delim}' ({description}) causes CDN to cache authenticated "
                        f"response as '{ext}' static content. Private data exposed to unauthenticated users "
                        f"via path: {repr(mal_path)}",
                        {
                            "name": f"CacheDeception-{delim_name}-{ext}",
                            "type": "path_delimiter",
                            "delimiter": delim,
                            "extension": ext,
                        },
                        target_url,
                        cache_evidence=cache_evidence,
                    ))
                    break  # One finding per extension per delimiter set

                # Medium signal: cacheable response matching baseline (no explicit hit header)
                elif resp_hash == self.baseline.body_hash and "public" in str(
                    deception_resp.get("headers", {}).get("cache-control", "")
                ).lower():
                    findings.append(self._make_finding(
                        "CacheDeceptionV2-DelimiterConfusion",
                        "HIGH",
                        f"Path delimiter '{delim}' triggers Cache-Control: public on authenticated endpoint. "
                        f"Potential cache deception via {repr(mal_path)}",
                        {
                            "name": f"CacheDeception-{delim_name}-{ext}",
                            "type": "path_delimiter",
                            "delimiter": delim,
                            "extension": ext,
                        },
                        target_url,
                        cache_evidence=cache_evidence,
                    ))
                    break

        return findings

    async def _test_path_traversal_static(self, client: HttpClient) -> List[Dict]:
        """
        Test path traversal to static directories.

        If /api/user/../static/x.css resolves to /static/x.css at the CDN but the
        origin processes /api/user and returns sensitive content, an attacker can
        poison the /api/user cache entry via a static-looking traversal path.
        """
        findings = []
        path = self._parsed.path or "/"
        scheme_host = f"{self._parsed.scheme}://{self._parsed.netloc}"

        traversal_tests = [
            ("traversal-static-css", f"{path}/../static/poison.css"),
            ("traversal-static-js", f"{path}/../assets/poison.js"),
            ("traversal-double-dot-css", f"{path}/..%2Fstatic%2Fpoison.css"),
            ("traversal-encoded-css", f"{path}/%2e%2e/static/poison.css"),
            ("traversal-double-encoded", f"{path}/%252e%252e/static/poison.css"),
        ]

        for name, mal_path in traversal_tests:
            cb = f"cb={int(time.time())}_{random.randint(1000, 9999)}"
            target_url = f"{scheme_host}{mal_path}?{cb}"

            try:
                resp = await client.request("GET", target_url, headers=self.safe_headers)
            except Exception:
                continue

            if not resp or resp["status"] != 200:
                continue

            resp_hash = hashlib.sha256(resp.get("body", b"")).hexdigest()

            if resp_hash == self.baseline.body_hash:
                is_cached, evidence = CacheGuard.cache_hit_signal(resp)

                findings.append(self._make_finding(
                    "CacheDeceptionV2-PathTraversal",
                    "HIGH",
                    f"Path traversal '{mal_path}' returns same content as authenticated endpoint. "
                    f"CDN may cache this under a static-appearing URL, exposing sensitive data.",
                    {"name": name, "type": "path_traversal", "mutation": mal_path},
                    target_url,
                    cache_evidence=evidence,
                ))

        return findings

    async def _test_double_extension(self, client: HttpClient) -> List[Dict]:
        """
        Test double-extension confusion.

        /api/profile.php.css — cache sees the final .css extension (static asset),
        but origin may process .php (dynamic page) and return sensitive content.
        If cached, the authenticated response is publicly accessible.
        """
        findings = []
        path = self._parsed.path or "/"
        scheme_host = f"{self._parsed.scheme}://{self._parsed.netloc}"

        dynamic_extensions = [".php", ".asp", ".aspx", ".cfm", ".do", ".action", ""]

        for dyn_ext in dynamic_extensions:
            for static_ext in STATIC_EXTENSIONS[:2]:
                mal_path = path.rstrip("/") + dyn_ext + static_ext
                cb = f"cb={int(time.time())}_{random.randint(1000, 9999)}"
                target_url = f"{scheme_host}{mal_path}?{cb}"

                try:
                    resp = await client.request("GET", target_url, headers=self.safe_headers)
                except Exception:
                    continue

                if not resp or resp["status"] != 200:
                    continue

                resp_hash = hashlib.sha256(resp.get("body", b"")).hexdigest()

                if resp_hash == self.baseline.body_hash:
                    is_cached, evidence = CacheGuard.cache_hit_signal(resp)

                    if is_cached:
                        findings.append(self._make_finding(
                            "CacheDeceptionV2-DoubleExtension",
                            "HIGH",
                            f"Double extension '{dyn_ext}{static_ext}' causes CDN to classify dynamic page "
                            f"as static '{static_ext}' resource while serving authenticated content.",
                            {
                                "name": f"DoubleExt-{dyn_ext or 'none'}-{static_ext}",
                                "type": "double_extension",
                            },
                            target_url,
                            cache_evidence=evidence,
                        ))

        return findings

    async def _test_matrix_parameter_confusion(self, client: HttpClient) -> List[Dict]:
        """
        Test matrix parameter (;key=value) path confusion.

        Some CDNs strip matrix parameters before computing the cache key and
        classify /api/user;sessionid=x.css as a .css static asset. If the origin
        ignores the matrix parameter and returns the full authenticated response,
        that response gets cached under a publicly cacheable key.
        """
        findings = []
        path = self._parsed.path or "/"
        scheme_host = f"{self._parsed.scheme}://{self._parsed.netloc}"

        matrix_tests = [
            ("matrix-version-css", f"{path};version=1.0.css"),
            ("matrix-session-css", f"{path};sessionid={self.payload_id}.css"),
            ("matrix-format-js", f"{path};format=json.js"),
            ("matrix-type-png", f"{path};type=image.png"),
        ]

        for name, mal_path in matrix_tests:
            cb = f"cb={int(time.time())}_{random.randint(1000, 9999)}"
            target_url = f"{scheme_host}{mal_path}?{cb}"

            try:
                resp = await client.request("GET", target_url, headers=self.safe_headers)
            except Exception:
                continue

            if not resp or resp["status"] != 200:
                continue

            resp_hash = hashlib.sha256(resp.get("body", b"")).hexdigest()

            if resp_hash == self.baseline.body_hash:
                is_cached, evidence = CacheGuard.cache_hit_signal(resp)

                if is_cached:
                    findings.append(self._make_finding(
                        "CacheDeceptionV2-MatrixParameter",
                        "HIGH",
                        f"Matrix parameter path '{mal_path}' causes CDN to cache dynamic content as static. "
                        f"CDN excludes matrix params from cache key; origin responds with full content.",
                        {"name": name, "type": "matrix_parameter", "mutation": mal_path},
                        target_url,
                        cache_evidence=evidence,
                    ))

        return findings

    def _make_finding(self, vuln_type: str, severity: str, details: str,
                      signature: Dict, target_url: str, **kwargs) -> Dict:
        """Create a cache deception v2 finding dict."""
        return {
            "vulnerability": vuln_type,
            "severity": severity,
            "details": details,
            "signature": signature,
            "url": self.baseline.url,
            "target_url": target_url,
            "payload_id": self.payload_id,
            "technique_type": "cache_deception_v2",
            **kwargs,
        }
