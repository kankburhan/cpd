"""
HTTP Upgrade Header Poisoning Detection Module

Detects cache poisoning via HTTP protocol upgrade header confusion.
Malformed or unexpected Upgrade header values can:
  1. Trigger backend errors (400/101/426) that get cached
  2. Cause protocol confusion between cache and origin
  3. Expose backend behavior differences enabling cache key manipulation

Techniques:
- h2c upgrade: Force HTTP/2 cleartext upgrade via Upgrade: h2c
- WebSocket upgrade: Malformed Sec-WebSocket-Key triggers rejected handshake
- Invalid protocol: Arbitrary/deprecated protocol strings cause backend rejection
- Connection hop-by-hop: Mark Upgrade as hop-by-hop to confuse cache stripping

References:
- RFC 7230 Section 6.7 (HTTP/1.1 Upgrade header)
- https://portswigger.net/web-security/request-smuggling/advanced
- https://portswigger.net/research/practical-web-cache-poisoning
"""

import time
import uuid
import random
import hashlib
import asyncio
from typing import Dict, List, Optional

from cpd.http_client import HttpClient
from cpd.logic.baseline import Baseline
from cpd.logic.cache_guard import CacheGuard
from cpd.logic.control import add_cb, control_probe, new_cb, stable_hash
from cpd.utils.logger import logger


class UpgradePoisoner:
    """
    Detects cache poisoning via HTTP Upgrade and protocol-switching header manipulation.

    When caches forward Upgrade headers to origins without including them in the
    cache key, malformed upgrades cause protocol rejections that can be cached
    and served to all subsequent users.
    """

    def __init__(self, baseline: Baseline, safe_headers: Dict[str, str] = None):
        self.baseline = baseline
        self.safe_headers = safe_headers or {}
        self.payload_id = str(uuid.uuid4())[:8]

    async def run(self, client: HttpClient) -> List[Dict]:
        """Execute all Upgrade header poisoning techniques."""
        findings = []

        techniques = [
            self._h2c_upgrade_poison,
            self._websocket_upgrade_poison,
            self._invalid_upgrade_poison,
            self._connection_upgrade_confusion,
        ]

        tasks = [asyncio.create_task(t(client)) for t in techniques]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.debug(f"Upgrade poison technique failed: {result}")
            elif result:
                if isinstance(result, list):
                    findings.extend(result)
                elif isinstance(result, dict):
                    findings.append(result)

        return findings

    async def _h2c_upgrade_poison(self, client: HttpClient) -> Optional[Dict]:
        """
        HTTP/2 Cleartext (h2c) Upgrade Poisoning

        Sends Upgrade: h2c to attempt HTTP/1.1 → HTTP/2 cleartext upgrade.
        If backend responds with 101/426/400 and this response gets cached,
        subsequent regular users receive unexpected protocol responses.

        The cache key typically does not include Upgrade, so the poisoned
        response may be served to all users requesting the same URL.
        """
        cb_name, cb_value = new_cb()
        target_url = add_cb(self.baseline.url, cb_name, cb_value)

        headers = {
            **self.safe_headers,
            "Upgrade": "h2c",
            "Connection": "Upgrade, HTTP2-Settings",
            "HTTP2-Settings": "AAMAAABkAAQAAP__",  # Minimal valid SETTINGS frame
        }

        try:
            poison_resp = await client.request("GET", target_url, headers=headers)
        except Exception:
            return None

        if not poison_resp:
            return None

        # 101 = Switching Protocols, 426 = Upgrade Required, 400 = bad upgrade attempt
        if poison_resp["status"] in [101, 426, 400]:
            verify_resp = await client.request("GET", target_url, headers=self.safe_headers)

            if verify_resp and verify_resp["status"] in [101, 426, 400]:
                is_hit, evidence = CacheGuard.cache_hit_signal(verify_resp)
                if is_hit:
                    return self._make_finding(
                        "UpgradePoisoning-h2c",
                        "HIGH",
                        f"Upgrade: h2c triggered a cached {poison_resp['status']} response. "
                        f"Cache serves protocol upgrade response to regular HTTP users.",
                        {"name": "Upgrade-h2c", "header": "Upgrade", "value": "h2c"},
                        target_url,
                        verify_url=target_url,
                        cached_status=poison_resp["status"],
                        cache_evidence=evidence,
                    )

        # Secondary check: content mismatch caused by h2c upgrade.
        # The reference is a cache-busted control, not Baseline.body_hash -- the
        # latter was captured without our `?cb=`, so on any target that reflects
        # the query string it never matches and every probe looks like a hit.
        control = await control_probe(client, self.baseline.url, self.safe_headers)
        if not control:
            return None
        control_hash, _ = control

        poison_hash = stable_hash(poison_resp.get("body", b""), cb_value)
        if poison_hash != control_hash:
            verify_resp = await client.request("GET", target_url, headers=self.safe_headers)
            if verify_resp:
                verify_hash = stable_hash(verify_resp.get("body", b""), cb_value)
                is_hit, evidence = CacheGuard.cache_hit_signal(verify_resp)
                if verify_hash == poison_hash and is_hit:
                    return self._make_finding(
                        "UpgradePoisoning-h2c-ContentMismatch",
                        "MEDIUM",
                        "Upgrade: h2c altered response content and the modified response was cached.",
                        {"name": "Upgrade-h2c-Content", "header": "Upgrade", "value": "h2c"},
                        target_url,
                        verify_url=target_url,
                        cache_evidence=evidence,
                    )

        return None

    async def _websocket_upgrade_poison(self, client: HttpClient) -> Optional[Dict]:
        """
        WebSocket Upgrade Poisoning

        Sends a malformed WebSocket handshake (invalid Sec-WebSocket-Key) to
        trigger protocol negotiation failure. Some caches forward Upgrade: websocket
        to the backend without including it in the cache key, causing backend
        rejection responses (400/101) to be cached for regular users.
        """
        cache_buster = f"cb={int(time.time())}_{random.randint(1000, 9999)}"
        target_url = self._add_cb(self.baseline.url, cache_buster)

        headers = {
            **self.safe_headers,
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": f"poison{self.payload_id}==",  # Invalid base64 encoding
        }

        try:
            poison_resp = await client.request("GET", target_url, headers=headers)
        except Exception:
            return None

        if not poison_resp:
            return None

        poison_status = poison_resp["status"]

        if poison_status in [400, 426, 101]:
            verify_resp = await client.request("GET", target_url, headers=self.safe_headers)
            if verify_resp and verify_resp["status"] in [400, 426, 101]:
                is_hit, evidence = CacheGuard.cache_hit_signal(verify_resp)
                if is_hit:
                    return self._make_finding(
                        "UpgradePoisoning-WebSocket",
                        "HIGH",
                        f"Malformed WebSocket upgrade (invalid Sec-WebSocket-Key) triggered "
                        f"cached {poison_status} error response.",
                        {
                            "name": "WebSocket-Upgrade-Malformed",
                            "header": "Upgrade",
                            "value": "websocket",
                        },
                        target_url,
                        verify_url=target_url,
                        cached_status=poison_status,
                        cache_evidence=evidence,
                    )

        return None

    async def _invalid_upgrade_poison(self, client: HttpClient) -> List[Dict]:
        """
        Invalid/Arbitrary Upgrade Protocol Poisoning

        Tests how caches handle completely unknown Upgrade protocol values.
        Some CDNs forward without validation; backends reject with 400/426.
        If that rejection gets cached, all users receive error responses.
        """
        findings = []

        invalid_protocols = [
            ("Upgrade-Unknown", f"poison-{self.payload_id}"),
            ("Upgrade-SPDY", "SPDY/3.1"),          # Deprecated protocol
            ("Upgrade-TLS", "TLS/1.0, HTTP/1.1"),  # Unusual cleartext TLS upgrade
            ("Upgrade-HTTP3", "h3"),                # HTTP/3 via cleartext (not valid)
        ]

        for name, protocol in invalid_protocols:
            cache_buster = f"cb={int(time.time())}_{random.randint(1000, 9999)}"
            target_url = self._add_cb(self.baseline.url, cache_buster)

            headers = {
                **self.safe_headers,
                "Upgrade": protocol,
                "Connection": "Upgrade",
            }

            try:
                poison_resp = await client.request("GET", target_url, headers=headers)
            except Exception:
                continue

            if not poison_resp:
                continue

            if poison_resp["status"] in [400, 426]:
                verify_resp = await client.request("GET", target_url, headers=self.safe_headers)
                if not verify_resp:
                    continue

                if verify_resp["status"] in [400, 426]:
                    is_hit, evidence = CacheGuard.cache_hit_signal(verify_resp)
                    if is_hit:
                        findings.append(self._make_finding(
                            "UpgradePoisoning-InvalidProtocol",
                            "MEDIUM",
                            f"Unknown Upgrade protocol '{protocol}' triggered cached "
                            f"{poison_resp['status']} error response.",
                            {"name": name, "header": "Upgrade", "value": protocol},
                            target_url,
                            verify_url=target_url,
                            cached_status=poison_resp["status"],
                            cache_evidence=evidence,
                        ))

        return findings

    async def _connection_upgrade_confusion(self, client: HttpClient) -> Optional[Dict]:
        """
        Connection: Upgrade Hop-by-Hop Confusion

        Marks custom headers as hop-by-hop via Connection: Upgrade, <header>.
        Caches should strip hop-by-hop headers before storing responses. If a
        cache fails to strip them and they leak into the cached response,
        subsequent users receive poisoned content containing the injected values.
        """
        cache_buster = f"cb={int(time.time())}_{random.randint(1000, 9999)}"
        target_url = self._add_cb(self.baseline.url, cache_buster)

        poison_header_name = f"X-Poison-{self.payload_id}"
        poison_marker = f"evil-{self.payload_id}"

        headers = {
            **self.safe_headers,
            "Connection": f"Upgrade, {poison_header_name}",
            "Upgrade": "h2c",
            poison_header_name: poison_marker,
        }

        try:
            poison_resp = await client.request("GET", target_url, headers=headers)
        except Exception:
            return None

        if not poison_resp:
            return None

        # Check if our hop-by-hop header leaked into the response
        if poison_marker in str(poison_resp.get("body", b"")) or \
                poison_marker in str(poison_resp.get("headers", {})):

            verify_resp = await client.request("GET", target_url, headers=self.safe_headers)
            if verify_resp and (
                poison_marker in str(verify_resp.get("body", b"")) or
                poison_marker in str(verify_resp.get("headers", {}))
            ):
                is_hit, evidence = CacheGuard.cache_hit_signal(verify_resp)
                return self._make_finding(
                    "UpgradePoisoning-ConnectionHopByHop",
                    "HIGH",
                    f"Connection: Upgrade with hop-by-hop custom header leaked into cached response. "
                    f"Cache failed to strip hop-by-hop headers before storing the response.",
                    {
                        "name": "Connection-Upgrade-HopByHop",
                        "header": "Connection",
                        "value": f"Upgrade, {poison_header_name}",
                    },
                    target_url,
                    verify_url=target_url,
                    cache_evidence=evidence,
                )

        return None

    def _add_cb(self, url: str, cb: str) -> str:
        """Add cache buster parameter to URL."""
        return f"{url}?{cb}" if "?" not in url else f"{url}&{cb}"

    def _make_finding(self, vuln_type: str, severity: str, details: str,
                      signature: Dict, target_url: str, **kwargs) -> Dict:
        """Create an upgrade poisoning finding dict."""
        return {
            "vulnerability": vuln_type,
            "severity": severity,
            "details": details,
            "signature": signature,
            "url": self.baseline.url,
            "target_url": target_url,
            "payload_id": self.payload_id,
            "technique_type": "upgrade_poison",
            **kwargs,
        }
