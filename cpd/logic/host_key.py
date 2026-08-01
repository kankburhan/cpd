"""
Host-blind cache key detection.

A cache key that is built from the request path alone -- without the Host
header / authority -- lets one virtual host poison another. An attacker sends a
request for ``/some/path`` carrying ``Host: attacker``, the response is stored
under the path only, and the next visitor asking the real host for the same path
is served the attacker's entry.

This is CVE-2026-2836 in Cloudflare Pingora (all versions < 0.8.0), whose default
cache key implementation used only the URI. Pingora 0.8.0 removes the default
outright and forces the integrator to name the factors their cache varies on.
The same bug shape appears in any hand-rolled reverse-proxy cache, so this
module probes for the behaviour rather than fingerprinting a product.

Detection is behavioural and deliberately conservative. Sending a spoofed Host
and getting a different response proves nothing on its own -- that is just
virtual hosting working. The finding requires the *clean* request to come back
carrying the spoofed host's response, which is only possible if the Host never
entered the cache key.

References:
- https://github.com/cloudflare/pingora/security/advisories/GHSA-f93w-pcj3-rggc
"""

import uuid
from typing import Dict, List, Optional
from urllib.parse import urlparse

from cpd.http_client import HttpClient
from cpd.logic.baseline import Baseline
from cpd.logic.cache_guard import CacheGuard
from cpd.logic.control import add_cb, control_probe, new_cb, stable_hash
from cpd.utils.logger import logger


class HostKeyProbe:
    """Probes whether the Host header participates in the cache key."""

    def __init__(self, baseline: Baseline, safe_headers: Dict[str, str] = None):
        self.baseline = baseline
        self.safe_headers = safe_headers or {}
        self.payload_id = str(uuid.uuid4())[:8]
        self._parsed = urlparse(baseline.url)

    async def run(self, client: HttpClient) -> List[Dict]:
        try:
            finding = await self._host_blind_cache_key(client)
        except Exception as exc:  # a broken probe must not abort the scan
            logger.debug(f"Host-key probe failed: {exc}")
            return []
        return [finding] if finding else []

    async def _host_blind_cache_key(self, client: HttpClient) -> Optional[Dict]:
        # `.example` is reserved by RFC 2606, so this can never collide with a
        # real vhost the operator owns.
        spoof_host = f"cpd-{self.payload_id}.example"

        # 1. Two independent controls. If the endpoint cannot even agree with
        #    itself under identical conditions it is too dynamic to reason about,
        #    and every later comparison would be noise.
        first = await control_probe(client, self.baseline.url, self.safe_headers)
        if not first:
            return None
        second = await control_probe(client, self.baseline.url, self.safe_headers)
        if not second:
            return None
        control_hash, _ = first
        if control_hash != second[0]:
            logger.debug("Host-key probe skipped - endpoint unstable across controls")
            return None

        # 2. Poison attempt: same URL, spoofed authority.
        cb_name, cb_value = new_cb()
        target_url = add_cb(self.baseline.url, cb_name, cb_value)
        probe_resp = await client.request(
            "GET", target_url, headers={**self.safe_headers, "Host": spoof_host}
        )
        if not probe_resp:
            return None
        probe_hash = stable_hash(probe_resp.get("body", b""), cb_value)

        # The origin ignored the spoofed Host, so there is no distinct response
        # to poison anything *with*. Not a finding.
        if probe_hash == control_hash:
            return None

        # 3. Does the clean request now receive the spoofed host's response?
        verify_resp = await client.request("GET", target_url, headers=self.safe_headers)
        if not verify_resp:
            return None
        verify_hash = stable_hash(verify_resp.get("body", b""), cb_value)
        if verify_hash != probe_hash:
            return None

        # 4. Stability: a one-off coincidence is not a cache entry.
        verify_resp_2 = await client.request("GET", target_url, headers=self.safe_headers)
        if not verify_resp_2:
            return None
        if stable_hash(verify_resp_2.get("body", b""), cb_value) != verify_hash:
            logger.debug("Host-key probe ignored - poisoned response not stable")
            return None

        # 5. Drift guard: if a brand-new cache key also serves the probe body,
        #    the site simply changed underneath us and nothing was poisoned.
        fresh = await control_probe(client, self.baseline.url, self.safe_headers)
        if not fresh:
            return None
        if fresh[0] == probe_hash:
            logger.debug("Host-key probe ignored - target drifted, fresh key matches probe")
            return None

        is_hit, evidence = CacheGuard.cache_hit_signal(verify_resp)
        severity = "CRITICAL" if is_hit else "HIGH"

        return {
            "vulnerability": "HostBlindCacheKey",
            "severity": severity,
            "details": (
                f"Clean request served the response produced for spoofed Host "
                f"{spoof_host!r}, so the Host/authority is absent from the cache key. "
                f"Any vhost sharing this cache can poison the others "
                f"(CVE-2026-2836 class; Pingora < 0.8.0 shipped exactly this default)."
            ),
            "signature": {
                "name": "Host-Blind-Cache-Key",
                "header": "Host",
                "value": spoof_host,
                "type": "cache_key",
            },
            "url": self.baseline.url,
            "target_url": target_url,
            "verify_url": target_url,
            "payload_id": self.payload_id,
            "technique_type": "host_key",
            "cve": "CVE-2026-2836",
            "cache_hit": is_hit,
            "cache_evidence": evidence,
        }
