"""
Exotic Cache Poisoning Detection Module

Implements "thinking out of the box" detection techniques that catch
vulnerabilities standard tools miss.
"""

import time
import uuid
import random
import hashlib
import asyncio
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta

from cpd.http_client import HttpClient
from cpd.logic.baseline import Baseline
from cpd.logic.cache_guard import CacheGuard
from cpd.utils.logger import logger


class ExoticPoisoner:
    """
    Advanced cache poisoning detection using unpredictable methods.
    """
    
    def __init__(self, baseline: Baseline, safe_headers: Dict[str, str] = None):
        self.baseline = baseline
        self.safe_headers = safe_headers or {}
        self.payload_id = str(uuid.uuid4())[:8]
        
    async def run(self, client: HttpClient) -> List[Dict]:
        """Execute all exotic detection techniques."""
        findings = []
        
        # Run all exotic techniques
        techniques = [
            self._time_based_collision,
            self._http10_downgrade_poison,
            self._accept_header_polymorphism,
            self._connection_hop_by_hop,
            self._early_hints_exploitation,
            self._unicode_normalization_confusion,
            self._fat_post_reflection,
            self._conditional_request_poison,
        ]
        
        tasks = [asyncio.create_task(t(client)) for t in techniques]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                logger.debug(f"Exotic technique failed: {result}")
            elif result:
                if isinstance(result, list):
                    findings.extend(result)
                else:
                    findings.append(result)
                    
        return findings
    
    async def _time_based_collision(self, client: HttpClient) -> Optional[Dict]:
        """
        Time-Based Cache Collision Detection
        
        Manipulates Date/If-Modified-Since headers to force cache key collision
        via time desynchronization between cache layers.
        """
        cache_buster = f"cb={int(time.time())}_{random.randint(1000,9999)}"
        target_url = self._add_cb(self.baseline.url, cache_buster)
        
        # Technique 1: Backdate the request to force stale cache entry
        backdated = "Mon, 01 Jan 2020 00:00:00 GMT"
        headers = {
            **self.safe_headers,
            "Date": backdated,
            "X-Poison-Time": self.payload_id,
        }
        
        poison_resp = await client.request("GET", target_url, headers=headers)
        if not poison_resp:
            return None
            
        # Check if our poison header leaked or response differs
        verify_resp = await client.request("GET", target_url, headers=self.safe_headers)
        if not verify_resp:
            return None
            
        if self.payload_id in str(verify_resp.get('body', b'')):
            return self._make_finding(
                "TimeBasedCacheCollision",
                "HIGH",
                "Date header manipulation caused cache collision. X-Poison-Time header leaked to clean request.",
                {"name": "Date-Backdating", "header": "Date", "value": backdated},
                target_url
            )
            
        return None
    
    async def _http10_downgrade_poison(self, client: HttpClient) -> Optional[Dict]:
        """
        HTTP/1.0 Downgrade Poisoning
        
        Forces HTTP/1.0 responses which may bypass cache key normalization
        since older protocol handling differs between frontend/backend.
        """
        cache_buster = f"cb={int(time.time())}_{random.randint(1000,9999)}"
        target_url = self._add_cb(self.baseline.url, cache_buster)
        
        # Send request implying we only accept HTTP/1.0
        headers = {
            **self.safe_headers,
            "Connection": "close",  # Typical for HTTP/1.0
            "X-Forwarded-Proto": "http",
            "X-HTTP-Version": "1.0",
            "X-Poison-HTTP10": f"downgrade-{self.payload_id}",
        }
        
        poison_resp = await client.request("GET", target_url, headers=headers)
        if not poison_resp:
            return None
            
        # Verify with clean HTTP/1.1 request
        verify_resp = await client.request("GET", target_url, headers=self.safe_headers)
        if not verify_resp:
            return None
            
        poison_marker = f"downgrade-{self.payload_id}"
        if poison_marker in str(verify_resp.get('body', b'')):
            return self._make_finding(
                "HTTP10DowngradePoisoning",
                "HIGH",
                "HTTP/1.0 downgrade attack successful. Protocol confusion caused cache poisoning.",
                {"name": "HTTP10-Downgrade", "header": "X-HTTP-Version", "value": "1.0"},
                target_url
            )
            
        return None
    
    async def _accept_header_polymorphism(self, client: HttpClient) -> List[Dict]:
        """
        Accept Header Polymorphism
        
        Uses edge cases in content negotiation that may be unkeyed but affect response.
        """
        findings = []
        cache_buster = f"cb={int(time.time())}_{random.randint(1000,9999)}"
        target_url = self._add_cb(self.baseline.url, cache_buster)
        
        # Edge case accept headers that might bypass cache or trigger different behavior
        test_cases = [
            # Low quality factor edge case
            ("Accept-Q-Edge", "text/*;q=0.001, */*;q=0"),
            # Invalid MIME type that might get normalized
            ("Accept-Invalid", f"text/html-{self.payload_id}"),
            # Wildcard with embedded payload (some parsers are lenient)
            ("Accept-Wildcard-XSS", f"*/*; {self.payload_id}"),
            # Content type confusion
            ("Accept-JSON-Override", "application/json"),
            # Range request confusion (bytes range in accept)
            ("Accept-Range-Confusion", "multipart/byteranges"),
        ]
        
        for name, accept_value in test_cases:
            headers = {**self.safe_headers, "Accept": accept_value}
            poison_resp = await client.request("GET", target_url, headers=headers)
            
            if not poison_resp:
                continue
                
            # Check if accept affects content but is unkeyed
            verify_resp = await client.request("GET", target_url, headers=self.safe_headers)
            if not verify_resp:
                continue
                
            # If verify response differs from baseline AND matches poison, it's cached
            poison_hash = hashlib.sha256(poison_resp.get('body', b'')).hexdigest()
            verify_hash = hashlib.sha256(verify_resp.get('body', b'')).hexdigest()
            baseline_hash = self.baseline.body_hash
            
            if verify_hash == poison_hash and verify_hash != baseline_hash:
                findings.append(self._make_finding(
                    "AcceptHeaderPoisoning",
                    "HIGH",
                    f"Accept header '{accept_value[:50]}' is unkeyed but affects cached response.",
                    {"name": name, "header": "Accept", "value": accept_value},
                    target_url
                ))
                
        return findings
    
    async def _connection_hop_by_hop(self, client: HttpClient) -> List[Dict]:
        """
        Connection Header Hop-by-Hop Poisoning
        
        Exploits hop-by-hop header stripping differences between cache and origin.
        """
        findings = []
        cache_buster = f"cb={int(time.time())}_{random.randint(1000,9999)}"
        target_url = self._add_cb(self.baseline.url, cache_buster)
        
        # Headers to try marking as hop-by-hop (cache may strip them but origin uses them)
        hop_by_hop_tests = [
            ("Conn-XFH", "Connection", "X-Forwarded-Host"),
            ("Conn-XFF", "Connection", "X-Forwarded-For"),
            ("Conn-Cookie", "Connection", "Cookie"),
            ("Conn-XOrigURL", "Connection", "X-Original-URL"),
            ("Conn-Auth", "Connection", "Authorization"),
        ]
        
        for name, conn_header, target_header in hop_by_hop_tests:
            # Send with Connection header trying to mark target_header as hop-by-hop
            poison_value = f"evil-{self.payload_id}.com"
            headers = {
                **self.safe_headers,
                conn_header: f"close, {target_header}",
                target_header: poison_value,
            }
            
            poison_resp = await client.request("GET", target_url, headers=headers)
            if not poison_resp:
                continue
                
            # Check if poison value reflected
            if poison_value in str(poison_resp.get('body', b'')):
                # Now verify if it's cached
                verify_resp = await client.request("GET", target_url, headers=self.safe_headers)
                if verify_resp and poison_value in str(verify_resp.get('body', b'')):
                    findings.append(self._make_finding(
                        "HopByHopPoisoning",
                        "CRITICAL",
                        f"Connection header used to mark {target_header} as hop-by-hop. Cache stripped it, origin processed it.",
                        {"name": name, "header": conn_header, "value": f"close, {target_header}"},
                        target_url,
                        extra_header={target_header: poison_value}
                    ))
                    
        return findings
    
    async def _early_hints_exploitation(self, client: HttpClient) -> Optional[Dict]:
        """
        Early Hints (103) Poisoning
        
        Exploits HTTP 103 Early Hints to inject preload resources.
        Note: Requires server to support/reflect Link header.
        """
        cache_buster = f"cb={int(time.time())}_{random.randint(1000,9999)}"
        target_url = self._add_cb(self.baseline.url, cache_buster)
        
        # Try to inject a malicious preload via Link header
        evil_script = f"https://evil-{self.payload_id}.com/pwned.js"
        headers = {
            **self.safe_headers,
            "Link": f"<{evil_script}>; rel=preload; as=script",
        }
        
        poison_resp = await client.request("GET", target_url, headers=headers)
        if not poison_resp:
            return None
            
        # Check if Link header is reflected in response
        resp_headers = poison_resp.get('headers', {})
        if 'Link' in resp_headers and self.payload_id in resp_headers['Link']:
            # Verify it's cached
            verify_resp = await client.request("GET", target_url, headers=self.safe_headers)
            if verify_resp:
                verify_headers = verify_resp.get('headers', {})
                if 'Link' in verify_headers and self.payload_id in verify_headers['Link']:
                    return self._make_finding(
                        "EarlyHintsPoisoning",
                        "CRITICAL",
                        "Link header injection persisted in cache. Can preload malicious scripts.",
                        {"name": "Early-Hint-103-Link", "header": "Link", "value": headers["Link"]},
                        target_url
                    )
                    
        # Also check if reflected in body (some frameworks embed Link in HTML)
        if evil_script in str(poison_resp.get('body', b'')):
            verify_resp = await client.request("GET", target_url, headers=self.safe_headers)
            if verify_resp and evil_script in str(verify_resp.get('body', b'')):
                return self._make_finding(
                    "LinkHeaderReflectionPoisoning",
                    "CRITICAL",
                    "Link header reflected in body and cached. XSS via resource injection possible.",
                    {"name": "Link-Header-Reflect", "header": "Link", "value": headers["Link"]},
                    target_url
                )
                
        return None
    
    async def _unicode_normalization_confusion(self, client: HttpClient) -> List[Dict]:
        """
        Unicode Normalization Confusion
        
        Uses homoglyph characters that normalize differently across cache/origin.
        """
        findings = []
        
        # Unicode variants that might normalize to common characters
        # These might bypass cache key comparison but resolve to same resource
        unicode_tests = [
            # Slash variants
            ("Unicode-Slash-Fraction", "/\u2044", "/"),  # ⁄ (fraction slash)
            ("Unicode-Slash-Division", "/\u2215", "/"),  # ∕ (division slash)
            # Dot variants
            ("Unicode-Dot-Full", ".\u3002", "."),  # 。 (ideographic full stop)
            # Case-folding edge cases
            ("Unicode-Case-Kelvin", "K\u212A", "K"),  # K vs KELVIN SIGN
            # Path traversal via unicode
            ("Unicode-Dot-Dot", "\u2025", ".."),  # ‥ (two dot leader)
        ]
        
        import urllib.parse
        parsed = urllib.parse.urlparse(self.baseline.url)
        
        for name, unicode_val, normalized in unicode_tests:
            if parsed.path and len(parsed.path) > 1:
                # Create path with unicode variant
                mal_path = parsed.path.replace(normalized[0], unicode_val[1:] if len(unicode_val) > 1 else unicode_val, 1)
                cache_buster = f"cb={int(time.time())}_{random.randint(1000,9999)}"
                
                mal_url = f"{parsed.scheme}://{parsed.netloc}{mal_path}"
                if parsed.query:
                    mal_url += f"?{parsed.query}&{cache_buster}"
                else:
                    mal_url += f"?{cache_buster}"
                    
                verify_url = self._add_cb(self.baseline.url, cache_buster)
                
                # Prime with unicode path
                poison_resp = await client.request("GET", mal_url, headers=self.safe_headers)
                if not poison_resp:
                    continue
                    
                # Verify with normalized path
                verify_resp = await client.request("GET", verify_url, headers=self.safe_headers)
                if not verify_resp:
                    continue
                    
                # If we get a cache HIT with different path, we have confusion
                is_hit, evidence = CacheGuard.cache_hit_signal(verify_resp)
                
                if is_hit:
                    poison_hash = hashlib.sha256(poison_resp.get('body', b'')).hexdigest()
                    verify_hash = hashlib.sha256(verify_resp.get('body', b'')).hexdigest()
                    
                    if poison_hash == verify_hash and verify_hash != self.baseline.body_hash:
                        findings.append(self._make_finding(
                            "UnicodeNormalizationPoisoning",
                            "HIGH",
                            f"Unicode path {repr(unicode_val)} normalized to {repr(normalized)} at cache but treated differently by origin.",
                            {"name": name, "type": "path", "mutation": "unicode", "value": unicode_val},
                            mal_url
                        ))
                        
        return findings
    
    async def _fat_post_reflection(self, client: HttpClient) -> Optional[Dict]:
        """
        Fat POST Reflection (POST-as-GET Cache Poisoning)
        
        Some frameworks reflect POST body in GET responses if cached incorrectly.
        """
        cache_buster = f"cb={int(time.time())}_{random.randint(1000,9999)}"
        target_url = self._add_cb(self.baseline.url, cache_buster)
        
        # Send POST with poison body
        poison_body = f"callback=evil_{self.payload_id}&x=1"
        headers = {
            **self.safe_headers,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        
        poison_resp = await client.request("POST", target_url, headers=headers, data=poison_body)
        if not poison_resp:
            return None
            
        # If POST response contains our payload
        if self.payload_id not in str(poison_resp.get('body', b'')):
            return None
            
        # Check if GET now serves poisoned content
        verify_resp = await client.request("GET", target_url, headers=self.safe_headers)
        if not verify_resp:
            return None
            
        if self.payload_id in str(verify_resp.get('body', b'')):
            return self._make_finding(
                "FatPOSTCachePoisoning",
                "CRITICAL",
                "POST body reflected in cached GET response. Request method not in cache key.",
                {"name": "Fat-POST", "type": "fat_post", "header": "Content-Type", "value": "application/x-www-form-urlencoded"},
                target_url,
                request_body=poison_body
            )
            
        return None
    
    async def _conditional_request_poison(self, client: HttpClient) -> List[Dict]:
        """
        Conditional Request Poisoning
        
        Exploits If-Modified-Since, If-None-Match, etc. to poison cache state.
        """
        findings = []
        cache_buster = f"cb={int(time.time())}_{random.randint(1000,9999)}"
        target_url = self._add_cb(self.baseline.url, cache_buster)
        
        # Test conditional headers
        conditional_tests = [
            # Future date - should get 304 but might poison
            ("IMS-Future", "If-Modified-Since", "Wed, 01 Jan 2099 00:00:00 GMT"),
            # Epoch date - forces fresh response
            ("IMS-Epoch", "If-Modified-Since", "Thu, 01 Jan 1970 00:00:00 GMT"),
            # Fake ETag
            ("INM-Fake", "If-None-Match", f'"{self.payload_id}"'),
            # Wildcard ETag
            ("INM-Wildcard", "If-None-Match", "*"),
            # Range with poison
            ("Range-Zero", "Range", "bytes=0-0"),
            ("Range-Negative", "Range", "bytes=-1"),
        ]
        
        for name, header, value in conditional_tests:
            headers = {**self.safe_headers, header: value}
            
            poison_resp = await client.request("GET", target_url, headers=headers)
            if not poison_resp:
                continue
                
            # If we got a 304 or 206, check if subsequent requests are affected
            if poison_resp['status'] in [304, 206]:
                verify_resp = await client.request("GET", target_url, headers=self.safe_headers)
                if not verify_resp:
                    continue
                    
                # If verify gives unexpected status, we have confusion
                if verify_resp['status'] != self.baseline.status:
                    findings.append(self._make_finding(
                        "ConditionalRequestPoisoning",
                        "MEDIUM",
                        f"{header} header affected cache state. Status changed from {self.baseline.status} to {verify_resp['status']}.",
                        {"name": name, "header": header, "value": value},
                        target_url
                    ))
                    
        return findings
    
    def _add_cb(self, url: str, cb: str) -> str:
        """Add cache buster to URL."""
        return f"{url}?{cb}" if '?' not in url else f"{url}&{cb}"
    
    def _make_finding(self, vuln_type: str, severity: str, details: str, 
                      signature: Dict, target: str, **kwargs) -> Dict:
        """Create a finding dict with POC information."""
        return {
            "vulnerability": vuln_type,
            "severity": severity,
            "details": details,
            "signature": signature,
            "url": self.baseline.url,
            "target_url": target,
            "payload_id": self.payload_id,
            "technique_type": "exotic",
            **kwargs
        }
