"""
Cache Key Analyzer - Identifies unkeyed headers and parameters.

This module helps detect which headers and parameters are NOT included in the 
cache key, making them potential vectors for cache poisoning attacks.
"""
import time
import random
import hashlib
from typing import Dict, List, Tuple, Optional, Set
from cpd.http_client import HttpClient
from cpd.utils.logger import logger


class CacheKeyAnalyzer:
    """Analyzes cache behavior to identify unkeyed inputs."""
    
    # Common headers that may be unkeyed
    CANDIDATE_HEADERS = [
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
        "X-Forwarded-Port",
        "X-Forwarded-Scheme",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Forwarded-For",
        "X-Real-IP",
        "True-Client-IP",
        "CF-Connecting-IP",
        "Fastly-Client-IP",
        "X-Host",
        "X-Forwarded-Server",
        "X-HTTP-Host-Override",
        "X-Original-Host",
        "Origin",
        "Referer",
        "Accept-Language",
        "Accept-Encoding",
        "User-Agent",
        "Cookie",
        "X-Forwarded-Prefix",
    ]
    
    # Common parameters that may be unkeyed
    CANDIDATE_PARAMS = [
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_content",
        "utm_term",
        "fbclid",
        "gclid",
        "msclkid",
        "ref",
        "source",
        "callback",
        "jsonp",
        "cb",
        "_",
    ]
    
    def __init__(self, base_headers: Dict[str, str] = None):
        self.base_headers = base_headers or {}
        self.unkeyed_headers: Set[str] = set()
        self.unkeyed_params: Set[str] = set()
        
    async def analyze(self, client: HttpClient, url: str) -> Dict[str, Set[str]]:
        """
        Analyze the target to identify unkeyed cache inputs.
        
        Returns dict with 'headers' and 'params' sets of unkeyed inputs.
        """
        logger.info(f"Analyzing cache keys for {url}")
        
        # Get baseline
        baseline_resp = await client.request("GET", url, headers=self.base_headers)
        if not baseline_resp:
            return {"headers": set(), "params": set()}
        
        baseline_hash = hashlib.sha256(baseline_resp.get('body', b'')).hexdigest()
        
        # Test headers
        await self._test_headers(client, url, baseline_hash)
        
        # Test params
        await self._test_params(client, url, baseline_hash)
        
        logger.info(f"Found {len(self.unkeyed_headers)} unkeyed headers, {len(self.unkeyed_params)} unkeyed params")
        
        return {
            "headers": self.unkeyed_headers,
            "params": self.unkeyed_params
        }
    
    async def _test_headers(self, client: HttpClient, url: str, baseline_hash: str):
        """Test which headers are unkeyed by comparing responses."""
        cache_buster = f"cb={int(time.time())}_{random.randint(1000,9999)}"
        base_url = f"{url}?{cache_buster}" if '?' not in url else f"{url}&{cache_buster}"
        
        for header in self.CANDIDATE_HEADERS:
            test_value = f"cpd-test-{random.randint(10000,99999)}"
            headers = self.base_headers.copy()
            headers[header] = test_value
            
            # Send request with modified header
            resp1 = await client.request("GET", base_url, headers=headers)
            if not resp1:
                continue
            
            # Send clean request to same cache key
            resp2 = await client.request("GET", base_url, headers=self.base_headers)
            if not resp2:
                continue
            
            # If response changed but cache key is same, header might be unkeyed
            resp1_hash = hashlib.sha256(resp1.get('body', b'')).hexdigest()
            resp2_hash = hashlib.sha256(resp2.get('body', b'')).hexdigest()
            
            # Check if test value reflected in response
            if test_value in str(resp2.get('body', b'')) or test_value in str(resp2.get('headers', {})):
                self.unkeyed_headers.add(header)
                logger.debug(f"Potentially unkeyed header found: {header}")
    
    async def _test_params(self, client: HttpClient, url: str, baseline_hash: str):
        """Test which parameters are unkeyed by comparing responses."""
        cache_buster = f"cb={int(time.time())}_{random.randint(1000,9999)}"
        
        for param in self.CANDIDATE_PARAMS:
            test_value = f"cpd-test-{random.randint(10000,99999)}"
            
            # URL with test param
            test_url = f"{url}?{cache_buster}&{param}={test_value}" if '?' not in url else f"{url}&{cache_buster}&{param}={test_value}"
            
            # Send request with test param
            resp1 = await client.request("GET", test_url, headers=self.base_headers)
            if not resp1:
                continue
            
            # Send clean request (same cache buster, no test param)
            clean_url = f"{url}?{cache_buster}" if '?' not in url else f"{url}&{cache_buster}"
            resp2 = await client.request("GET", clean_url, headers=self.base_headers)
            if not resp2:
                continue
            
            # If both responses are identical AND different from adding the param,
            # the param might be unkeyed
            resp1_hash = hashlib.sha256(resp1.get('body', b'')).hexdigest()
            resp2_hash = hashlib.sha256(resp2.get('body', b'')).hexdigest()
            
            # Check if test value reflected in clean response (indicates caching)
            if test_value in str(resp2.get('body', b'')) or resp1_hash == resp2_hash:
                body_str = str(resp1.get('body', b''))
                if test_value in body_str:
                    self.unkeyed_params.add(param)
                    logger.debug(f"Potentially unkeyed param found: {param}")
    
    def get_priority_signatures(self, unkeyed_inputs: Dict[str, Set[str]]) -> List[str]:
        """
        Get list of signature names that should be prioritized based on unkeyed inputs.
        """
        priority = []
        
        header_mapping = {
            "X-Forwarded-Host": ["X-Forwarded-Host", "Forwarded"],
            "X-Forwarded-Proto": ["X-Forwarded-Proto", "X-Forwarded-Scheme"],
            "X-Original-URL": ["X-Original-URL", "X-Rewrite-URL"],
            "Origin": ["Origin-Reflect"],
            "Referer": ["Referer-Reflect", "Referer-Poison"],
            "User-Agent": ["Valid-User-Agent"],
        }
        
        for header in unkeyed_inputs.get("headers", []):
            if header in header_mapping:
                priority.extend(header_mapping[header])
            else:
                # Generic match
                priority.append(header)
        
        param_mapping = {
            "utm_source": ["Unkeyed-UTM-Source", "Parameter-Pollution"],
            "utm_campaign": ["Unkeyed-UTM-Campaign"],
            "callback": ["Unkeyed-Callback"],
            "jsonp": ["Unkeyed-JSONP"],
        }
        
        for param in unkeyed_inputs.get("params", []):
            if param in param_mapping:
                priority.extend(param_mapping[param])
        
        return priority
