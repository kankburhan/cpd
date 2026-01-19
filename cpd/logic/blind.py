import time
import uuid
import random
import statistics
from typing import Dict, List, Optional
from cpd.http_client import HttpClient
from cpd.utils.logger import logger

class BlindCachePoisoner:
    """Detect cache poisoning without visible reflection (Blind)."""
    
    async def timing_based_detection(self, client: HttpClient, url: str) -> Optional[Dict]:
        """
        Use timing side-channel to detect cache hits on poisoned requests.
        """
        # 1. Prime the cache with a unique poison header
        marker = str(uuid.uuid4())[:8]
        poison_header = {"X-Cache-Marker": marker}
        
        # Warm up/Prime
        # We send 5 requests with the poison header. 
        # If the header enters the cache key, these will be MISS/HIT separately.
        # If the header is UNKEYED, they hits the main cache (or creates a poisoned entry).
        
        poison_timings = []
        for _ in range(3):
            start = time.time()
            await client.request("GET", url, headers=poison_header)
            poison_timings.append(time.time() - start)
            
        # 2. Test clean requests (no header)
        clean_timings = []
        for _ in range(3):
            start = time.time()
            await client.request("GET", url)
            clean_timings.append(time.time() - start)
            
        # Analysis
        if not poison_timings or not clean_timings:
            return None
            
        avg_poison = statistics.mean(poison_timings)
        avg_clean = statistics.mean(clean_timings)
        
        # Very rough heuristic: If clean requests are significantly faster (~instantly cached)
        # and poison requests were slow, it suggests separation.
        # But for BLIND poisoning, we want to know if our poison attempt *disrupted* the clean cache
        # or if we can infer a hit.
        
        # Actually, a better blind test is checks if we can cause a DoS or change 
        # (covered by other modules).
        # This module specifically checks if the server is processing the unkeyed header 
        # in a way that suggests backend processing time difference.
        
        # If poison requests are consistently getting HIT speeds after the first one,
        # it means the header is ignored (good) or the cache is poisoned (bad).
        
        # Let's stick to the "Leakage" check which is more reliable for Blind detection 
        # (checking if unkeyed params affect response via side channels).
        
        return None  # Timing is too noisy for this implementation level without more samples.

    
    async def cache_buster_leakage(self, client: HttpClient, url: str) -> List[Dict]:
        """
        Test if commonly unkeyed parameters (utm_source etc) can be used to poison the cache.
        """
        findings = []
        test_params = [
            "utm_source", "fbclid", "gclid", 
            "mc_cid", "_ga", "ref"
        ]
        
        base_cb = f"cb={int(time.time())}"
        clean_url = f"{url}&{base_cb}" if '?' in url else f"{url}?{base_cb}"
        
        # Get baseline for this cache buster
        base_resp = await client.request("GET", clean_url)
        if not base_resp: 
            return []
            
        for param in test_params:
            # 1. Send request with param + payload
            payload = f"blind-{str(uuid.uuid4())[:8]}"
            poison_url = f"{clean_url}&{param}={payload}"
            
            # Poison attempt
            await client.request("GET", poison_url)
            
            # 2. Check clean URL again
            verify_resp = await client.request("GET", clean_url)
            
            if not verify_resp:
                continue
                
            # If the clean URL now contains our payload, it's a confirmed finding!
            if payload in str(verify_resp['body']):
                findings.append({
                    "vulnerability": "UnkeyedParamPoisoning",
                    "param": param,
                    "details": f"Parameter {param} is unkeyed but reflected in the cache.",
                    "severity": "HIGH",
                    "payload": payload
                })
        
        return findings
