from typing import Dict, List, Optional
from urllib.parse import urlparse
from cpd.http_client import HttpClient
from cpd.logic.cache_guard import CacheGuard

class NormalizationTester:
    """Test cache key calculation inconsistencies via path normalization."""
    
    def generate_encoding_variants(self, url: str) -> List[str]:
        """Generate URL variants with different encodings of characters."""
        parsed = urlparse(url)
        path = parsed.path
        if not path or path == "/":
            return [] # Can't normalize root much
        
        # Base variants of the path
        # 1. Encoded characters
        variants = []
        
        # Slashes
        if '/' in path:
            variants.append(url.replace('/', '%2F'))
            variants.append(url.replace('/', '%252F')) # Double encoded
            # variants.append(url.replace('/', '\u2044')) # Unicode fraction slash - risky for python client?
        
        # Dots
        if '.' in path:
             variants.append(url.replace('.', '%2E'))
        
        # Case mismatch
        variants.append(url.upper())
        
        # Matrix params (semicolon)
        if not ';' in path:
            variants.append(f"{parsed.scheme}://{parsed.netloc}{path};param=1?{parsed.query}")

        return variants
    
    async def test_cache_key_confusion(self, client: HttpClient, base_url: str, baseline_fingerprint: str) -> List[Dict]:
        """
        Test if different URLs hit the same cache key as the baseline.
        """
        findings = []
        variants = self.generate_encoding_variants(base_url)
        
        for variant_url in variants:
            # We don't want to use the default cache buster here necessarily, 
            # we want to see if this variant maps to the *base_url* cache key.
            # But the base_url likely has a cache buster in the baseline object.
            # Assuming base_url passed here is the CLEAN url.
            
            resp = await client.request("GET", variant_url)
            if not resp:
                continue
                
            fingerprint = CacheGuard.fingerprint_response(resp)
            
            # If the content is identical to the baseline, it *might* be a cache hit (collision)
            # OR just that the server normalizes it and serves the same content.
            # To prove it's a cache collision, we need to see evidence of the *original* cached response (e.g. earlier timestamp, or specific header).
            # But here we are just checking if the server responds identically.
            
            # Check cache status headers
            is_hit, evidence = CacheGuard.cache_hit_signal(resp)
            
            if is_hit and fingerprint == baseline_fingerprint:
                # Strong indicator: We asked for %2Ffoo, got a HIT, and content matches /foo.
                findings.append({
                    "vulnerability": "CacheKeyNormalization",
                    "variant_url": variant_url,
                    "original_url": base_url,
                    "evidence": evidence,
                    "severity": "HIGH",
                    "details": f"Variant {variant_url} returned a cache HIT matching baseline content."
                })
        
        return findings
