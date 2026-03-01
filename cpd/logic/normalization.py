from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from cpd.http_client import HttpClient
from cpd.logic.cache_guard import CacheGuard

class NormalizationTester:
    """Test cache key calculation inconsistencies via path and query parameter normalization."""
    
    def _generate_query_param_variants(self, url: str) -> List[str]:
        """Generate URL variants with query parameter case normalization."""
        parsed = urlparse(url)
        
        if not parsed.query:
            return []  # No query params to normalize
        
        variants = []
        
        # Parse query parameters
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Only generate variants if we have query parameters
        if not params:
            return []
        
        # Variant 1: All parameter names UPPERCASE
        upper_params = {k.upper(): v for k, v in params.items()}
        upper_query = urlencode(upper_params, doseq=True)
        upper_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, upper_query, parsed.fragment
        ))
        variants.append(upper_url)
        
        # Variant 2: All parameter names lowercase
        lower_params = {k.lower(): v for k, v in params.items()}
        lower_query = urlencode(lower_params, doseq=True)
        lower_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, lower_query, parsed.fragment
        ))
        variants.append(lower_url)
        
        # Variant 3: Mixed case (alternating)
        mixed_params = {}
        for i, (k, v) in enumerate(params.items()):
            # Alternate between upper and lower
            mixed_params[k.upper() if i % 2 == 0 else k.lower()] = v
        mixed_query = urlencode(mixed_params, doseq=True)
        mixed_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, mixed_query, parsed.fragment
        ))
        variants.append(mixed_url)
        
        return variants
    
    def generate_encoding_variants(self, url: str) -> List[str]:
        """Generate URL variants with different encodings of characters."""
        parsed = urlparse(url)
        path = parsed.path
        variants = []

        # Path-based variants (existing logic)
        if path and path != "/":
            # Slashes
            if '/' in path:
                variants.append(url.replace('/', '%2F'))
                variants.append(url.replace('/', '%252F'))  # Double encoded

            # Dots
            if '.' in path:
                variants.append(url.replace('.', '%2E'))

            # Case mismatch (path)
            variants.append(url.upper())

            # Matrix params (semicolon)
            if ';' not in path:
                variants.append(f"{parsed.scheme}://{parsed.netloc}{path};param=1?{parsed.query}")

        # Query parameter variants
        query_variants = self._generate_query_param_variants(url)
        variants.extend(query_variants)

        return variants

    def _generate_delimiter_confusion_variants(self, url: str) -> List[str]:
        """
        Generate URL variants that exploit path delimiter parsing differences
        between CDN/cache servers and origin servers.

        Based on 2024 research showing CDNs and origins interpret path components
        differently when encountering semicolons, encoded chars, and other delimiters.
        """
        parsed = urlparse(url)
        path = parsed.path or "/"
        scheme_host = f"{parsed.scheme}://{parsed.netloc}"
        query = f"?{parsed.query}" if parsed.query else ""
        variants = []

        # Only generate if we have a non-trivial path
        if path == "/" or not path:
            return variants

        base_path = path.rstrip("/")

        # Semicolon-based delimiter confusion
        # CDN may treat /path;.css as a static .css file (cacheable by default)
        # Origin may strip the semicolon segment and serve the original dynamic path
        variants.append(f"{scheme_host}{base_path};.css{query}")
        variants.append(f"{scheme_host}{base_path};.js{query}")
        variants.append(f"{scheme_host}{base_path};version=1{query}")
        variants.append(f"{scheme_host}{base_path};param=1.css{query}")

        # Encoded delimiter confusion
        # %3B = semicolon, %23 = hash, %3F = question mark
        variants.append(f"{scheme_host}{base_path}%3B.css{query}")
        variants.append(f"{scheme_host}{base_path}%23.js{query}")
        variants.append(f"{scheme_host}{base_path}%3F.png{query}")

        # Null byte path termination
        # Some CDNs normalize %00 out while computing cache key; origins may reject or
        # interpret the path up to the null byte differently
        variants.append(f"{scheme_host}{base_path}%00.css{query}")
        variants.append(f"{scheme_host}{base_path}%00.js{query}")

        # Non-standard path separators
        # Tilde and exclamation are not standard separators but some frameworks handle them
        variants.append(f"{scheme_host}{base_path}~.css{query}")

        # Encoded path traversal variants (beyond the existing %2F coverage)
        # %2E%2E = ".." — CDN may normalize, origin may process differently
        variants.append(f"{scheme_host}{base_path}/%2e%2e/cache.css{query}")
        variants.append(f"{scheme_host}{base_path}/%252e%252e/cache.js{query}")

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
