from typing import Dict, Optional, Tuple
from cpd.http_client import HttpClient
from cpd.utils.logger import logger

class CacheValidator:
    def __init__(self):
        self.cache_headers = [
            "X-Cache",
            "CF-Cache-Status",
            "X-Varnish",
            "Age",
            "Via",
            "X-Drupal-Cache",
            "X-Proxy-Cache",
            "Akamai-Cache-Status"
        ]

    async def analyze(self, client: HttpClient, url: str) -> Tuple[bool, Optional[str]]:
        """
        Analyze if the target URL is using a cache.
        Returns: (is_cached, reason)
        """
        logger.info(f"Checking for cache indicators on {url}")
        
        # 1. Passive Header Check
        resp = await client.request("GET", url)
        if not resp:
            return False, "Failed to fetch URL"

        for header in self.cache_headers:
            for key in resp['headers']:
                if key.lower() == header.lower():
                    val = resp['headers'][key]
                    logger.info(f"Cache indicator found: {key}: {val}")
                    # Some headers explicitly say MISS, but the presence of the header 
                    # usually implies a caching layer is present, even if it missed.
                    return True, f"Found cache header: {key}"

        # 2. Heuristic/Behavioral Check (Optional)
        # If no explicit headers, we could check for Age incrementing or valid Cache-Control
        # For now, we'll rely on the most common headers.
        
        # Check standard Cache-Control
        cc = resp['headers'].get('Cache-Control', '').lower()
        if 'public' in cc or 's-maxage' in cc:
             return True, f"Cache-Control implies public caching: {cc}"

        logger.warning(f"No obvious cache indicators found for {url}")
        return False, "No cache headers detected"
