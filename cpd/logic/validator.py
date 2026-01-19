from typing import Dict, Optional, Tuple
from cpd.http_client import HttpClient
from cpd.utils.logger import logger

class CacheValidator:
    def __init__(self):
        self.cache_headers = [
            "X-Cache",
            "CF-Cache-Status",     # Cloudflare
            "X-Varnish",           # Varnish
            "Age",                 # Standard
            "Via",                 # Proxies
            "X-Drupal-Cache",      # Drupal
            "X-Proxy-Cache",       # Nginx
            "Akamai-Cache-Status", # Akamai
            "Cache-Status",        # Standard / Apache
            "X-Cache-Status",      # Generic / Nginx
            "X-Cache-Hits",        # Fastly
            "Server-Timing",       # W3C / CDNs
            "X-Cache-Detail",      # Apache
            # NEW HEADERS
            "X-Cache-Lookup",      # Varnish
            "X-Fastly-Cache-Status",  # Fastly (more specific)
            "X-Served-By",         # Fastly/Varnish
            "X-Timer",             # Fastly
            "X-Backend",           # Custom CDNs
            "X-Nginx-Cache-Status",  # Nginx
            "X-Proxy-Cache-Status",  # Squid
        ]

    async def analyze(self, client: HttpClient, url: str, headers: Dict[str, str] = None) -> Tuple[bool, Optional[str]]:
        """
        Analyze if the target URL is using a cache.
        Returns: (is_cached, reason)
        """
        logger.info(f"Checking for cache indicators on {url}")
        
        # 1. Passive Header Check
        resp = await client.request("GET", url, headers=headers)
        if not resp:
            return False, "Failed to fetch URL"

        for header_name in self.cache_headers:
            for key in resp['headers']:
                if key.lower() == header_name.lower():
                    val = resp['headers'][key]
                    logger.info(f"Cache indicator found: {key}: {val}")
                    
                    # Special handling for Server-Timing which is common but not always cache-related
                    if key.lower() == 'server-timing':
                        # Check for cache-related keywords in Server-Timing value
                        val_lower = val.lower()
                        if any(k in val_lower for k in ['cache', 'miss', 'hit', 'cdn-cache']):
                             return True, f"Found cache indicator in Server-Timing: {val}"
                        else:
                            # If it's Server-Timing but doesn't mention cache, keep looking
                            continue

                    return True, f"Found cache header: {key}"

        # 2. Heuristic/Behavioral Check (Optional)
        # Check standard Cache-Control
        cc = resp['headers'].get('Cache-Control', '').lower()
        if 'public' in cc or 's-maxage' in cc:
             return True, f"Cache-Control implies public caching: {cc}"
        
        # Check for max-age if 'private' is NOT present (implied public)
        if 'max-age' in cc and 'private' not in cc and 'no-store' not in cc:
             return True, f"Cache-Control implies cacheability (max-age present): {cc}"

        logger.warning(f"No obvious cache indicators found for {url}")
        return False, "No cache headers detected"
