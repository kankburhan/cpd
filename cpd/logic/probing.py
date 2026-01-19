from typing import Dict, List, Optional
from cpd.http_client import HttpClient

class CacheProber:
    """Identify cache architecture and layers via error messages and headers."""
    
    async def cache_architecture_fingerprint(self, client: HttpClient, url: str) -> Optional[Dict]:
        """Identify cache layers via error responses and headers."""
        
        # 1. Header Analysis
        resp = await client.request("GET", url)
        if not resp:
            return None
            
        headers = resp.get('headers', {})
        detected = []
        
        known_headers = {
            "Server": ["cloudflare", "nginx", "apache", "varnish", "akamai", "ec2"],
            "Via": ["varnish", "akamai", "cloudfront", "google"],
            "X-Cache": ["varnish", "cloudfront", "akamai"],
            "X-Amz-Cf-Id": ["cloudfront"],
            "CF-Ray": ["cloudflare"],
            "Fastly-Debug-Digest": ["fastly"]
        }
        
        for h_name, keywords in known_headers.items():
            val = headers.get(h_name, "").lower()
            for kw in keywords:
                if kw in val:
                    detected.append(kw)
        
        # 2. Error Message Probing
        # Send malformed requests to trigger backend/cache errors
        probes = [
            {"headers": {"X-Forwarded-Host": "a" * 5000}}, # Oversized
            {"headers": {"Host": ""}}, # Empty host
        ]
        
        error_patterns = {
            "Varnish": ["guru meditation", "503 backend fetch failed"],
            "Fastly": ["fastly error"],
            "CloudFlare": ["cf-ray", "cloudflare"],
            "Akamai": ["akamaighost", "reference #"],
            "AWS CloudFront": ["the request could not be satisfied"]
        }
        
        for probe in probes:
            err_resp = await client.request("GET", url, headers=probe["headers"])
            if err_resp:
                body_lower = str(err_resp['body']).lower()
                for cache_type, patterns in error_patterns.items():
                    if any(p in body_lower for p in patterns):
                        detected.append(cache_type.lower())

        if detected:
            return {
                "technologies": list(set(detected)),
                "confidence": "HIGH"
            }
            
        return None
