from typing import Dict, Tuple, Optional
from urllib.parse import urlparse

def parse_raw_request(raw_content: str, scheme: str = "https") -> Dict:
    """
    Parse a raw HTTP request (string) into components for HttpClient.
    
    Args:
        raw_content: The raw HTTP request string.
        scheme: The protocol scheme (http/https). Default is https.
        
    Returns:
        Dict containing url, method, headers, and body.
    """
    lines = raw_content.strip().splitlines()
    if not lines:
        raise ValueError("Empty request content")

    # 1. Parse Request Line
    # GET /api/folders HTTP/2
    req_line_parts = lines[0].split()
    if len(req_line_parts) < 2:
        raise ValueError(f"Invalid request line: {lines[0]}")
    
    method = req_line_parts[0].upper()
    path = req_line_parts[1]
    
    # 2. Parse Headers
    headers = {}
    body = None
    line_idx = 1
    
    while line_idx < len(lines):
        line = lines[line_idx]
        if line == "":
            # End of headers, start of body
            body = "\n".join(lines[line_idx+1:])
            break
        
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip()] = val.strip()
        line_idx += 1

    # 3. Construct URL
    # Needs Host header
    host = headers.get("Host")
    if not host:
        # Fallback if no Host header (unlikely for valid requests)
        raise ValueError("Missing Host header in raw request")

    # Handle full URL in path (proxy style) vs relative path
    if path.startswith("http"):
        url = path
    else:
        url = f"{scheme}://{host}{path}"

    return {
        "url": url,
        "method": method,
        "headers": headers,
        "body": body
    }
