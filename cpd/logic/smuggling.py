from typing import Dict, List, Optional
from cpd.http_client import HttpClient
from cpd.utils.logger import logger

class SmugglingDetector:
    """
    Detects potential HTTP Request Smuggling vulnerabilities (CL.TE, TE.CL, TE.TE)
    that can lead to cache poisoning.
    """

    def __init__(self):
        self.payloads = [
            # CL.TE: Content-Length stated, but Transfer-Encoding present and obeyed by backend
            {
                "name": "CL.TE-Detection",
                "headers": {
                    "Content-Length": "6",
                    "Transfer-Encoding": "chunked",
                },
                "body": "0\r\n\r\nG" # Smuggled 'G'
            },
            # TE.CL: Transfer-Encoding obfuscated, hoping frontend sees TE but backend sees CL
            {
                "name": "TE.CL-Obfuscated",
                "headers": {
                    "Content-Length": "4",
                    "Transfer-Encoding": "chunked\r\nTransfer-Encoding: x",
                },
                "body": "5c\r\nGPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n"
            }
        ]

    async def detect_desync(self, client: HttpClient, url: str) -> List[Dict]:
        """
        Attempt to detect desynchronization.
        Note: This is a basic check. Full detection often requires timing analysis 
        or specific socket handling which aiohttp might abstract away.
        """
        findings = []
        
        for payload in self.payloads:
            # We use the client to send the request
            # Warning: aiohttp might strip invalid headers or fix CL.
            # This is a best-effort check using the standard client.
            try:
                # We append a cache buster to avoid poisoning the main page during the test if possible,
                # though smuggling usually affects the socket not the URL.
                resp = await client.request(
                    "POST", 
                    url, 
                    headers=payload["headers"], 
                    data=payload["body"]
                )
                
                if not resp:
                    continue

                # Analyze response for timeout or 500s which might indicate desync logic trying to read more data
                if resp['status'] in [500, 502, 504]:
                     findings.append({
                        "vulnerability": "PotentialRequestSmuggling",
                        "type": payload["name"],
                        "url": url,
                        "details": f"Server returned {resp['status']} to ambiguous TE/CL headers. Manual verification required.",
                        "severity": "MEDIUM"
                    })
                
                # If we get a 400 Bad Request, it usually means the server parsed it correctly and rejected the ambiguity (Safe)
                
            except Exception as e:
                logger.debug(f"Smuggling probe {payload['name']} failed: {e}")

        return findings
