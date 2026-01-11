import hashlib
from typing import Dict, Optional
from dataclasses import dataclass
from cpd.http_client import HttpClient
from cpd.utils.logger import logger

@dataclass
class Baseline:
    url: str
    status: int
    headers: Dict[str, str]
    body_hash: str
    body: bytes = b""
    is_stable: bool = True
    content_type: str = ""  # NEW

    def __post_init__(self):
        # Extract content type
        self.content_type = self.headers.get('Content-Type', '').lower()

class BaselineAnalyzer:
    # Add these constants
    SKIP_STATUS_CODES = {401, 402, 407, 408, 409, 429, 500, 502, 503, 504}
    TESTABLE_STATUS_CODES = {200, 201, 204, 206, 301, 302, 303, 304, 307, 308, 403, 404, 405, 410}

    def __init__(self, iterations: int = 3, headers: Dict[str, str] = None):
        self.iterations = iterations
        self.headers = headers or {}

    async def analyze(self, client: HttpClient, url: str) -> Optional[Baseline]:
        """
        Fetch the URL multiple times to establish a baseline.
        """
        responses = []
        status_codes = []

        for i in range(self.iterations):
            resp = await client.request("GET", url, headers=self.headers)
            if not resp:
                logger.warning(f"Failed to fetch baseline for {url} (attempt {i+1})")
                continue
            responses.append(resp)
            status_codes.append(resp['status'])
        
        if not responses:
            return None

        # NEW: Check status code consistency
        if len(set(status_codes)) > 1:
            logger.warning(f"Inconsistent status codes for {url}: {status_codes}")
            return None
        
        baseline_status = status_codes[0]
        
        # NEW: Validate status code is testable
        if baseline_status in self.SKIP_STATUS_CODES:
            logger.warning(f"Skipping {url} - Status {baseline_status} not suitable for testing")
            return None
        
        if baseline_status not in self.TESTABLE_STATUS_CODES:
            logger.warning(f"Unknown status {baseline_status} for {url} - proceeding with caution")

        # Analyze stability
        first = responses[0]
        first_hash = self._calculate_hash(first['body'])
        
        is_stable = True
        for resp in responses[1:]:
            current_hash = self._calculate_hash(resp['body'])
            if current_hash != first_hash:
                is_stable = False
                logger.info(f"Baseline instability detected for {url}")
                break
        
        return Baseline(
            url=url,
            status=first['status'],
            headers=first['headers'],
            body_hash=first_hash,
            body=first['body'],
            is_stable=is_stable
        )

    def _calculate_hash(self, body: bytes) -> str:
        return hashlib.sha256(body).hexdigest()
