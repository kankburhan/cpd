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
    is_stable: bool = True

class BaselineAnalyzer:
    def __init__(self, iterations: int = 3, headers: Dict[str, str] = None):
        self.iterations = iterations
        self.headers = headers or {}

    async def analyze(self, client: HttpClient, url: str) -> Optional[Baseline]:
        """
        Fetch the URL multiple times to establish a baseline.
        """
        responses = []
        for i in range(self.iterations):
            resp = await client.request("GET", url, headers=self.headers)
            if not resp:
                logger.warning(f"Failed to fetch baseline for {url} (attempt {i+1})")
                continue
            responses.append(resp)
        
        if not responses:
            return None

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
            is_stable=is_stable
        )

    def _calculate_hash(self, body: bytes) -> str:
        return hashlib.sha256(body).hexdigest()
