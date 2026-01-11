import aiohttp
import asyncio
from typing import Optional, Dict, Any
from cpd.utils.logger import logger

class HttpClient:
    def __init__(self, timeout: int = 10, proxy: Optional[str] = None, rate_limit: int = 0):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.proxy = proxy
        self.session: Optional[aiohttp.ClientSession] = None
        self.rate_limit = rate_limit
        self.last_request_time = 0
        self.lock = asyncio.Lock()

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(timeout=self.timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None, **kwargs) -> Any:
        if not self.session:
            raise RuntimeError("Session not initialized. Use 'async with' context manager.")

        # Rate Limiting Logic
        if self.rate_limit > 0:
            async with self.lock:
                now = asyncio.get_event_loop().time()
                elapsed = now - self.last_request_time
                min_interval = 1.0 / self.rate_limit
                if elapsed < min_interval:
                    await asyncio.sleep(min_interval - elapsed)
                self.last_request_time = asyncio.get_event_loop().time()

        try:
            async with self.session.request(method, url, headers=headers, proxy=self.proxy, **kwargs) as response:
                # Read body immediately to release connection
                body = await response.read()
                return {
                    "status": response.status,
                    "headers": dict(response.headers),
                    "body": body,
                    "url": str(response.url)
                }
        except Exception as e:
            logger.debug(f"Request failed for {url}: {str(e)}")
            return None
