import aiohttp
import asyncio
from typing import Optional, Dict, Any
from cpd.utils.logger import logger

class HttpClient:
    def __init__(self, timeout: int = 10, proxy: Optional[str] = None):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.proxy = proxy
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(timeout=self.timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None, **kwargs) -> Any:
        if not self.session:
            raise RuntimeError("Session not initialized. Use 'async with' context manager.")

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
