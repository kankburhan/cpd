import asyncio
from typing import List, Dict
from cpd.http_client import HttpClient
from cpd.utils.logger import logger

class Engine:
    def __init__(self, concurrency: int = 50, timeout: int = 10, headers: Dict[str, str] = None, skip_unstable: bool = True, rate_limit: int = 0):
        self.concurrency = concurrency
        self.timeout = timeout
        self.headers = headers or {}
        self.skip_unstable = skip_unstable
        self.rate_limit = rate_limit
        self.stats = {
            'total_urls': 0,
            'skipped_status': 0,
            'skipped_unstable': 0,
            'tested': 0,
            'findings': 0
        }

    async def run(self, urls: List[str]):
        self.stats['total_urls'] = len(urls)
        """
        Main execution loop.
        """
        # Worker Pool Pattern
        queue = asyncio.Queue()
        
        # Populate queue
        for url in urls:
            queue.put_nowait(url)
            
        # Create workers
        workers = []
        all_findings = []
        
        async def worker():
             while True:
                 try:
                     url = queue.get_nowait()
                 except asyncio.QueueEmpty:
                     break
                 
                 try:
                     result = await self._process_url(client, url)
                     if result:
                         all_findings.extend(result)
                 except Exception as e:
                     logger.error(f"Error processing {url}: {e}")
                 finally:
                     queue.task_done()

        async with HttpClient(timeout=self.timeout, rate_limit=self.rate_limit) as client:
            # Launch workers
            for _ in range(self.concurrency):
                workers.append(asyncio.create_task(worker()))
            
            # Wait for all workers to finish
            await asyncio.gather(*workers)
            
            logger.info(f"Scan complete: {self.stats['tested']}/{self.stats['total_urls']} tested, "
                       f"{self.stats['findings']} vulnerabilities found, "
                       f"{self.stats['skipped_status']} skipped (bad status), "
                       f"{self.stats['skipped_unstable']} skipped (unstable)")
            return all_findings

    async def _process_url(self, client: HttpClient, url: str):
        from cpd.logic.baseline import BaselineAnalyzer
        
        
        # No semaphore needed, worker count limits concurrency
        logger.info(f"Processing {url}")
        
        # 0. Cache Validation
        from cpd.logic.validator import CacheValidator
        validator = CacheValidator()
        is_cached, reason = await validator.analyze(client, url)
        
        if is_cached:
            logger.info(f"Cache detected on {url}: {reason}")
        else:
             logger.warning(f"Target {url} does not appear to be using a cache ({reason}). Findings might be invalid.")
            
        # 1. Baseline Analysis
        analyzer = BaselineAnalyzer(headers=self.headers)
        baseline = await analyzer.analyze(client, url)
        
        if not baseline:
            logger.error(f"Could not establish baseline for {url}")
            self.stats['skipped_status'] += 1
            return

        # NEW: Check stability
        if not baseline.is_stable:
            if self.skip_unstable:
                logger.warning(f"Skipping {url} due to instability.")
                self.stats['skipped_unstable'] += 1
                return
            else:
                logger.warning(f"URL {url} is unstable - results may have false positives")

        logger.info(f"Baseline established for {url} - Stable: {baseline.is_stable}, Hash: {baseline.body_hash[:8]}")
        
        # 2. Poisoning Simulation
        self.stats['tested'] += 1
        from cpd.logic.poison import Poisoner
        poisoner = Poisoner(baseline, headers=self.headers)
        findings = await poisoner.run(client)
        if findings:
            self.stats['findings'] += len(findings)
            logger.info(f"Scan finished for {url} - Findings: {len(findings)}")
            return findings
        else:
            logger.info(f"Scan finished for {url} - No vulnerabilities found")
            return []
