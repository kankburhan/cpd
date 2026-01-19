import asyncio
from typing import List, Dict, Iterable
from cpd.http_client import HttpClient
from cpd.utils.logger import logger

class Engine:
    def __init__(
        self,
        concurrency: int = 50,
        timeout: int = 10,
        headers: Dict[str, str] = None,
        skip_unstable: bool = True,
        rate_limit: int = 0,
        cache_key_allowlist: Iterable[str] = None,
        cache_key_ignore_params: Iterable[str] = None,
        enforce_header_allowlist: bool = True,
        enable_waf_bypass: bool = True,
        waf_max_attempts: int = 50,
    ):
        self.concurrency = concurrency
        self.timeout = timeout
        self.headers = headers or {}
        self.skip_unstable = skip_unstable
        self.rate_limit = rate_limit
        self.cache_key_allowlist = [h.lower() for h in (cache_key_allowlist or [])]
        self.cache_key_ignore_params = list(cache_key_ignore_params or [])
        self.enforce_header_allowlist = enforce_header_allowlist
        self.enable_waf_bypass = enable_waf_bypass
        self.waf_max_attempts = waf_max_attempts
        self.stats = {
            'total_urls': 0,
            'skipped_status': 0,
            'skipped_unstable': 0,
            'tested': 0,
            'findings': 0
        }

    def _filter_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        if not self.enforce_header_allowlist or not self.cache_key_allowlist:
            return headers.copy()
        return {
            key: value
            for key, value in headers.items()
            if key.lower() in self.cache_key_allowlist
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
        
        # WAF Bypass Context
        local_headers = self.headers.copy()
        bypass_mutator = None
        
        if self.enable_waf_bypass:
            from cpd.logic.waf_bypass import WAFBypassEngine
            waf_engine = WAFBypassEngine()
            
            # Detect
            waf_name, confidence = await waf_engine.detector.detect(client, url)
            if waf_name:
                logger.warning(f"WAF Detected on {url}: {waf_name} ({confidence}%)")
                
                # Bypass
                success, bypasses = await waf_engine.analyze_and_bypass(client, url, "<script>alert(1)</script>", local_headers)
                if success and bypasses:
                    # Pick best bypass (simple strategy: first one for now)
                    best_bypass = bypasses[0]
                    logger.info(f"Using WAF bypass technique: {best_bypass['technique']}")
                    
                    # Merge headers
                    if best_bypass.get('headers'):
                        local_headers.update(best_bypass['headers'])
                        
                    # Create mutator
                    # We need a way to map technique name back to a functional mutator or use the one from engine?
                    # The bypass object has 'technique' name. WAFBypassEngine has methods _technique_*.
                    # Let's verify how we can get the method. 
                    # Simpler: The engine returns the payload, but Poisoner needs to apply it to arbitrary strings.
                    # We should probably expose the technique function or recreate it.
                    # Let's map technique name to a method on waf_engine.
                    technique_name = best_bypass['technique']
                    method_name = f"_technique_{technique_name}"
                    if hasattr(waf_engine, method_name):
                         # Create a wrapper that takes a string and returns the first result of the technique
                         technique_func = getattr(waf_engine, method_name)
                         bypass_mutator = lambda s: technique_func(s)[0] if technique_func(s) else s

        # No semaphore needed, worker count limits concurrency
        logger.info(f"Processing {url}")
        
        # 0. Cache Validation
        from cpd.logic.validator import CacheValidator
        validator = CacheValidator()
        is_cached, reason = await validator.analyze(client, url, headers=local_headers)
        
        if is_cached:
            logger.info(f"Cache detected on {url}: {reason}")
        else:
             logger.warning(f"Target {url} does not appear to be using a cache ({reason}). Findings might be invalid.")
            
        # 1. Baseline Analysis
        safe_headers = self._filter_headers(local_headers)
        analyzer = BaselineAnalyzer(headers=safe_headers)
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
        poisoner = Poisoner(
            baseline,
            headers=local_headers,
            cache_key_allowlist=self.cache_key_allowlist,
            cache_key_ignore_params=self.cache_key_ignore_params,
            enforce_header_allowlist=self.enforce_header_allowlist,
            value_mutator=bypass_mutator,
        )
        findings = await poisoner.run(client)
        if findings:
            self.stats['findings'] += len(findings)
            logger.info(f"Scan finished for {url} - Findings: {len(findings)}")
            return findings
        else:
            logger.info(f"Scan finished for {url} - No vulnerabilities found")
            return []
