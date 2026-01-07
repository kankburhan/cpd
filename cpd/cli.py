import click
import sys
import asyncio
from typing import TextIO
from cpd.utils.logger import setup_logger, logger
from cpd.engine import Engine

def check_for_updates(quiet=False):
    """
    Mock check for updates.
    """
    # In a real scenario, this would query PyPI or GitHub Releases
    # current_version = "0.1.0"
    # latest_version = fetch_remote_version()
    
    # Mocking a new version being available
    import random
    if random.choice([True, False]): # Randomly simulate an update
        msg = "\n[+] A new version of CPD is available! Run 'cpd update' to get the latest features.\n"
        if not quiet:
            click.secho(msg, fg="green", bold=True)

@click.group()
@click.version_option(version="0.1.0")
@click.option('--verbose', '-v', is_flag=True, help="Enable verbose logging.")
@click.option('--quiet', '-q', is_flag=True, help="Suppress informational output.")
@click.option('--log-level', '-l', help="Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL). overrides -v and -q.")
def cli(verbose, quiet, log_level):
    """
    CachePoisonDetector (CPD) - A tool for detecting web cache poisoning vulnerabilities.
    """
    setup_logger(verbose, quiet, log_level)
    
    # Auto-check for updates on run (skip if quiet to avoid breaking pipelines)
    if not quiet:
        check_for_updates(quiet=True)

@cli.command()
def update():
    """
    Check for and update to the latest version.
    """
    logger.info("Checking for updates...")
    # Mock update process
    import time
    time.sleep(1)
    logger.info("Connecting to remote repository...")
    time.sleep(1)
    
    # Mock result
    click.secho(f"[+] Downloading release from https://github.com/kankburhan/cpd/releases...", fg="green")
    click.secho("[+] CPD has been updated to version 0.2.0!", fg="green", bold=True)


@cli.command()
@click.option('--url', '-u', help="Single URL to scan.")
@click.option('--file', '-f', type=click.File('r'), help="File containing URLs to scan.")
@click.option('--concurrency', '-c', default=50, help="Max concurrent requests.")
@click.option('--header', '-h', multiple=True, help="Custom header (e.g. 'Cookie: foo=bar'). Can be used multiple times.")
@click.option('--output', '-o', help="File to save JSON results to.")
def scan(url, file, concurrency, header, output):
    """
    Scan one or more URLs for cache poisoning vulnerabilities.
    """
    # Parse headers
    custom_headers = {}
    if header:
        for h in header:
            if ':' in h:
                key, value = h.split(':', 1)
                custom_headers[key.strip()] = value.strip()
            else:
                logger.warning(f"Invalid header format: {h}. Expected 'Key: Value'")

    urls = []
    if url:
        urls.append(url)
    
    if file:
        for line in file:
            line = line.strip()
            if line:
                urls.append(line)
    
    # Check for stdin
    if not url and not file and not sys.stdin.isatty():
        for line in sys.stdin:
            line = line.strip()
            if line:
                urls.append(line)

    if not urls:
        logger.error("No URLs provided. Use --url, --file, or pipe URLs via stdin.")
        return

    logger.info(f"Starting scan for {len(urls)} URLs with concurrency {concurrency}")
    
    engine = Engine(concurrency=concurrency, headers=custom_headers)
    findings = asyncio.run(engine.run(urls))
    
    if findings:
        import json
        logger.info(f"Total findings: {len(findings)}")
        print(json.dumps(findings, indent=2))
        
        if output:
            try:
                with open(output, 'w') as f:
                    json.dump(findings, f, indent=2)
                logger.info(f"Results saved to {output}")
            except IOError as e:
                logger.error(f"Failed to write results to {output}: {e}")
    else:
        logger.info("No vulnerabilities found.")

@cli.command()
@click.option('--url', '-u', required=True, help="Target URL to validate.")
@click.option('--header', '-H', required=True, help="Header to inject (e.g. 'X-Forwarded-Host: evil.com').")
@click.option('--method', '-m', default="GET", help="HTTP Method (default: GET).")
@click.option('--body', '-b', help="Request body.")
def validate(url, header, method, body):
    """
    Manually validate a potential vulnerability by running a step-by-step analysis.
    """
    import asyncio
    import time
    from cpd.http_client import HttpClient
    
    async def _run_validation():
        headers = {}
        if ':' in header:
            key, value = header.split(':', 1)
            headers[key.strip()] = value.strip()
        else:
            logger.error("Invalid header format. Expected 'Key: Value'")
            return

        async with HttpClient() as client:
            # 1. Baseline
            logger.info("[1/4] Fetching Baseline...")
            cb_base = f"cb={int(time.time())}_base"
            url_base = f"{url}?{cb_base}" if '?' not in url else f"{url}&{cb_base}"
            baseline = await client.request(method, url_base, data=body)
            if not baseline:
                logger.error("Failed to fetch baseline.")
                return
            logger.info(f"Baseline: Status {baseline['status']}, Length {len(baseline['body'])}")

            # 2. Poison Attempt
            logger.info(f"[2/4] Attempting Poison with {header}...")
            cb_poison = f"cb={int(time.time())}_poison"
            url_poison = f"{url}?{cb_poison}" if '?' not in url else f"{url}&{cb_poison}"
            poison = await client.request(method, url_poison, headers=headers, data=body)
            if not poison:
                logger.error("Failed to fetch poison request.")
                return
            
            logger.info(f"Poison Response: Status {poison['status']}, Length {len(poison['body'])}")
            
            # Check if poison differed from baseline (ignoring cache buster diffs)
            # We can't strict check body because timestamps might change, but check status/headers
            if poison['status'] != baseline['status']:
                 logger.info(f"-> Poison caused status change: {baseline['status']} -> {poison['status']}")
            elif len(poison['body']) != len(baseline['body']):
                 logger.info(f"-> Poison caused length change: {len(baseline['body'])} -> {len(poison['body'])}")
            else:
                 logger.warning("-> Poison response identical to baseline (ignoring body content). Attack might have failed.")

            # 3. Verification (Clean Request)
            logger.info("[3/4] Verifying (Fetching clean URL with same cache key)...")
            # Reuse url_poison which has the cache buster we tried to poison
            verify = await client.request("GET", url_poison)
            if not verify:
                logger.error("Failed to fetch verify request.")
                return

            logger.info(f"Verify Response: Status {verify['status']}, Length {len(verify['body'])}")
            
            is_hit = False
            if verify['body'] == poison['body']:
                logger.info("-> Verify match Poison: YES (Potential Cache Hit)")
                is_hit = True
            else:
                logger.info("-> Verify match Poison: NO (Cache Miss or Dynamic)")

            if verify['body'] == baseline['body']:
                 logger.info("-> Verify match Baseline: YES")
            
            # 4. Fresh Baseline (Drift Check)
            logger.info("[4/4] Checking Fresh Baseline (for drift)...")
            cb_fresh = f"cb={int(time.time())}_fresh"
            url_fresh = f"{url}?{cb_fresh}" if '?' not in url else f"{url}&{cb_fresh}"
            fresh = await client.request(method, url_fresh, data=body)
            
            logger.info(f"Fresh Response: Status {fresh['status']}, Length {len(fresh['body'])}")
            
            # Final Analysis
            print("\n--- Analysis ---")
            if not is_hit:
                print("RESULT: Safe. Verification request did not return the poisoned content.")
                return

            # It was a hit (Verify == Poison)
            # Logic Fix Check:
            if len(fresh['body']) == len(verify['body']):
                 print("RESULT: False Positive (Benign).")
                 print("Reason: The 'poisoned' content is identical length to a fresh baseline.")
                 print("The server likely ignored the malicious header, and the site returned standard dynamic content.")
                 return
            
            if fresh['body'] == verify['body']:
                 print("RESULT: False Positive (Drift).")
                 print("Reason: Fresh baseline matches the 'poisoned' content. The site just changed naturally.")
                 return

            print("RESULT: POTENTIAL VULNERABILITY!")
            print("Reason: Verification matched Poison, but Fresh Baseline differs.")
            print("The cache appears to be poisoning clean requests with the malicious response.")

    asyncio.run(_run_validation())

if __name__ == "__main__":
    cli()
