import click
import sys
import asyncio
from typing import TextIO
from cpd.utils.logger import setup_logger, logger
from cpd.engine import Engine

@click.group()
@click.option('--verbose', '-v', is_flag=True, help="Enable verbose logging.")
@click.option('--quiet', '-q', is_flag=True, help="Suppress informational output.")
@click.option('--log-level', '-l', help="Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL). overrides -v and -q.")
def cli(verbose, quiet, log_level):
    """
    CachePoisonDetector (CPD) - A tool for detecting web cache poisoning vulnerabilities.
    """
    setup_logger(verbose, quiet, log_level)

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

if __name__ == "__main__":
    cli()
