import pytest
import aiohttp
import asyncio
import os
import json
import time
from unittest.mock import MagicMock
from cpd.http_client import HttpClient
from cpd.utils.reporter import Reporter
from cpd.config import load_config

# === Test Reporter ===
def test_html_report_generation(tmp_path):
    output_file = tmp_path / "report.html"
    findings = [
        {"vulnerability": "Test Vuln", "severity": "HIGH", "target_url": "http://example.com"}
    ]
    Reporter.generate_html_report(findings, str(output_file))
    
    assert output_file.exists()
    content = output_file.read_text()
    assert "CPD Scan Report" in content
    assert "Test Vuln" in content
    assert "HIGH" in content

# === Test Rate Limiting ===
@pytest.mark.asyncio
async def test_rate_limiting():
    # Rate limit: 2 requests per second (0.5s interval)
    limit = 2
    async with HttpClient(rate_limit=limit) as client:
        start_time = asyncio.get_event_loop().time()
        
        # Mock session request
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_response.url = "http://example.com"
        
        # AsyncMock for read()
        f = asyncio.Future()
        f.set_result(b"")
        mock_response.read.return_value = f
        
        # Configure MagicMock context manager
        session_request_cm = MagicMock()
        session_request_cm.__aenter__.return_value = mock_response
        session_request_cm.__aexit__.return_value = None
        
        client.session.request = MagicMock(return_value=session_request_cm)
        
        # Make 3 request
        # 1st: immediate (t=0)
        # 2nd: wait 0.5s (t=0.5)
        # 3rd: wait 0.5s (t=1.0)
        # Total duration should be approx 1.0s
        await client.request("GET", "http://a.com")
        await client.request("GET", "http://b.com")
        await client.request("GET", "http://c.com")
        
        end_time = asyncio.get_event_loop().time()
        duration = end_time - start_time
        
        # Should be at least 1.0s (2 intervals of 0.5s)
        # Allow small margin for execution overhead
        assert duration >= 0.95 

# === Test Configuration ===
def test_load_config(tmp_path):
    config_file = tmp_path / "test_config.yaml"
    config_file.write_text("concurrency: 100\nskip_unstable: false\n")
    
    cfg = load_config(str(config_file))
    
    assert cfg["concurrency"] == 100
    assert cfg["skip_unstable"] is False
    assert cfg["timeout"] == 10 # Default value preserved
