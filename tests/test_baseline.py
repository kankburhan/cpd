import pytest
from unittest.mock import AsyncMock, MagicMock
from cpd.logic.baseline import BaselineAnalyzer

@pytest.mark.asyncio
async def test_skip_500_status():
    """Test that 500 status codes are skipped"""
    analyzer = BaselineAnalyzer()
    client = MagicMock()
    client.request = AsyncMock()
    
    # Return 500 status
    client.request.return_value = {
        "status": 500,
        "headers": {},
        "body": b"Internal Server Error"
    }
    
    baseline = await analyzer.analyze(client, "http://example.com")
    assert baseline is None

@pytest.mark.asyncio
async def test_inconsistent_status_codes():
    """Test that inconsistent status codes are rejected"""
    analyzer = BaselineAnalyzer()
    client = MagicMock()
    client.request = AsyncMock()
    
    # Return different status codes
    # We mock 3 iterations (default)
    client.request.side_effect = [
        {"status": 200, "headers": {}, "body": b"OK"},
        {"status": 404, "headers": {}, "body": b"Not Found"},
        {"status": 200, "headers": {}, "body": b"OK"}
    ]
    
    baseline = await analyzer.analyze(client, "http://example.com")
    assert baseline is None

@pytest.mark.asyncio
async def test_404_accepted():
    """Test that 404 status is accepted for testing"""
    analyzer = BaselineAnalyzer()
    client = MagicMock()
    client.request = AsyncMock()
    
    body = b"Not Found"
    client.request.return_value = {
        "status": 404,
        "headers": {"Content-Type": "text/html"},
        "body": body
    }
    
    baseline = await analyzer.analyze(client, "http://example.com")
    assert baseline is not None
    assert baseline.status == 404
