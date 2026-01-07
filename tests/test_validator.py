import pytest
from unittest.mock import AsyncMock, MagicMock
from cpd.logic.validator import CacheValidator

@pytest.mark.asyncio
async def test_cache_detected_by_header():
    validator = CacheValidator()
    
    # Mock HttpClient
    mock_client = MagicMock()
    mock_client.request = AsyncMock(return_value={
        "status": 200,
        "headers": {
            "Content-Type": "text/html",
            "X-Cache": "HIT"
        },
        "body": b"test"
    })
    
    is_cached, reason = await validator.analyze(mock_client, "http://example.com")
    
    assert is_cached is True
    assert "X-Cache" in reason

@pytest.mark.asyncio
async def test_cache_not_detected():
    validator = CacheValidator()
    
    # Mock HttpClient
    mock_client = MagicMock()
    mock_client.request = AsyncMock(return_value={
        "status": 200,
        "headers": {
            "Content-Type": "text/html",
            "Server": "Apache" 
        },
        "body": b"test"
    })
    
    is_cached, reason = await validator.analyze(mock_client, "http://example.com")
    
    assert is_cached is False
    assert "No cache headers detected" in reason

@pytest.mark.asyncio
async def test_cache_detected_by_cache_control():
    validator = CacheValidator()
    
    # Mock HttpClient
    mock_client = MagicMock()
    mock_client.request = AsyncMock(return_value={
        "status": 200,
        "headers": {
            "Cache-Control": "public, max-age=3600"
        },
        "body": b"test"
    })
    
    is_cached, reason = await validator.analyze(mock_client, "http://example.com")
    
    assert is_cached is True
    assert "Cache-Control" in reason

@pytest.mark.asyncio
async def test_cache_detected_by_cache_status():
    validator = CacheValidator()
    
    mock_client = MagicMock()
    mock_client.request = AsyncMock(return_value={
        "status": 200,
        "headers": {
            "Content-Type": "text/html",
            "Cache-Status": "hit"
        },
        "body": b"test"
    })
    
    is_cached, reason = await validator.analyze(mock_client, "http://example.com")
    
    assert is_cached is True
    assert "Cache-Status" in reason

@pytest.mark.asyncio
async def test_cache_detected_by_server_timing():
    validator = CacheValidator()
    
    mock_client = MagicMock()
    mock_client.request = AsyncMock(return_value={
        "status": 200,
        "headers": {
            "Content-Type": "text/html",
            "Server-Timing": "cdn-cache; desc=HIT"
        },
        "body": b"test"
    })
    
    is_cached, reason = await validator.analyze(mock_client, "http://example.com")
    
    assert is_cached is True
    assert "Server-Timing" in reason

@pytest.mark.asyncio
async def test_server_timing_ignored_if_no_cache_keyword():
    validator = CacheValidator()
    
    mock_client = MagicMock()
    mock_client.request = AsyncMock(return_value={
        "status": 200,
        "headers": {
            "Content-Type": "text/html",
            "Server-Timing": "cpu;dur=2.4"
        },
        "body": b"test"
    })
    
    is_cached, reason = await validator.analyze(mock_client, "http://example.com")
    
    assert is_cached is False

@pytest.mark.asyncio
async def test_cache_detected_by_other_headers():
    validator = CacheValidator()
    headers_to_test = [
        ("X-Cache-Status", "HIT"),
        ("X-Cache-Hits", "1"),
        ("X-Cache-Detail", "conditional cache hit")
    ]

    for header, value in headers_to_test:
        mock_client = MagicMock()
        mock_client.request = AsyncMock(return_value={
            "status": 200,
            "headers": {
                "Content-Type": "text/html",
                header: value
            },
            "body": b"test"
        })
        
        is_cached, reason = await validator.analyze(mock_client, "http://example.com")
        
        assert is_cached is True, f"Failed to detect {header}"
        assert header in reason
