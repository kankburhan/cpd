import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from cpd.logic.poison import Poisoner
from cpd.logic.baseline import Baseline

@pytest.fixture
def mock_baseline():
    return Baseline(
        url="https://example.com/foo",
        status=200,
        headers={"Server": "Test"},
        body_hash="02f67ccd1094983cb438874466ce795ddf13ec4989dbd10eebfcf3ab2c8c04ca",
        is_stable=True
    )

@pytest.fixture
def poisoner(mock_baseline):
    return Poisoner(mock_baseline)

@pytest.mark.asyncio
async def test_poisoner_payload_generation(poisoner):
    """
    Test that poisoner generates correct malicious URLs and headers.
    """
    assert len(poisoner.signatures) > 0
    
    # Test path normalization signature logic
    # We need to simulate _attempt_poison internals or break it down
    # But since _attempt_poison is monolithic, we test it via mocking client
    
    mock_client = AsyncMock()
    # Simulate a cache miss then hit
    mock_client.request.side_effect = [
        {"status": 200, "headers": {}, "body": b"poisoned" * 10, "url": "https://example.com/foo"}, # Malicious request
        {"status": 200, "headers": {}, "body": b"poisoned" * 10, "url": "https://example.com/foo"}, # Clean verification request
        # Full validation requires Verify 2 and Fresh
        {"status": 200, "headers": {}, "body": b"poisoned" * 10, "url": "https://example.com/foo"},
        {"status": 200, "headers": {}, "body": b"Content A", "url": "https://example.com/foo?fresh"}, 
    ]
    
    # Find the path signature
    sig = next(s for s in poisoner.signatures if s.get("type") == "path")
    
    result = await poisoner._attempt_poison(mock_client, sig)
    
    assert result is not None
    assert result["vulnerability"] == "PathNormalizationPoisoning"
    assert result["severity"] == "HIGH"

@pytest.mark.asyncio
async def test_poisoner_xss_detection(poisoner):
    """
    Test usage of reflected XSS scoring.
    """
    mock_client = AsyncMock()
    
    sig = {"name": "Test-XSS", "header": "User-Agent", "value": "<script>alert(1)</script>"}
    
    mock_client.request.side_effect = [
        {"status": 200, "headers": {}, "body": b"ok"}, 
        # Verification response contains the XSS payload
        {"status": 200, "headers": {}, "body": b"<html><script>alert(1)</script></html>", "url": "https://example.com/foo"} 
    ]
    
    result = await poisoner._attempt_poison(mock_client, sig)
    
    assert result is not None
    assert result["severity"] == "CRITICAL"
    assert "reflected" in result["details"]
