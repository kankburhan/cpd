import pytest
from unittest.mock import AsyncMock, MagicMock
from cpd.logic.poison import Poisoner
from cpd.logic.baseline import Baseline

@pytest.fixture
def mock_client():
    client = MagicMock()
    client.request = AsyncMock()
    return client

@pytest.fixture
def baseline():
    import hashlib
    body = b"<html><body>Full Content</body></html>"
    body_hash = hashlib.sha256(body).hexdigest()
    
    return Baseline(
        url="http://example.com/page",
        status=200,
        headers={"Content-Type": "text/html"},
        body_hash=body_hash, 
        body=body
    )

@pytest.mark.asyncio
async def test_range_poisoning(mock_client, baseline):
    """
    Simulate Range Poisoning:
    Baseline: Full Content (A)
    Poison Attempt (Range: bytes=0-0): Returns 1 byte (B) + 206 Partial Content
    Verify 1 (Clean): Returns 1 byte (B) + 206 Partial Content (Poisoned!)
    Verify 2 (Clean): Returns 1 byte (B) (Stable)
    Fresh Baseline: Returns Full Content (A)
    """
    poisoner = Poisoner(baseline)
    sigs = [s for s in poisoner.signatures if s["name"] == "Range-Poisoning"]
    assert len(sigs) == 1

    # Range response is usually just first byte, e.g., "<"
    partial_body = b"<"
    
    mock_client.request.side_effect = [
        {"status": 206, "headers": {"Content-Range": "bytes 0-0/100"}, "body": partial_body, "url": "http://example.com/page?cb=1"},
        {"status": 206, "headers": {"Content-Range": "bytes 0-0/100"}, "body": partial_body, "url": "http://example.com/page?cb=1"},
        {"status": 206, "headers": {"Content-Range": "bytes 0-0/100"}, "body": partial_body, "url": "http://example.com/page?cb=1"},
        {"status": 200, "headers": {"Content-Type": "text/html"}, "body": baseline.body, "url": "http://example.com/page?cb=fresh"}
    ]
    
    finding = await poisoner._attempt_poison(mock_client, sigs[0])

    assert finding is not None
    assert finding['signature']['name'] == "Range-Poisoning"
    assert finding['vulnerability'] == "MethodOverridePoisoning"

@pytest.mark.asyncio
async def test_range_safe(mock_client, baseline):
    """
    Simulate Safe Range behavior:
    Poison Attempt: Returns Partial
    Verify 1: Returns Full Content (Not Cached)
    """
    poisoner = Poisoner(baseline)
    sigs = [s for s in poisoner.signatures if s["name"] == "Range-Poisoning"]
    assert len(sigs) == 1

    partial_body = b"<"
    
    mock_client.request.side_effect = [
        {"status": 206, "headers": {"Content-Range": "bytes 0-0/100"}, "body": partial_body, "url": "http://example.com/page?cb=1"},
        {"status": 200, "headers": {"Content-Type": "text/html"}, "body": baseline.body, "url": "http://example.com/page?cb=1"},
    ]
    
    finding = await poisoner._attempt_poison(mock_client, sigs[0])
    assert finding is None
