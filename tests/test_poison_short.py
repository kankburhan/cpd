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
    return Baseline(
        url="http://example.com/",
        status=200,
        headers={},
        body_hash="hash_A", 
        body=b"Content A"
    )

@pytest.mark.asyncio
async def test_vercel_short_value_ignored(mock_client, baseline):
    """
    Test that a short value (like 'US') appearing in verification
    does NOT trigger a finding if it wasn't in baseline.
    """
    poisoner = Poisoner(baseline)
    # Only test Vercel-IP-Country-US
    poisoner.signatures = [s for s in poisoner.signatures if s["name"] == "Vercel-IP-Country-US"]
    
    # Baseline: "Content A" (No "US")
    # Poison Attempt: "Content A matched US" (Found "US")
    # Verify: "Content A matched US" (Found "US") -> This simulates a dynamic string containing "US"
    # Logic should IGNORE it because "US" is < 5 chars.
    
    body_with_us = b"Content A matched US keyword"
    
    mock_client.request.side_effect = [
        {"status": 200, "headers": {}, "body": body_with_us, "url": "http://example.com/?cb=1"},
        {"status": 200, "headers": {}, "body": body_with_us, "url": "http://example.com/?cb=1"},
        # Method Override triggers 2 more checks: Verify 2 and Fresh
        {"status": 200, "headers": {}, "body": body_with_us, "url": "http://example.com/?cb=1"},
        {"status": 200, "headers": {}, "body": b"Content A", "url": "http://example.com/?cb=fresh"},
    ]
    
    findings = await poisoner.run(mock_client)
    
    assert len(findings) == 0

@pytest.mark.asyncio
async def test_long_value_reflection_reported(mock_client, baseline):
    """
    Test that a LONG value (>= 5 chars) is reported if reflected.
    """
    poisoner = Poisoner(baseline)
    # Test a custom signature with long value
    poisoner.signatures = [{
        "name": "Long-Reflect",
        "header": "X-Long",
        "value": "ABCDE12345"
    }]
    
    body_with_long = b"Content reflected ABCDE12345"
    
    mock_client.request.side_effect = [
        {"status": 200, "headers": {}, "body": body_with_long, "url": "http://example.com/?cb=1"},
        {"status": 200, "headers": {}, "body": body_with_long, "url": "http://example.com/?cb=1"},
    ]
    
    findings = await poisoner.run(mock_client)
    
    assert len(findings) == 1
    assert findings[0]['signature']['name'] == "Long-Reflect"
