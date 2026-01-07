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
        url="http://example.com",
        status=200,
        headers={},
        body_hash="hash_A", # Mock hash
        body=b"Content A"
    )

@pytest.mark.asyncio
async def test_dynamic_content_ignored(mock_client, baseline):
    """
    Simulate a scenario where content keeps changing:
    Baseline: A
    Poison: B
    Verify 1: B (Looks like poison worked!)
    Verify 2: C (Wait, it changed again -> Dynamic)
    """
    poisoner = Poisoner(baseline)
    
    # Only test one signature to keep it simple
    poisoner.signatures = [{
        "name": "Method-Override-POST", 
        "type": "method_override", 
        "header": "X-HTTP-Method-Override", 
        "value": "POST"
    }]
    
    # Mock Responses:
    # 1. Poison Attempt -> Returns B
    # 2. Verify 1 -> Returns B
    # 3. Verify 2 -> Returns C
    mock_client.request.side_effect = [
        {"status": 200, "headers": {}, "body": b"Content B", "url": "http://example.com"},
        {"status": 200, "headers": {}, "body": b"Content B", "url": "http://example.com"},
        {"status": 200, "headers": {}, "body": b"Content C", "url": "http://example.com"}
    ]
    
    findings = await poisoner._attempt_poison(mock_client, poisoner.signatures[0])
    
    # Should be None because verified content was unstable
    assert findings is None

@pytest.mark.asyncio
async def test_stable_poisoning_reported(mock_client, baseline):
    """
    Simulate a true poisoning scenario:
    Baseline: A
    Poison: B
    Verify 1: B
    Verify 2: B (Stable -> Poison confirmed)
    """
    poisoner = Poisoner(baseline)
    poisoner.signatures = [{
        "name": "Method-Override-POST", 
        "type": "method_override", 
        "header": "X-HTTP-Method-Override", 
        "value": "POST"
    }]
    
    # Mock Responses:
    # 1. Poison Attempt -> Returns B
    # 2. Verify 1 -> Returns B
    # 3. Verify 2 -> Returns B
    mock_client.request.side_effect = [
        {"status": 200, "headers": {}, "body": b"Content B", "url": "http://example.com"},
        {"status": 200, "headers": {}, "body": b"Content B", "url": "http://example.com"},
        {"status": 200, "headers": {}, "body": b"Content B", "url": "http://example.com"}
    ]
    
    findings = await poisoner._attempt_poison(mock_client, poisoner.signatures[0])
    
    assert findings is not None
    assert findings['vulnerability'] == "MethodOverridePoisoning"
