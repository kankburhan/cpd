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
async def test_drifted_content_ignored(mock_client, baseline):
    """
    Simulate a scenario where the site drifted from A -> B.
    Baseline: A
    Poison: B
    Verify 1: B
    Verify 2: B (Stable)
    Fresh Baseline Check: B (Looks like B is just the new normal)
    """
    poisoner = Poisoner(baseline)
    poisoner.signatures = [{
        "name": "Method-Override-POST", 
        "type": "method_override", 
        "header": "X-HTTP-Method-Override", 
        "value": "POST"
    }]
    
    # Mock Responses:
    # 1. Poison Attempt -> B
    # 2. Verify 1 -> B
    # 3. Verify 2 -> B (Stability Pass)
    # 4. Fresh Baseline -> B (Drift Confirmation)
    mock_client.request.side_effect = [
        {"status": 200, "headers": {}, "body": b"Content B", "url": "http://example.com?cb=1"},
        {"status": 200, "headers": {}, "body": b"Content B", "url": "http://example.com?cb=1"},
        {"status": 200, "headers": {}, "body": b"Content B", "url": "http://example.com?cb=1"},
        {"status": 200, "headers": {}, "body": b"Content B", "url": "http://example.com?cb=fresh"}
    ]
    
    findings = await poisoner._attempt_poison(mock_client, poisoner.signatures[0])
    
    assert findings is None

@pytest.mark.asyncio
async def test_chaotic_site_ignored(mock_client, baseline):
    """
    Simulate a chaotic site A -> B -> C.
    Baseline: A
    Poison: B
    Verify 1: B
    Verify 2: B (Stable for that cache buster)
    Fresh Baseline: C (Chaotic - Site changed again)
    """
    poisoner = Poisoner(baseline)
    poisoner.signatures = [{
        "name": "Method-Override-POST", 
        "type": "method_override", 
        "header": "X-HTTP-Method-Override", 
        "value": "POST"
    }]
    
    # Mock Responses:
    # 1. Poison Attempt -> B
    # 2. Verify 1 -> B
    # 3. Verify 2 -> B (Stability Pass)
    # 4. Fresh Baseline -> C (Chaotic Check)
    mock_client.request.side_effect = [
        {"status": 200, "headers": {}, "body": b"Content B", "url": "http://example.com?cb=1"},
        {"status": 200, "headers": {}, "body": b"Content B", "url": "http://example.com?cb=1"},
        {"status": 200, "headers": {}, "body": b"Content B", "url": "http://example.com?cb=1"},
        {"status": 200, "headers": {}, "body": b"Content C", "url": "http://example.com?cb=fresh"}
    ]
    
    findings = await poisoner._attempt_poison(mock_client, poisoner.signatures[0])
    
    # SHould be ignored due to chaotic check
    assert findings is None

@pytest.mark.asyncio
async def test_legitimate_poisoning_reported_despite_check(mock_client, baseline):
    """
    Simulate a legitimate poisoning.
    Baseline: A
    Poison: B
    Verify 1: B
    Verify 2: B (Stable)
    Fresh Baseline Check: A (The site is still A normally, only specific poisoned cache is B)
    """
    poisoner = Poisoner(baseline)
    poisoner.signatures = [{
        "name": "Method-Override-POST", 
        "type": "method_override", 
        "header": "X-HTTP-Method-Override", 
        "value": "POST"
    }]
    
    # Mock Responses:
    # 1. Poison Attempt -> B
    # 2. Verify 1 -> B
    # 3. Verify 2 -> B (Stability Pass)
    # 4. Fresh Baseline -> A (Drift Check Fails -> Valid Finding)
    mock_client.request.side_effect = [
        {"status": 200, "headers": {}, "body": b"Content B", "url": "http://example.com?cb=1"},
        {"status": 200, "headers": {}, "body": b"Content B", "url": "http://example.com?cb=1"},
        {"status": 200, "headers": {}, "body": b"Content B", "url": "http://example.com?cb=1"},
        {"status": 200, "headers": {}, "body": b"Content A", "url": "http://example.com?cb=fresh"}
    ]
    
    findings = await poisoner._attempt_poison(mock_client, poisoner.signatures[0])
    
    assert findings is not None
    assert findings['vulnerability'] == "MethodOverridePoisoning"
