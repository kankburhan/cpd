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
    body = b"<html><body>Normal Content</body></html>"
    body_hash = hashlib.sha256(body).hexdigest()
    
    return Baseline(
        url="http://example.com/foo/bar/baz",
        status=200,
        headers={"Content-Type": "text/html"},
        body_hash=body_hash, 
        body=body
    )

@pytest.mark.asyncio
async def test_backslash_last_slash(mock_client, baseline):
    """
    Simulate Backslash Last Slash Poisoning:
    Baseline: /foo/bar/baz (Content A)
    Poison Attempt: /foo/bar\baz -> Returns Poisoned Content (B)
    Verify 1 (Clean /foo/bar/baz): Returns Poisoned Content (B)
    Verify 2 (Clean): Returns Poisoned Content (B)
    Fresh Baseline: Returns Content A
    """
    poisoner = Poisoner(baseline)
    sigs = [s for s in poisoner.signatures if s["name"] == "Backslash-Last-Path-Replace"]
    assert len(sigs) == 1

    # Make poisoned body significantly larger to bypass the < 20 bytes diff check
    poisoned_body = b"<html><body>Poisoned Content - This content must be significantly different in length to avoid the heuristic check that ignores small differences as benign dynamic content.</body></html>"
    
    mock_client.request.side_effect = [
        # Poison Attempt: http://example.com/foo/bar\baz
        {"status": 200, "headers": {}, "body": poisoned_body, "url": "http://example.com/foo/bar\\baz?cb=1"},
        # Verify 1: http://example.com/foo/bar/baz
        {"status": 200, "headers": {}, "body": poisoned_body, "url": "http://example.com/foo/bar/baz?cb=1"},
        # Verify 2
        {"status": 200, "headers": {}, "body": poisoned_body, "url": "http://example.com/foo/bar/baz?cb=1"},
        # Fresh Baseline
        {"status": 200, "headers": {}, "body": baseline.body, "url": "http://example.com/foo/bar/baz?cb=fresh"}
    ]
    
    finding = await poisoner._attempt_poison(mock_client, sigs[0])

    assert finding is not None
    assert finding['signature']['name'] == "Backslash-Last-Path-Replace"
    assert finding['vulnerability'] == "PathNormalizationPoisoning"
    assert "\\baz" in finding['target_url']

@pytest.mark.asyncio
async def test_backslash_last_slash_root(mock_client):
    """
    Test edge case where path is just /
    """
    import hashlib
    # Baseline is short
    body = b"root"
    baseline = Baseline(
        url="http://example.com/",
        status=200,
        headers={},
        body_hash=hashlib.sha256(body).hexdigest(),
        body=body
    )
    
    poisoner = Poisoner(baseline)
    sigs = [s for s in poisoner.signatures if s["name"] == "Backslash-Last-Path-Replace"]
    assert len(sigs) == 1

    # logic should convert / to \
    # Poisoned content must be significantly different length (> 20 bytes diff)
    poisoned_body = b"Poisoned Content that is definitely longer than 20 bytes to pass the heuristic check."
    
    mock_client.request.side_effect = [
        {"status": 200, "headers": {}, "body": poisoned_body, "url": "http://example.com/\\?cb=1"},
        {"status": 200, "headers": {}, "body": poisoned_body, "url": "http://example.com/?cb=1"},
        {"status": 200, "headers": {}, "body": poisoned_body, "url": "http://example.com/?cb=1"},
        {"status": 200, "headers": {}, "body": body, "url": "http://example.com/?cb=fresh"}
    ]
    
    finding = await poisoner._attempt_poison(mock_client, sigs[0])
    assert finding is not None
    assert "\\" in finding['target_url'] or "%5C" in finding['target_url']
