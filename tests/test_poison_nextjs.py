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
    # Make body larger to bypass the < 20 bytes diff check in poison.py
    body = b"<html><body>Content A - This is a much longer content to ensure that the length difference check passes...</body></html>"
    body_hash = hashlib.sha256(body).hexdigest()
    
    # Baseline is HTML content
    return Baseline(
        url="http://example.com/page",
        status=200,
        headers={"Content-Type": "text/html"},
        body_hash=body_hash, 
        body=body
    )

@pytest.mark.asyncio
async def test_nextjs_prefetch_poisoning(mock_client, baseline):
    """
    Simulate Next.js prefetch poisoning:
    Baseline: HTML (A)
    Poison Attempt (with X-Middleware-Prefetch: 1): Returns JSON (B)
    Verify 1 (Clean Request): Returns JSON (B) -> POISONED
    Verify 2 (Clean Request): Returns JSON (B) -> STABLE
    Fresh Baseline: Returns HTML (A) -> CONFIRMED
    """
    poisoner = Poisoner(baseline)
    # Filter to only run the signatures we are testing
    poisoner.signatures = [s for s in poisoner.signatures if s["name"] in [
        "NextJS-Middleware-Prefetch", 
        "NextJS-Data", 
        "NextJS-Purpose-Prefetch"
    ]]
    
    # We expect all 3 to be found potentially, but let's just check if it finds them.
    # We need to set up the mock side effects carefully.
    # Since asyncio.gather is used, the order of execution is not strictly guaranteed,
    # but for a single mocked client in a loop, we might need a more robust side_effect 
    # or just test one signature at a time.
    
    # Let's test just one specific signature to be deterministic in this unit test
    sig_to_test = "NextJS-Middleware-Prefetch"
    poisoner.signatures = [s for s in poisoner.signatures if s["name"] == sig_to_test]
    
    # Mock Responses:
    # 1. Poison Attempt (Request with Header) -> Returns JSON
    # 2. Verify 1 (Clean Request) -> Returns JSON (Poisoned!)
    # 3. Verify 2 (Clean Request) -> Returns JSON (Stable Poison)
    # 4. Fresh Baseline (Clean Request + New Cache Buster) -> Returns HTML (Original State)
    
    mock_client.request.side_effect = [
        {"status": 200, "headers": {"Content-Type": "application/json"}, "body": b'{"pageProps": "..."}', "url": "http://example.com/page?cb=1"},
        {"status": 200, "headers": {"Content-Type": "application/json"}, "body": b'{"pageProps": "..."}', "url": "http://example.com/page?cb=1"},
        {"status": 200, "headers": {"Content-Type": "application/json"}, "body": b'{"pageProps": "..."}', "url": "http://example.com/page?cb=1"},
        {"status": 200, "headers": {"Content-Type": "text/html"}, "body": b"<html><body>Content A - This is a much longer content to ensure that the length difference check passes...</body></html>", "url": "http://example.com/page?cb=fresh"}
    ]
    
    findings = await poisoner.run(mock_client)
    
    assert len(findings) == 1
    finding = findings[0]
    assert finding['signature']['name'] == sig_to_test
    assert "POTENTIAL VULNERABILITY: MethodOverridePoisoning" in finding['details']
    assert finding['target_url'] and finding['verify_url']

@pytest.mark.asyncio
async def test_nextjs_prefetch_safe(mock_client, baseline):
    """
    Simulate Safe behavior (Not Vulnerable):
    Baseline: HTML (A)
    Poison Attempt: Returns JSON (B) (Server responds to prefetch correctly)
    Verify 1: Returns HTML (A) (Cache didn't store the JSON for the clean URL)
    """
    poisoner = Poisoner(baseline)
    sig_to_test = "NextJS-Middleware-Prefetch"
    poisoner.signatures = [s for s in poisoner.signatures if s["name"] == sig_to_test]
    
    mock_client.request.side_effect = [
        {"status": 200, "headers": {"Content-Type": "application/json"}, "body": b'{"pageProps": "..."}', "url": "http://example.com/page?cb=1"},
        {"status": 200, "headers": {"Content-Type": "text/html"}, "body": b"<html><body>Content A - This is a much longer content to ensure that the length difference check passes...</body></html>", "url": "http://example.com/page?cb=1"},
    ]
    
    findings = await poisoner.run(mock_client)
    assert len(findings) == 0
