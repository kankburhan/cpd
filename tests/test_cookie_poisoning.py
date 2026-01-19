"""Tests for cookie-based cache poisoning detection."""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from cpd.logic.poison import Poisoner
from cpd.logic.baseline import Baseline


@pytest.fixture
def baseline_with_cookie():
    """Create a baseline that simulates a page with cookie reflection."""
    baseline = MagicMock(spec=Baseline)
    baseline.url = "https://example.com/"
    baseline.status = 200
    baseline.body = b'data = {"host":"example.com","frontend":"prod-cache-01"}'
    baseline.body_hash = "abcd1234"
    baseline.headers = {"Content-Type": "text/html; charset=utf-8"}
    baseline.content_type = "text/html"
    baseline.is_stable = True
    # Populate cookies for dynamic testing
    baseline.cookies = {"session": "abc", "fehost": "prod-cache-01"}
    return baseline


@pytest.mark.asyncio
async def test_dynamic_cookie_signatures_generated(baseline_with_cookie):
    """Test that dynamic cookie signatures are generated from baseline cookies."""
    poisoner = Poisoner(baseline_with_cookie)
    
    # Check for auto-generated signatures
    defaults = [s['name'] for s in poisoner.signatures if s['name'].endswith('-Auto')]
    
    assert "Cookie-session-Auto" in defaults
    assert "Cookie-fehost-Auto" in defaults
    
    # Verify structure of one
    sig = next(s for s in poisoner.signatures if s['name'] == "Cookie-fehost-Auto")
    assert "fehost=evil-" in sig['value']
    assert "evil-" in sig['check_value']


@pytest.mark.asyncio
async def test_cookie_fehost_signature_exists(baseline_with_cookie):
    """Test that Cookie-Fehost signature is present."""
    poisoner = Poisoner(baseline_with_cookie)
    
    cookie_sigs = [s for s in poisoner.signatures if s['name'].startswith('Cookie-')]
    assert len(cookie_sigs) >= 5, "Should have at least 5 cookie signatures"
    
    fehost_sig = [s for s in cookie_sigs if s['name'] == 'Cookie-Fehost']
    assert len(fehost_sig) == 1, "Should have Cookie-Fehost signature"
    
    sig = fehost_sig[0]
    assert sig['header'] == 'Cookie'
    assert 'fehost=' in sig['value']
    assert 'check_value' in sig


@pytest.mark.asyncio
async def test_cookie_poisoning_detection(baseline_with_cookie):
    """Test that cookie-based cache poisoning is properly detected."""
    poisoner = Poisoner(baseline_with_cookie)
    payload_id = poisoner.payload_id
    
    # Mock HTTP client
    mock_client = AsyncMock()
    
    # First call: poisoning request (with cookie header)
    # This should return the reflected cookie value
    poison_response = {
        'status': 200,
        'headers': {'Content-Type': 'text/html', 'X-Cache': 'miss'},
        'body': f'data = {{"host":"example.com","frontend":"evil-{payload_id}.com"}}'.encode(),
        'url': 'https://example.com/?cb=123'
    }
    
    # Second call: verification request (without cookie)
    # Should still return the poisoned content (cached)
    verify_response = {
        'status': 200,
        'headers': {'Content-Type': 'text/html', 'X-Cache': 'hit'},
        'body': f'data = {{"host":"example.com","frontend":"evil-{payload_id}.com"}}'.encode(),
        'url': 'https://example.com/?cb=123'
    }
    
    # Configure mock to return different responses 
    mock_client.request = AsyncMock(side_effect=[poison_response, verify_response])
    
    # Get the Cookie-Fehost signature directly
    fehost_sig = next(s for s in poisoner.signatures if s['name'] == 'Cookie-Fehost')
    
    # Run the poison attempt
    result = await poisoner._attempt_poison(mock_client, fehost_sig)
    
    # Verify detection
    assert result is not None, "Should detect cookie-based cache poisoning"
    assert result['vulnerability'] == 'CachePoisoning'
    assert 'Cookie-Fehost' in result['details']


@pytest.mark.asyncio
async def test_cookie_not_reflected(baseline_with_cookie):
    """Test that non-reflected cookies are not flagged."""
    poisoner = Poisoner(baseline_with_cookie)
    payload_id = poisoner.payload_id
    
    mock_client = AsyncMock()
    
    # Normal response (cookie not reflected)
    normal_response = {
        'status': 200,
        'headers': {'Content-Type': 'text/html', 'X-Cache': 'miss'},
        'body': b'data = {"host":"example.com","frontend":"prod-cache-01"}',
        'url': 'https://example.com/?cb=123'
    }
    
    mock_client.request = AsyncMock(return_value=normal_response)
    
    fehost_sig = next(s for s in poisoner.signatures if s['name'] == 'Cookie-Fehost')
    result = await poisoner._attempt_poison(mock_client, fehost_sig)
    
    assert result is None, "Should not detect when cookie is not reflected"


@pytest.mark.asyncio
async def test_cookie_value_in_baseline_ignored(baseline_with_cookie):
    """Test that cookies already in baseline are ignored (false positive prevention)."""
    # Set baseline to already contain the evil value
    baseline_with_cookie.body = b'data = {"host":"example.com","frontend":"evil-existing.com"}'
    
    poisoner = Poisoner(baseline_with_cookie)
    
    mock_client = AsyncMock()
    
    # Response reflects the value (but it was already in baseline)
    response = {
        'status': 200,
        'headers': {'Content-Type': 'text/html'},
        'body': b'data = {"host":"example.com","frontend":"evil-existing.com"}',
        'url': 'https://example.com/?cb=123'
    }
    mock_client.request = AsyncMock(return_value=response)
    
    # Use a signature that matches the baseline content
    sig = {
        'name': 'Cookie-Test',
        'header': 'Cookie',
        'value': 'test=evil-existing.com',
        'check_value': 'evil-existing.com'
    }
    
    result = await poisoner._attempt_poison(mock_client, sig)
    
    assert result is None, "Should not flag values already in baseline"
