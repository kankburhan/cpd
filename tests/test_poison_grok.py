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
        url="http://example.com/path/to/resource",
        status=200,
        headers={},
        body_hash="hash_A", 
        body=b"Content A"
    )

@pytest.mark.asyncio
async def test_mutation_append_css(mock_client, baseline):
    poisoner = Poisoner(baseline)
    poisoner.signatures = [{"name": "WCD", "type": "path", "mutation": "append_css", "value": "/static/style.css?poison=123"}]
    
    mock_client.request.return_value = {"status": 200, "headers": {}, "body": b"A", "url": "url"}
    
    await poisoner.run(mock_client)
    
    # Check target URL construction
    call_args = mock_client.request.call_args_list[0]
    target_url = call_args[0][1] # (method, url, ...)
    # Expected: /path/to/resource/static/style.css?poison=123&cb=... 
    # Use 'in' because cb is dynamic
    assert "/path/to/resource/static/style.css?poison=123" in target_url

@pytest.mark.asyncio
async def test_mutation_dot_segment(mock_client, baseline):
    poisoner = Poisoner(baseline)
    poisoner.signatures = [{"name": "Dot", "type": "path", "mutation": "dot_segment", "value": "/./poison"}]
    
    mock_client.request.return_value = {"status": 200, "headers": {}, "body": b"A", "url": "url"}
    
    await poisoner.run(mock_client)
    
    call_args = mock_client.request.call_args_list[0]
    target_url = call_args[0][1]
    # Expected: /path/to/resource/./poison
    assert "/path/to/resource/./poison" in target_url

@pytest.mark.asyncio
async def test_mutation_encoded_slash(mock_client, baseline):
    poisoner = Poisoner(baseline)
    poisoner.signatures = [{"name": "EncodedSlash", "type": "path", "mutation": "encoded_slash", "value": "/%2fpoison"}]
    
    mock_client.request.return_value = {"status": 200, "headers": {}, "body": b"A", "url": "url"}
    
    await poisoner.run(mock_client)
    
    call_args = mock_client.request.call_args_list[0]
    target_url = call_args[0][1]
    assert "/path/to/resource/%2fpoison" in target_url
