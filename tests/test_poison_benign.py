import pytest
from unittest.mock import AsyncMock, MagicMock
from cpd.logic.poison import Poisoner
from cpd.logic.baseline import Baseline
import hashlib

@pytest.fixture
def mock_client():
    client = MagicMock()
    client.request = AsyncMock()
    return client

@pytest.fixture
def baseline():
    body = b"Standard Content"
    return Baseline(
        url="http://example.com/foo",
        status=200,
        headers={},
        body_hash=hashlib.sha256(body).hexdigest(),
        body=body
    )

@pytest.mark.asyncio
async def test_ignore_identical_normalization(mock_client, baseline):
    """
    Test that if the poison response (e.g. backslash path) returns the EXACT SAME content
    as the baseline, it is ignored as benign normalization/aliasing.
    """
    poisoner = Poisoner(baseline)
    # Use a path signature
    poisoner.signatures = [{"name": "Backslash", "type": "path", "mutation": "backslash_last_slash"}]
    
    # Mock Response:
    # 1. Poison Attempt -> Returns SAME body as baseline
    mock_client.request.return_value = {
        "status": 200, 
        "headers": {}, 
        "body": b"Standard Content",  # Identical to baseline
        "url": "http://example.com/foo"
    }
    
    # Run
    # Note: run() iterates signatures. We can test _attempt_poison directly or run().
    # Let's use _attempt_poison for direct assertion.
    result = await poisoner._attempt_poison(mock_client, poisoner.signatures[0])
    
    assert result is None
