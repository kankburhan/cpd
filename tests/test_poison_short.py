import hashlib

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
    body = b"Content A"
    return Baseline(
        url="http://example.com/",
        status=200,
        headers={},
        # Must match body: BaselineAnalyzer always derives one from the other,
        # and the drift guard hashes baseline.body directly.
        body_hash=hashlib.sha256(body).hexdigest(),
        body=body
    )

@pytest.mark.asyncio
async def test_vercel_short_value_ignored(mock_client, baseline):
    """
    Test that a short value (like 'US') appearing in verification
    does NOT trigger a finding if it wasn't in baseline.

    This targets the reflection guard in _attempt_poison ("len(sig_check) > 4"),
    so the scenario must isolate it: the verify body differs from the poison body,
    which rules out the separate content-mismatch branch. The only evidence left
    is the short value "US" showing up in a dynamic page.
    """
    poisoner = Poisoner(baseline)
    # Only test Vercel-IP-Country-US
    sigs = [s for s in poisoner.signatures if s["name"] == "Vercel-IP-Country-US"]
    assert len(sigs) == 1
    assert sigs[0]["value"] == "US"  # the guard keys off this being < 5 chars

    # Baseline: "Content A" (No "US")
    # Poison Attempt / Verify: dynamic bodies that both happen to contain "US".
    # They differ from each other, so this is reflection evidence only.
    # Logic should IGNORE it because "US" is < 5 chars.

    mock_client.request.side_effect = [
        {"status": 200, "headers": {}, "body": b"Content A matched US keyword", "url": "http://example.com/?cb=1"},
        {"status": 200, "headers": {}, "body": b"Content A matched US again", "url": "http://example.com/?cb=1"},
    ]

    finding = await poisoner._attempt_poison(mock_client, sigs[0])

    assert finding is None

@pytest.mark.asyncio
async def test_long_value_reflection_reported(mock_client, baseline):
    """
    Test that a LONG value (>= 5 chars) is reported if reflected.
    """
    poisoner = Poisoner(baseline)
    # Test a custom signature with long value
    sigs = [{
        "name": "Long-Reflect",
        "header": "X-Long",
        "value": "ABCDE12345"
    }]
    
    body_with_long = b"Content reflected ABCDE12345"
    
    mock_client.request.side_effect = [
        {"status": 200, "headers": {}, "body": body_with_long, "url": "http://example.com/?cb=1"},
        {"status": 200, "headers": {}, "body": body_with_long, "url": "http://example.com/?cb=1"},
    ]
    
    finding = await poisoner._attempt_poison(mock_client, sigs[0])

    assert finding is not None
    assert finding['signature']['name'] == "Long-Reflect"
