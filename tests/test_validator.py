import pytest
from unittest.mock import AsyncMock, MagicMock
from cpd.logic.validator import CacheValidator

@pytest.mark.asyncio
async def test_validator_max_age_implied_public():
    validator = CacheValidator()
    client = MagicMock()
    client.request = AsyncMock()
    
    # Mock user's headers
    client.request.return_value = {
        "status": 200,
        "headers": {
            "Server": "Apache",
            "Cache-Control": "max-age=435828",
            "Expires": "Fri, 16 Jan 2026 15:02:14 GMT",
            "Date": "Sun, 11 Jan 2026 13:58:26 GMT"
        }
    }
    
    is_cached, reason = await validator.analyze(client, "http://example.com")
    
    assert is_cached is True
    assert "max-age present" in reason

@pytest.mark.asyncio
async def test_validator_private_ignored():
    validator = CacheValidator()
    client = MagicMock()
    client.request = AsyncMock()
    
    client.request.return_value = {
        "status": 200,
        "headers": {
            "Cache-Control": "private, max-age=3600"
        }
    }
    
    is_cached, reason = await validator.analyze(client, "http://example.com")
    
    assert is_cached is False
