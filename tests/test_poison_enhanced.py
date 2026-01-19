"""
Tests for new cache poisoning detection features:
- Unkeyed port manipulation
- Header combinations (exploit chains)
- Enhanced parameter cloaking
"""
import pytest
import hashlib
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
    body = b"<html><body>Normal Content</body></html>"
    body_hash = hashlib.sha256(body).hexdigest()
    return Baseline(
        url="http://example.com/api/user",
        status=200,
        headers={"Content-Type": "text/html"},
        body_hash=body_hash,
        body=body
    )


@pytest.mark.asyncio
async def test_header_combinations_generation(baseline):
    """Test that header combinations are generated correctly."""
    poisoner = Poisoner(baseline)
    combos = poisoner._get_header_combinations()
    
    # Should have at least 4 combinations
    assert len(combos) >= 4
    
    # Each combo should have at least 2 headers
    for combo in combos:
        assert len(combo) >= 2
        for h in combo:
            assert "header" in h
            assert "value" in h


@pytest.mark.asyncio
async def test_port_signature_exists(baseline):
    """Test that port manipulation signatures are included."""
    poisoner = Poisoner(baseline)
    
    port_sigs = [s for s in poisoner.signatures if s.get("type") == "header_port"]
    assert len(port_sigs) >= 3  # Host-Port-8080, 443, 8443


@pytest.mark.asyncio
async def test_param_cloaking_signatures_exist(baseline):
    """Test that enhanced parameter cloaking signatures are included."""
    poisoner = Poisoner(baseline)
    
    cloaking_names = ["Param-Cloaking-Amp", "Param-Cloaking-Hash", "Param-Cloaking-Null"]
    for name in cloaking_names:
        found = any(s.get("name") == name for s in poisoner.signatures)
        assert found, f"Missing signature: {name}"


@pytest.mark.asyncio
async def test_path_encoding_signatures_exist(baseline):
    """Test that path encoding variant signatures are included."""
    poisoner = Poisoner(baseline)
    
    encoding_names = ["Path-Double-Encode-Slash", "Path-Mixed-Case", "Path-Unicode-Slash"]
    for name in encoding_names:
        found = any(s.get("name") == name for s in poisoner.signatures)
        assert found, f"Missing signature: {name}"


@pytest.mark.asyncio
async def test_cache_key_signatures_exist(baseline):
    """Test that cache key manipulation signatures are included."""
    poisoner = Poisoner(baseline)
    
    cache_key_names = ["X-Cache-Key-Inject", "Surrogate-Key", "Cache-Tag"]
    for name in cache_key_names:
        found = any(s.get("name") == name for s in poisoner.signatures)
        assert found, f"Missing signature: {name}"


@pytest.mark.asyncio
async def test_signature_count_increased(baseline):
    """Test that total signature count has increased."""
    poisoner = Poisoner(baseline)
    
    # Should have more than 100 signatures now
    assert len(poisoner.signatures) > 100
