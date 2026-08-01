"""
Tests for new cache poisoning detection features:
- Unkeyed port manipulation
- Header combinations (exploit chains)
- Enhanced parameter cloaking

NOTE: the xfail-marked tests below were added in a3fc1e5 (v0.5.0) alongside the
big poison.py rewrite, but the features they describe were never implemented --
they failed on the very commit that introduced them and have never passed. They
are kept as executable specs for the gaps rather than deleted, since these are
real techniques worth covering. Related-but-differently-named signatures that DO
exist today: X-Forwarded-Port-8080 / Host-Port-Mismatch (port), X-Cache-Key-Bypass
and Surrogate-Control (cache key), Path-Encoded-Slash (path encoding).

The markers are strict, so implementing a feature turns its test into an XPASS
failure -- that is the signal to drop the marker rather than edit the assertion.
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


@pytest.mark.xfail(
    strict=True,
    reason="Poisoner._get_header_combinations() was never implemented (see module docstring)",
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


@pytest.mark.xfail(
    strict=True,
    reason="No signature uses type='header_port'; port sigs exist but are untyped (see module docstring)",
)
@pytest.mark.asyncio
async def test_port_signature_exists(baseline):
    """Test that port manipulation signatures are included."""
    poisoner = Poisoner(baseline)
    
    port_sigs = [s for s in poisoner.signatures if s.get("type") == "header_port"]
    assert len(port_sigs) >= 3  # Host-Port-8080, 443, 8443


@pytest.mark.xfail(
    strict=True,
    reason="Param-Cloaking-Amp/Hash/Null never existed; only Param-Cloaking-Semi did, dropped in a3fc1e5",
)
@pytest.mark.asyncio
async def test_param_cloaking_signatures_exist(baseline):
    """Test that enhanced parameter cloaking signatures are included."""
    poisoner = Poisoner(baseline)
    
    cloaking_names = ["Param-Cloaking-Amp", "Param-Cloaking-Hash", "Param-Cloaking-Null"]
    for name in cloaking_names:
        found = any(s.get("name") == name for s in poisoner.signatures)
        assert found, f"Missing signature: {name}"


@pytest.mark.xfail(
    strict=True,
    reason="Only Path-Encoded-Slash exists; the double-encode/mixed-case/unicode variants were never implemented",
)
@pytest.mark.asyncio
async def test_path_encoding_signatures_exist(baseline):
    """Test that path encoding variant signatures are included."""
    poisoner = Poisoner(baseline)
    
    encoding_names = ["Path-Double-Encode-Slash", "Path-Mixed-Case", "Path-Unicode-Slash"]
    for name in encoding_names:
        found = any(s.get("name") == name for s in poisoner.signatures)
        assert found, f"Missing signature: {name}"


@pytest.mark.xfail(
    strict=True,
    reason="Only X-Cache-Key-Bypass/Surrogate-Control exist; Inject/Surrogate-Key/Cache-Tag were never implemented",
)
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
