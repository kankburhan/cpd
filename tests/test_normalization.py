"""
Tests for NormalizationTester module.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock
from cpd.logic.normalization import NormalizationTester
from cpd.http_client import HttpClient


# === Query Parameter Normalization Tests ===

def test_query_param_uppercase_variant():
    """Test that query parameters are normalized to uppercase."""
    tester = NormalizationTester()
    url = "https://example.com/page?utm_source=twitter&pid=Social_twitter"
    
    variants = tester._generate_query_param_variants(url)
    
    # Should generate uppercase variant
    assert any("UTM_SOURCE" in v and "PID" in v for v in variants)


def test_query_param_lowercase_variant():
    """Test that query parameters are normalized to lowercase."""
    tester = NormalizationTester()
    url = "https://example.com/page?UTM_SOURCE=twitter&PID=Social"
    
    variants = tester._generate_query_param_variants(url)
    
    # Should generate lowercase variant
    assert any("utm_source" in v and "pid" in v for v in variants)


def test_query_param_mixed_case_variant():
    """Test mixed case query parameter variants."""
    tester = NormalizationTester()
    url = "https://example.com/page?first=1&second=2&third=3"
    
    variants = tester._generate_query_param_variants(url)
    
    # Should generate at least 3 variants (upper, lower, mixed)
    assert len(variants) >= 3


def test_no_query_params():
    """Test that URLs without query params return empty variant list."""
    tester = NormalizationTester()
    url = "https://example.com/page"
    
    variants = tester._generate_query_param_variants(url)
    
    assert variants == []


def test_query_params_preserved_values():
    """Test that query parameter values are preserved during normalization."""
    tester = NormalizationTester()
    url = "https://example.com/page?key=SensitiveValue"
    
    variants = tester._generate_query_param_variants(url)
    
    # All variants should preserve the parameter value
    for variant in variants:
        assert "SensitiveValue" in variant


# === Integration with generate_encoding_variants ===

def test_encoding_variants_includes_query_params():
    """Test that generate_encoding_variants includes query param variants."""
    tester = NormalizationTester()
    url = "https://example.com/path?utm_campaign=test&pid=social"
    
    variants = tester.generate_encoding_variants(url)
    
    # Should include both path variants and query param variants
    assert len(variants) > 0
    # Should have at least one uppercase query param variant
    assert any("UTM_CAMPAIGN" in v for v in variants)


def test_encoding_variants_path_only():
    """Test path normalization still works without query params."""
    tester = NormalizationTester()
    url = "https://example.com/path/to/resource"
    
    variants = tester.generate_encoding_variants(url)
    
    # Should still generate path-based variants
    assert len(variants) > 0


# === Cache Key Confusion Detection Tests (Mocked) ===

@pytest.mark.asyncio
async def test_cache_key_confusion_detection():
    """Test that cache key confusion is detected when variant matches baseline."""
    tester = NormalizationTester()
    
    # Mock HTTP client
    client = AsyncMock(spec=HttpClient)
    
    # Mock response with cache HIT
    mock_response = {
        "status": 200,
        "headers": {
            "X-Cache": "Hit from cloudfront",
            "Content-Type": "text/html"
        },
        "body": b"<html>Test Content</html>"
    }
    
    client.request = AsyncMock(return_value=mock_response)
    
    # Baseline fingerprint (same as variant)
    baseline_fingerprint = "test-fingerprint-123"
    
    # Mock CacheGuard to return matching fingerprint and cache hit
    import cpd.logic.normalization as norm_module
    original_fingerprint = norm_module.CacheGuard.fingerprint_response
    original_cache_hit = norm_module.CacheGuard.cache_hit_signal
    
    norm_module.CacheGuard.fingerprint_response = MagicMock(return_value=baseline_fingerprint)
    norm_module.CacheGuard.cache_hit_signal = MagicMock(return_value=(True, ["X-Cache=Hit from cloudfront"]))
    
    try:
        base_url = "https://example.com/page?pid=Social_twitter"
        findings = await tester.test_cache_key_confusion(client, base_url, baseline_fingerprint)
        
        # Should detect cache key normalization
        assert len(findings) > 0
        assert findings[0]["vulnerability"] == "CacheKeyNormalization"
        assert findings[0]["severity"] == "HIGH"
        assert "cache" in findings[0]["details"].lower() and "hit" in findings[0]["details"].lower()
    finally:
        # Restore original methods
        norm_module.CacheGuard.fingerprint_response = original_fingerprint
        norm_module.CacheGuard.cache_hit_signal = original_cache_hit


@pytest.mark.asyncio
async def test_no_false_positive_without_cache_hit():
    """Test that no findings are reported when there's no cache HIT."""
    tester = NormalizationTester()
    
    # Mock HTTP client
    client = AsyncMock(spec=HttpClient)
    
    # Mock response WITHOUT cache HIT
    mock_response = {
        "status": 200,
        "headers": {"Content-Type": "text/html"},
        "body": b"<html>Test Content</html>"
    }
    
    client.request = AsyncMock(return_value=mock_response)
    
    # Mock CacheGuard
    import cpd.logic.normalization as norm_module
    original_fingerprint = norm_module.CacheGuard.fingerprint_response
    original_cache_hit = norm_module.CacheGuard.cache_hit_signal
    
    norm_module.CacheGuard.fingerprint_response = MagicMock(return_value="test-fingerprint-123")
    norm_module.CacheGuard.cache_hit_signal = MagicMock(return_value=(False, []))
    
    try:
        base_url = "https://example.com/page?pid=Social_twitter"
        findings = await tester.test_cache_key_confusion(client, base_url, "test-fingerprint-123")
        
        # Should NOT detect anything (no cache hit)
        assert len(findings) == 0
    finally:
        # Restore original methods
        norm_module.CacheGuard.fingerprint_response = original_fingerprint
        norm_module.CacheGuard.cache_hit_signal = original_cache_hit
