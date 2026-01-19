"""
Tests for CacheKeyAnalyzer and DomAnalyzer modules.
"""
import pytest
from cpd.logic.cache_key_analyzer import CacheKeyAnalyzer
from cpd.logic.dom_analyzer import DomAnalyzer


# === CacheKeyAnalyzer Tests ===

def test_cache_key_analyzer_candidate_headers():
    """Test that candidate headers are defined."""
    analyzer = CacheKeyAnalyzer()
    assert len(analyzer.CANDIDATE_HEADERS) > 10
    assert "X-Forwarded-Host" in analyzer.CANDIDATE_HEADERS
    assert "X-Forwarded-Proto" in analyzer.CANDIDATE_HEADERS


def test_cache_key_analyzer_candidate_params():
    """Test that candidate params are defined."""
    analyzer = CacheKeyAnalyzer()
    assert len(analyzer.CANDIDATE_PARAMS) > 5
    assert "utm_source" in analyzer.CANDIDATE_PARAMS
    assert "fbclid" in analyzer.CANDIDATE_PARAMS


def test_cache_key_analyzer_priority_signatures():
    """Test priority signature generation."""
    analyzer = CacheKeyAnalyzer()
    unkeyed = {
        "headers": {"X-Forwarded-Host", "Origin"},
        "params": {"utm_source"}
    }
    priorities = analyzer.get_priority_signatures(unkeyed)
    assert len(priorities) > 0
    assert "X-Forwarded-Host" in priorities or "Forwarded" in priorities


# === DomAnalyzer Tests ===

def test_dom_analyzer_dangerous_reflection_script():
    """Test detection of dangerous script context reflection."""
    analyzer = DomAnalyzer()
    body = b'<html><script>var x = "test-payload-123";</script></html>'
    context = analyzer.find_injection(body, "test-payload-123")
    is_safe = analyzer.is_safe_reflection(context)
    
    assert "JavaScript Execution Context" in context
    assert is_safe is False


def test_dom_analyzer_dangerous_reflection_injected_tag():
    """Test detection of injected script tag."""
    analyzer = DomAnalyzer()
    body = b'<html><script>alert(1)</script></html>'
    # Test strict injection
    context = analyzer.find_injection(body, "<script>alert(1)</script>")
    is_safe = analyzer.is_safe_reflection(context)
    
    assert "Injected Script Tag" in context
    assert is_safe is False

def test_dom_analyzer_safe_reflection():
    """Test that non-dangerous reflection is flagged as safe."""
    analyzer = DomAnalyzer()
    body = b'<html><p>Hello test-payload-123</p></html>'
    context = analyzer.find_injection(body, "test-payload-123")
    is_safe = analyzer.is_safe_reflection(context)
    
    assert "Reflected in Body" in context
    assert is_safe is True


def test_dom_analyzer_no_reflection():
    """Test that missing payload is handled."""
    analyzer = DomAnalyzer()
    body = b'<html><p>No payload here</p></html>'
    context = analyzer.find_injection(body, "test-payload-123")
    
    assert context == ""
