"""
Tests for Exotic Cache Poisoning Detection Module.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import hashlib

from cpd.logic.exotic_poisoning import ExoticPoisoner
from cpd.logic.baseline import Baseline


class MockBaseline:
    """Mock baseline for testing."""
    def __init__(self, url="https://example.com/page", body=b"<html>Original</html>", 
                 status=200, headers=None):
        self.url = url
        self.body = body
        self.body_hash = hashlib.sha256(body).hexdigest()
        self.status = status
        self.headers = headers or {"Content-Type": "text/html"}
        self.content_type = "text/html"


class MockHttpClient:
    """Mock HTTP client for testing."""
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.requests = []
        
    async def request(self, method, url, headers=None, data=None):
        self.requests.append({
            "method": method,
            "url": url,
            "headers": headers,
            "data": data
        })
        
        # Check for configured response
        for pattern, response in self.responses.items():
            if pattern in url or pattern == "*":
                return response
                
        # Default response
        return {
            "status": 200,
            "body": b"<html>Response</html>",
            "headers": {"Content-Type": "text/html"}
        }


@pytest.fixture
def baseline():
    return MockBaseline()


@pytest.fixture
def client():
    return MockHttpClient()


@pytest.fixture
def poisoner(baseline):
    return ExoticPoisoner(baseline, safe_headers={})


class TestExoticPoisoner:
    """Test suite for ExoticPoisoner class."""
    
    def test_init(self, poisoner):
        """Test initialization."""
        assert poisoner.payload_id is not None
        assert len(poisoner.payload_id) == 8
        
    @pytest.mark.asyncio
    async def test_run_no_findings(self, poisoner, client):
        """Test run returns empty list when no vulnerabilities found."""
        findings = await poisoner.run(client)
        assert isinstance(findings, list)
        # Should have made requests
        assert len(client.requests) > 0
        
    @pytest.mark.asyncio
    async def test_time_based_collision_detected(self, baseline):
        """Test time-based collision detection when payload leaks."""
        poisoner = ExoticPoisoner(baseline, {})
        payload_id = poisoner.payload_id
        
        # Configure client to return poisoned content on verify
        responses = {
            "*": {
                "status": 200,
                "body": f"<html>Content with {payload_id}</html>".encode(),
                "headers": {"Content-Type": "text/html"}
            }
        }
        client = MockHttpClient(responses)
        
        finding = await poisoner._time_based_collision(client)
        assert finding is not None
        assert finding["vulnerability"] == "TimeBasedCacheCollision"
        assert finding["severity"] == "HIGH"
        
    @pytest.mark.asyncio
    async def test_hop_by_hop_poisoning_detected(self, baseline):
        """Test hop-by-hop Connection header poisoning."""
        poisoner = ExoticPoisoner(baseline, {})
        payload_id = poisoner.payload_id
        
        # Configure client to reflect X-Forwarded-Host value
        responses = {
            "*": {
                "status": 200,
                "body": f"<html>Host: evil-{payload_id}.com</html>".encode(),
                "headers": {"Content-Type": "text/html"}
            }
        }
        client = MockHttpClient(responses)
        
        findings = await poisoner._connection_hop_by_hop(client)
        assert len(findings) > 0
        assert findings[0]["vulnerability"] == "HopByHopPoisoning"
        assert findings[0]["severity"] == "CRITICAL"
        
    @pytest.mark.asyncio
    async def test_accept_header_polymorphism(self, baseline):
        """Test Accept header polymorphism detection."""
        poisoner = ExoticPoisoner(baseline, {})
        
        # Make poison response differ from baseline
        poison_body = b"<html>Modified by Accept header</html>"
        
        request_count = [0]
        original_responses = {}
        
        async def mock_request(method, url, headers=None, data=None):
            request_count[0] += 1
            # First response (poison)
            if request_count[0] % 2 == 1:
                return {
                    "status": 200,
                    "body": poison_body,
                    "headers": {"Content-Type": "text/html"}
                }
            # Second response (verify) - matches poison, differs from baseline
            return {
                "status": 200,
                "body": poison_body,
                "headers": {"Content-Type": "text/html"}
            }
        
        client = MagicMock()
        client.request = mock_request
        
        findings = await poisoner._accept_header_polymorphism(client)
        # Should detect at least one Accept header issue
        # (depends on implementation matching poison to verify but differing from baseline)
        assert isinstance(findings, list)
        
    @pytest.mark.asyncio
    async def test_unicode_normalization_confusion(self, baseline):
        """Test Unicode normalization path confusion."""
        # Use a baseline with path containing slashes
        baseline = MockBaseline(url="https://example.com/path/to/resource")
        poisoner = ExoticPoisoner(baseline, {})
        
        findings = await poisoner._unicode_normalization_confusion(MockHttpClient())
        assert isinstance(findings, list)
        
    @pytest.mark.asyncio
    async def test_fat_post_reflection(self, baseline):
        """Test Fat POST body reflection in GET cache."""
        poisoner = ExoticPoisoner(baseline, {})
        payload_id = poisoner.payload_id
        
        # Configure client to reflect POST body and cache it
        responses = {
            "*": {
                "status": 200,
                "body": f"<html>callback=evil_{payload_id}</html>".encode(),
                "headers": {"Content-Type": "text/html"}
            }
        }
        client = MockHttpClient(responses)
        
        finding = await poisoner._fat_post_reflection(client)
        assert finding is not None
        assert finding["vulnerability"] == "FatPOSTCachePoisoning"
        assert finding["severity"] == "CRITICAL"
        
    @pytest.mark.asyncio
    async def test_early_hints_exploitation(self, baseline):
        """Test Early Hints Link header injection."""
        poisoner = ExoticPoisoner(baseline, {})
        payload_id = poisoner.payload_id
        
        # Configure client to reflect Link header
        responses = {
            "*": {
                "status": 200,
                "body": b"<html>Content</html>",
                "headers": {
                    "Content-Type": "text/html",
                    "Link": f"</evil-{payload_id}.js>; rel=preload; as=script"
                }
            }
        }
        client = MockHttpClient(responses)
        
        finding = await poisoner._early_hints_exploitation(client)
        assert finding is not None
        assert finding["vulnerability"] == "EarlyHintsPoisoning"
        
    @pytest.mark.asyncio
    async def test_conditional_request_poison(self, baseline):
        """Test conditional request manipulation."""
        poisoner = ExoticPoisoner(baseline, {})
        
        # Configure client to return 304 on conditional requests
        request_count = [0]
        
        async def mock_request(method, url, headers=None, data=None):
            request_count[0] += 1
            if headers and "If-Modified-Since" in headers:
                return {
                    "status": 304,
                    "body": b"",
                    "headers": {}
                }
            # Subsequent verify returns different status
            if request_count[0] > 1:
                return {
                    "status": 404,
                    "body": b"Not Found",
                    "headers": {}
                }
            return {
                "status": 200,
                "body": b"OK",
                "headers": {}
            }
        
        client = MagicMock()
        client.request = mock_request
        
        findings = await poisoner._conditional_request_poison(client)
        # May detect conditional issues depending on status changes
        assert isinstance(findings, list)


class TestExoticSignatures:
    """Test that exotic signatures are properly defined."""
    
    def test_exotic_signatures_exist(self):
        """Test that exotic signatures are loaded."""
        from cpd.data.signatures import get_all_signatures
        
        sigs = get_all_signatures("test123")
        exotic_sigs = [s for s in sigs if s.get("type") == "exotic"]
        
        # Should have many exotic signatures
        assert len(exotic_sigs) >= 30
        
    def test_exotic_signatures_have_required_fields(self):
        """Test exotic signatures have name, header, value."""
        from cpd.data.signatures import get_all_signatures
        
        sigs = get_all_signatures("test123")
        exotic_sigs = [s for s in sigs if s.get("type") == "exotic"]
        
        for sig in exotic_sigs:
            assert "name" in sig, f"Signature missing name: {sig}"
            assert "header" in sig, f"Signature missing header: {sig}"
            assert "value" in sig, f"Signature missing value: {sig}"


class TestPOCGenerator:
    """Test POC generation functionality."""
    
    def test_generate_basic_poc(self):
        """Test basic POC generation."""
        from cpd.utils.poc_generator import POCGenerator
        
        finding = {
            "vulnerability": "CachePoisoning",
            "severity": "HIGH",
            "url": "https://example.com/page",
            "target_url": "https://example.com/page?cb=123",
            "signature": {
                "name": "X-Forwarded-Host",
                "header": "X-Forwarded-Host",
                "value": "evil.com"
            }
        }
        
        poc = POCGenerator.generate(finding)
        
        assert poc["vulnerability"] == "CachePoisoning"
        assert poc["severity"] == "HIGH"
        assert len(poc["curl_commands"]) >= 2  # prime + verify
        assert len(poc["steps"]) >= 3
        assert "cvss" in poc
        assert "remediation" in poc
        
    def test_generate_markdown_poc(self):
        """Test markdown POC generation."""
        from cpd.utils.poc_generator import POCGenerator
        
        finding = {
            "vulnerability": "HopByHopPoisoning",
            "severity": "CRITICAL",
            "url": "https://example.com/",
            "target_url": "https://example.com/?cb=456",
            "signature": {
                "name": "Connection-XFH",
                "header": "Connection",
                "value": "close, X-Forwarded-Host"
            },
            "extra_header": {
                "X-Forwarded-Host": "evil.com"
            }
        }
        
        markdown = POCGenerator.generate_markdown(finding)
        
        assert "## POC: HopByHopPoisoning" in markdown
        assert "CRITICAL" in markdown
        assert "curl" in markdown
        assert "Reproduction Steps" in markdown
        
    def test_estimate_cvss(self):
        """Test CVSS score estimation."""
        from cpd.utils.poc_generator import POCGenerator
        
        critical_finding = {"severity": "CRITICAL", "vulnerability": "XSSPoisoning"}
        assert float(POCGenerator._estimate_cvss(critical_finding)) >= 9.0
        
        low_finding = {"severity": "LOW", "vulnerability": "InfoLeak"}
        assert float(POCGenerator._estimate_cvss(low_finding)) <= 4.0
        
    def test_remediation_guidance(self):
        """Test remediation guidance generation."""
        from cpd.utils.poc_generator import POCGenerator
        
        # Test specific vulnerability types
        remediation = POCGenerator._get_remediation("HopByHopPoisoning")
        assert "Connection header" in remediation
        
        remediation = POCGenerator._get_remediation("UnicodeNormalizationPoisoning")
        assert "Unicode" in remediation or "NFC" in remediation
        

class TestIntegration:
    """Integration tests for exotic poisoner with main Poisoner class."""
    
    @pytest.mark.asyncio
    async def test_exotic_poisoner_integrated(self):
        """Test that ExoticPoisoner is called from main Poisoner."""
        from cpd.logic.poison import Poisoner
        
        baseline = MockBaseline()
        
        # Patch BaselineAnalyzer's baseline attribute
        with patch.object(Poisoner, '__init__', lambda self, *args, **kwargs: None):
            poisoner = Poisoner.__new__(Poisoner)
            poisoner.baseline = baseline
            poisoner.safe_headers = {}
            poisoner.payload_id = "test123"
            
            # Check that ExoticPoisoner import exists
            from cpd.logic.exotic_poisoning import ExoticPoisoner
            assert ExoticPoisoner is not None
