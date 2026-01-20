"""
Test HTML reporter functionality.
"""
from cpd.utils.reporter import Reporter
import os
import tempfile


def test_html_report_generation():
    """Test that HTML report generates without errors."""
    sample_findings = [
        {
            "vulnerability": "CacheKeyNormalization",
            "severity": "HIGH",
            "details": "Variant URL returned a cache HIT matching baseline content.",
            "url": "https://example.com/page?pid=Social_twitter",
            "variant_url": "https://example.com/page?PID=SOCIAL_TWITTER",
            "original_url": "https://example.com/page?pid=Social_twitter",
            "target_url": "https://example.com/page?PID=SOCIAL_TWITTER",
            "evidence": ["X-Cache=RefreshHit from cloudfront"],    
            "signature": {
                "name": "CacheKeyNorm-QueryParam",
                "header": "N/A",
                "value": "N/A"
            }
        },
        {
            "vulnerability": "UnkeyedHeader",
            "severity": "CRITICAL",
            "details": "X-Forwarded-Host header is unkeyed and reflected.",
            "url": "https://victim.com",
            "target_url": "https://victim.com?cb=poison123",
            "verify_url": "https://victim.com?cb=poison123",
            "reflected_in": "response body",
            "reflection_context": "<meta property='og:url' content='https://evil.com/pwned'>",
            "payload": "evil.com",
            "evidence": ["X-Cache=Hit", "Age=120"],
            "signature": {
                "name": "X-Forwarded-Host",
                "header": "X-Forwarded-Host",
                "value": "evil.com"
            }
        }
    ]
    
    # Generate report to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        output_path = f.name
    
    try:
        Reporter.generate_html_report(sample_findings, output_path)
        
        # Verify file was created
        assert os.path.exists(output_path)
        
        # Read and verify content
        with open(output_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Basic checks
        assert 'CPD' in html_content and 'Scan Report' in html_content
        assert 'CacheKeyNormalization' in html_content
        assert 'UnkeyedHeader' in html_content
        assert 'HIGH' in html_content
        assert 'CRITICAL' in html_content
        assert 'Proof of Concept' in html_content
        assert 'curl' in html_content
        assert 'Variant URL' in html_content
        assert 'X-Forwarded-Host' in html_content
        assert 'evil.com' in html_content
        
        print(f"✅ HTML report generated successfully: {output_path}")
        print(f"   Report size: {len(html_content)} bytes")
        
    finally:
        # Cleanup
        if os.path.exists(output_path):
            os.remove(output_path)


if __name__ == "__main__":
    test_html_report_generation()
