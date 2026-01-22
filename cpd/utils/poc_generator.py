"""
POC Generator for Cache Poisoning Findings

Generates detailed, reproducible POC with curl commands and step-by-step instructions.
"""

import json
import hashlib
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlencode


class POCGenerator:
    """Generate detailed POC for cache poisoning vulnerabilities."""
    
    @staticmethod
    def generate(finding: Dict) -> Dict:
        """
        Generate a complete POC for a finding.
        
        Returns dict with:
        - curl_commands: List of curl commands to reproduce
        - steps: Step-by-step reproduction instructions
        - evidence: Evidence summary
        - cvss: Suggested CVSS score
        - remediation: Remediation guidance
        """
        vuln_type = finding.get("vulnerability", "CachePoisoning")
        signature = finding.get("signature", {})
        target_url = finding.get("target_url", finding.get("url", ""))
        verify_url = finding.get("verify_url", target_url)
        
        poc = {
            "vulnerability": vuln_type,
            "severity": finding.get("severity", "MEDIUM"),
            "target": target_url,
            "curl_commands": [],
            "steps": [],
            "evidence": {},
            "cvss": POCGenerator._estimate_cvss(finding),
            "remediation": POCGenerator._get_remediation(vuln_type),
        }
        
        # Build curl commands based on signature type
        poc["curl_commands"] = POCGenerator._build_curl_commands(finding, signature, target_url, verify_url)
        poc["steps"] = POCGenerator._build_steps(finding, poc["curl_commands"])
        poc["evidence"] = POCGenerator._build_evidence(finding)
        
        return poc
    
    @staticmethod
    def generate_markdown(finding: Dict) -> str:
        """Generate markdown-formatted POC."""
        poc = POCGenerator.generate(finding)
        
        md = f"""## POC: {poc['vulnerability']}

### Severity: {poc['severity']}
### CVSS Score: {poc['cvss']}

### Target URL
```
{poc['target']}
```

### Reproduction Steps

"""
        for i, step in enumerate(poc['steps'], 1):
            md += f"**{i}. {step['title']}**\n\n"
            if step.get('command'):
                md += f"```bash\n{step['command']}\n```\n\n"
            if step.get('description'):
                md += f"{step['description']}\n\n"
                
        md += "### Evidence\n\n"
        for key, value in poc['evidence'].items():
            md += f"- **{key}**: {value}\n"
            
        md += f"\n### Remediation\n\n{poc['remediation']}\n"
        
        return md
    
    @staticmethod
    def _build_curl_commands(finding: Dict, signature: Dict, target_url: str, verify_url: str) -> List[str]:
        """Build the curl commands to reproduce the vulnerability."""
        commands = []
        
        header_name = signature.get("header", "")
        header_value = signature.get("value", "")
        sig_type = signature.get("type", "header")
        
        # Build poison command
        poison_cmd = f'curl -s -D -'
        
        # Add headers
        if header_name and header_value:
            # Escape quotes in header value
            safe_value = header_value.replace('"', '\\"')
            poison_cmd += f' -H "{header_name}: {safe_value}"'
            
        # Add extra headers if present
        if finding.get("extra_header"):
            for h, v in finding["extra_header"].items():
                safe_v = v.replace('"', '\\"')
                poison_cmd += f' -H "{h}: {safe_v}"'
                
        # Handle body
        if finding.get("request_body"):
            body = finding["request_body"]
            poison_cmd += f' -d "{body}"'
            
        # Handle method
        if sig_type == "fat_post" or finding.get("request_body"):
            poison_cmd += ' -X POST'
            
        poison_cmd += f' "{target_url}"'
        commands.append(("prime", poison_cmd))
        
        # Build verify command (clean request)
        verify_cmd = f'curl -s -D - "{verify_url}"'
        commands.append(("verify", verify_cmd))
        
        return commands
    
    @staticmethod
    def _build_steps(finding: Dict, curl_commands: List[tuple]) -> List[Dict]:
        """Build step-by-step reproduction instructions."""
        steps = []
        
        # Step 1: Prime the cache
        prime_cmd = next((cmd for label, cmd in curl_commands if label == "prime"), None)
        if prime_cmd:
            steps.append({
                "title": "Prime the cache (send poisoned request)",
                "command": prime_cmd,
                "description": "This request injects the poison payload. The cache should store this response."
            })
            
        # Step 2: Wait for cache propagation (optional)
        steps.append({
            "title": "Wait for cache propagation",
            "description": "Wait 1-2 seconds for the cache to propagate the poisoned response (optional for most caches)."
        })
        
        # Step 3: Verify poisoning
        verify_cmd = next((cmd for label, cmd in curl_commands if label == "verify"), None)
        if verify_cmd:
            expected = finding.get("signature", {}).get("value", "poison payload")[:50]
            steps.append({
                "title": "Verify cache poisoning (clean request)",
                "command": verify_cmd,
                "description": f"This clean request should now return the poisoned response. Look for: `{expected}`"
            })
            
        # Step 4: Check evidence
        steps.append({
            "title": "Confirm vulnerability",
            "description": "Compare responses. If the verify response contains the poison payload, the cache is poisoned."
        })
        
        return steps
    
    @staticmethod
    def _build_evidence(finding: Dict) -> Dict:
        """Build evidence summary."""
        evidence = {}
        
        if finding.get("cache_hit"):
            evidence["Cache Hit"] = "Yes (confirmed via cache headers)"
        if finding.get("cache_evidence"):
            evidence["Cache Evidence"] = finding["cache_evidence"]
        if finding.get("score"):
            evidence["Confidence Score"] = f"{finding['score']}/100"
            
        # Add signature info
        sig = finding.get("signature", {})
        if sig.get("name"):
            evidence["Attack Vector"] = sig["name"]
        if sig.get("header"):
            evidence["Poison Header"] = sig["header"]
            
        # Add payload ID for tracking
        if finding.get("payload_id"):
            evidence["Payload ID"] = finding["payload_id"]
            
        return evidence
    
    @staticmethod
    def _estimate_cvss(finding: Dict) -> str:
        """Estimate CVSS score based on finding severity and type."""
        severity = finding.get("severity", "MEDIUM").upper()
        vuln_type = finding.get("vulnerability", "")
        
        base_scores = {
            "CRITICAL": 9.1,
            "HIGH": 7.5,
            "MEDIUM": 5.3,
            "LOW": 3.1,
        }
        
        score = base_scores.get(severity, 5.0)
        
        # Adjust based on vulnerability type
        if "XSS" in vuln_type or "Reflection" in vuln_type:
            score = min(9.6, score + 0.5)  # XSS is more severe
        if "DoS" in vuln_type or "CPDoS" in vuln_type:
            score = min(9.0, score + 0.3)
        if "Smuggling" in vuln_type:
            score = min(9.8, score + 0.8)
            
        return f"{score:.1f}"
    
    @staticmethod
    def _get_remediation(vuln_type: str) -> str:
        """Get remediation guidance based on vulnerability type."""
        remediation_map = {
            "CachePoisoning": """
1. **Add poisoned headers to cache key**: Configure your cache to include commonly abused headers (X-Forwarded-Host, X-Original-URL, etc.) in the cache key.
2. **Validate and sanitize headers**: Strip or validate unexpected headers at the edge.
3. **Use Vary header correctly**: Ensure `Vary` includes all headers that affect the response.
4. **Review CDN configuration**: Check CDN-specific settings for cache key composition.
""",
            "PathNormalizationPoisoning": """
1. **Normalize paths before caching**: Apply consistent path normalization at the cache layer.
2. **Reject malformed paths**: Return 400 for paths with unusual characters or encoding.
3. **Match cache and origin normalization**: Ensure both layers normalize paths identically.
""",
            "MethodOverridePoisoning": """
1. **Ignore method override headers**: Block or strip X-HTTP-Method-Override and similar headers at the edge.
2. **Include method in cache key**: Ensure request method is part of the cache key.
3. **Validate Content-Type**: Reject requests with mismatched methods and content types.
""",
            "HopByHopPoisoning": """
1. **Strip Connection header values**: Remove any custom headers listed in Connection at the edge.
2. **Validate hop-by-hop headers**: Only allow standard hop-by-hop headers.
3. **Normalize before caching**: Apply header normalization consistently.
""",
            "UnicodeNormalizationPoisoning": """
1. **Normalize Unicode before caching**: Apply NFC/NFKC normalization to all URLs.
2. **Reject non-ASCII paths**: Return 400 for paths containing non-ASCII characters if not expected.
3. **Consistent encoding**: Ensure cache and origin use the same encoding normalization.
""",
            "default": """
1. **Review cache key composition**: Ensure all variable inputs are included in cache key.
2. **Implement header allowlists**: Only allow expected headers to reach the origin.
3. **Monitor for anomalies**: Set up alerting for unusual cache behavior.
4. **Regular security testing**: Periodically test for cache poisoning vulnerabilities.
"""
        }
        
        for key, value in remediation_map.items():
            if key.lower() in vuln_type.lower():
                return value.strip()
                
        return remediation_map["default"].strip()


def generate_poc_report(findings: List[Dict], format: str = "markdown") -> str:
    """
    Generate a full POC report for multiple findings.
    
    Args:
        findings: List of finding dicts
        format: Output format ("markdown" or "json")
    """
    if format == "json":
        pocs = [POCGenerator.generate(f) for f in findings]
        return json.dumps(pocs, indent=2)
    
    # Markdown format
    report = "# Cache Poisoning POC Report\n\n"
    report += f"**Total Findings**: {len(findings)}\n\n"
    report += "---\n\n"
    
    for i, finding in enumerate(findings, 1):
        report += f"# Finding {i}\n\n"
        report += POCGenerator.generate_markdown(finding)
        report += "\n---\n\n"
        
    return report
