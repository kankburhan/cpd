import math
from typing import Dict, Any

class FalsePositiveFilter:
    """
    Uses heuristics and entropy analysis to score findings and filter out
    likely false positives.
    """

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of the data."""
        if not data:
            return 0.0
        
        entropy = 0.0
        length = len(data)
        
        # Count byte occurrences
        counts = {}
        for byte in data:
            counts[byte] = counts.get(byte, 0) + 1
            
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
            
        return entropy

    def calculate_suspicion_score(self, finding: Dict[str, Any]) -> int:
        """
        Calculate a suspicion score (0-100) for a finding.
        Higher score = More likely to be a valid/critical vulnerability.
        """
        score = 0
        
        # 1. Base Score based on component severity
        severity = finding.get('severity', 'LOW')
        if severity == 'CRITICAL':
            score += 40
        elif severity == 'HIGH':
            score += 30
        elif severity == 'MEDIUM':
            score += 20
        else:
            score += 10
            
        # 2. Cache Evidence
        if finding.get('cache_hit'):
            score += 25 # High confidence if we actually hit the cache
        elif finding.get('cacheable'):
            score += 10 # Potentially exploitable
            
        # 3. Payload Reflection Verification
        # If the specific payload was found in the body of the verified request
        verify_body = str(finding.get('verify_body', '')) # Warning: verify_body might not be in finding dict yet
        signature = finding.get('signature', {})
        payload_val = signature.get('value', '')
        
        if payload_val and payload_val in verify_body:
             score += 20
             
        # 4. Entropy Analysis (Heuristic for "garbage" vs "content")
        # Very high entropy might indicate compressed data or encryption, 
        # but sudden entropy changes in simple text endpoints can be suspicious (or FP).
        # This is experimental.
        # body_entropy = self.calculate_entropy(finding.get('verify_body_bytes', b''))
        # if body_entropy > 7.5:
        #     score += 5 

        # 5. Unkeyed Header Usage
        if finding.get('unkeyed_header'):
            score += 15

        return min(score, 100)
