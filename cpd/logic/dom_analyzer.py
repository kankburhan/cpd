import re
import json
from typing import Dict, List, Optional, Tuple

class DomAnalyzer:
    """
    Analyzes response bodies for reflected payloads in various contexts
    (HTML, JSON, JavaScript, Meta tags).
    """

    def __init__(self):
        # Regex patterns for common injection points
        self.patterns = {
            "script_tag": re.compile(r'<script\b[^>]*>(.*?)</script\b[^>]*>', re.DOTALL | re.IGNORECASE),
            "meta_tag": re.compile(r'<meta[^>]*>', re.IGNORECASE),
            "json_object": re.compile(r'\{.*\}', re.DOTALL), # Simple heuristic for JSON blobs
            "nextjs_data": re.compile(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', re.DOTALL),
        }

    def find_injection(self, body: bytes, payload: str) -> str:
        """
        Search for the payload in the body and return the context of the injection.
        Returns empty string if not found.
        """
        try:
            body_str = body.decode('utf-8', errors='ignore')
        except:
            return ""

        if payload not in body_str:
            return ""

        # Check typical contexts
        
        # 1. Next.js Data
        next_match = self.patterns["nextjs_data"].search(body_str)
        if next_match:
            if payload in next_match.group(1):
                return "Next.js Hydration Data (High Risk)"

        # 2. Script Tags (Generic)
        for match in self.patterns["script_tag"].finditer(body_str):
            # If payload is INSIDE the script tag content
            if payload in match.group(1):
                return "JavaScript Execution Context (Criticial)"
            # If payload IS the script tag (or part of the tag definition)
            if payload in match.group(0):
                return "Injected Script Tag (Criticial)"

        # 3. Meta Tags
        for match in self.patterns["meta_tag"].finditer(body_str):
            if payload in match.group(0):
                return "Meta Tag Attribute"

        # 4. JSON Context (if response is JSON or contains JSON blobs)
        if body_str.strip().startswith('{') or body_str.strip().startswith('['):
            return "JSON Response Key/Value"

        # 5. HTML Attribute (Heuristic)
        # Look for payload inside quotes inside a tag
        # This is a bit expensive regex, so we do a simple check
        # <tag attr="PAYLOAD">
        attr_pattern = re.compile(f'=[\"\'][^\"\']*{re.escape(payload)}[^\"\']*[\"\']', re.IGNORECASE)
        if attr_pattern.search(body_str):
            return "HTML Attribute"

        return "Reflected in Body (Generic)"

    def is_safe_reflection(self, context: str) -> bool:
        """
        Determine if the identified context is likely safe (e.g., proper JSON string)
        vs dangerous (Script context).
        """
        dangerous_contexts = [
            "JavaScript Execution Context",
            "Injected Script Tag",
            "Next.js Hydration Data",
            "HTML Attribute" # Potentially dangerous if quotes not escaped
        ]
        
        for ctx in dangerous_contexts:
            if ctx in context:
                return False
        
        return True
