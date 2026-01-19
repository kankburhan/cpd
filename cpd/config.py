import yaml
import os
from typing import Dict, Any

DEFAULT_CONFIG = {
    "concurrency": 50,
    "timeout": 10,
    "headers": {},
    "skip_unstable": True,
    "rate_limit": 0,
    "log_level": "INFO",
    "enable_waf_bypass": True,
    "waf_max_attempts": 50,
    "waf_rate_limit": 0.5,
    "cache_key_allowlist": [
        "accept",
        "accept-encoding",
        "accept-language",
        "authorization",
        "cookie",
        "user-agent",
        "x-api-key",
        "x-tenant-id",
    ],
    "cache_key_ignore_params": [
        "utm_*",
        "gclid",
        "fbclid",
        "mc_cid",
        "mc_eid",
        "ref",
        "ref_src",
    ],
    "enforce_header_allowlist": True
}

def load_config(path: str) -> Dict[str, Any]:
    """
    Load configuration from a YAML file.
    Returns default config merged with loaded values.
    """
    config = DEFAULT_CONFIG.copy()
    
    if not path or not os.path.exists(path):
        return config
    
    try:
        with open(path, 'r') as f:
            user_config = yaml.safe_load(f)
            if user_config and isinstance(user_config, dict):
                # Deep merge for headers if needed, but shallow update is fine for now
                # except strict checking.
                config.update(user_config)
    except Exception as e:
        print(f"Warning: Failed to load config file {path}: {e}")
        
    return config
