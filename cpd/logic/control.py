"""
Control probes and cache-buster-aware hashing.

Every poisoning technique appends its own cache buster (``?cb=...``) so that it
gets a fresh cache entry to work with. The response to such a probe must NOT be
compared against ``Baseline.body_hash``, which was captured on the *clean* URL:
any application that reflects the query string back into the page -- Drupal's
``drupal-settings-json.currentQuery``, Next.js ``__NEXT_DATA__``, Rails, most
analytics bootstraps -- then differs from the baseline on *every* probe, so
*every* signature fires. That is a guaranteed false positive, not a finding.

Two primitives fix the whole class:

``stable_hash``   neutralises our own cache-buster token before hashing, so a
                  reflected buster cannot masquerade as a content change.
``control_probe`` fetches a second cache-busted copy with clean headers. That,
                  not the clean-URL baseline, is the correct reference for
                  "did my header actually change anything?".
"""

import hashlib
import json
import random
import time
from typing import Dict, Optional, Tuple
from urllib.parse import quote

CB_PLACEHOLDER = b"__CPD_CB__"


def new_cb() -> Tuple[str, str]:
    """
    Return a ``(name, value)`` cache-buster pair.

    The value is fixed-width on purpose: if the target reflects it, the
    reflection occupies the same number of bytes on every probe, so a
    length-based comparison never shifts underneath us.
    """
    return "cb", f"{int(time.time()):010d}{random.randint(10**9, 10**10 - 1)}"


def add_cb(url: str, name: str, value: str) -> str:
    """Append a cache buster to ``url``."""
    return f"{url}{'&' if '?' in url else '?'}{name}={value}"


def _token_variants(token: str):
    """Yield the encodings a reflected token can plausibly appear in."""
    yield token
    yield quote(token, safe="")
    yield json.dumps(token)[1:-1]  # JSON \u-escaped form


def stable_hash(body: bytes, *tokens: str) -> str:
    """
    SHA-256 of ``body`` with our own cache-buster ``tokens`` neutralised.

    Use this instead of a raw ``sha256(body)`` whenever the body came from a
    cache-busted URL and is about to be compared against a body fetched under a
    different buster.
    """
    data = body or b""
    for token in tokens:
        if not token:
            continue
        for variant in _token_variants(token):
            data = data.replace(variant.encode(), CB_PLACEHOLDER)
    return hashlib.sha256(data).hexdigest()


async def control_probe(
    client, url: str, safe_headers: Optional[Dict[str, str]] = None
) -> Optional[Tuple[str, Dict]]:
    """
    Fetch a fresh cache-busted copy of ``url`` with clean headers.

    Returns ``(stable_hash, response)`` or ``None`` if the request failed.
    This is the reference a probe should compare against -- see module docstring.

    A transport error yields ``None`` rather than propagating: losing the
    control means a technique cannot conclude anything, which is a skip, not a
    scan-aborting error.
    """
    name, value = new_cb()
    try:
        resp = await client.request("GET", add_cb(url, name, value), headers=safe_headers or {})
    except Exception:
        return None
    if not resp:
        return None
    return stable_hash(resp.get("body", b""), value), resp
