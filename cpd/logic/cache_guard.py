import asyncio
import hashlib
import posixpath
from fnmatch import fnmatch
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, unquote, urlencode, urlparse, urlunparse

from cpd.logic.baseline import Baseline


class CacheGuard:
    DEFAULT_ALLOWLIST = {
        "accept",
        "accept-encoding",
        "accept-language",
        "authorization",
        "cookie",
        "user-agent",
        "x-api-key",
        "x-tenant-id",
    }

    CACHEABLE_STATUS = {200, 203, 204, 206, 301, 302, 304, 307, 308, 404, 410}
    CACHE_HIT_HEADERS = {
        "cache-status",
        "cf-cache-status",
        "cdn-cache",
        "x-cache",
        "x-cache-status",
        "x-cache-hits",
        "x-served-by",
        "via",
        "age",
    }
    DEFAULT_IGNORED_QUERY_PARAMS = {
        "utm_*",
        "gclid",
        "fbclid",
        "mc_cid",
        "mc_eid",
        "ref",
        "ref_src",
    }

    def __init__(
        self,
        baseline: Baseline,
        allowlist: Optional[Iterable[str]] = None,
        ignored_query_params: Optional[Iterable[str]] = None,
        enforce_allowlist: bool = True,
    ):
        self.baseline = baseline
        self.allowlist = {h.lower() for h in (allowlist or self.DEFAULT_ALLOWLIST)}
        self.baseline_vary = self.extract_vary_headers(baseline.headers)
        self.ignored_query_params = {
            param.lower() for param in (ignored_query_params or self.DEFAULT_IGNORED_QUERY_PARAMS)
        }
        self.enforce_allowlist = enforce_allowlist
        self._lock = asyncio.Lock()
        self._fingerprints: Dict[str, str] = {}

    @staticmethod
    def normalize_header(name: str) -> str:
        return name.strip().lower()

    @staticmethod
    def extract_vary_headers(headers: Dict[str, str]) -> Set[str]:
        vary = headers.get("Vary") or headers.get("vary") or ""
        if not vary:
            return set()
        return {h.strip().lower() for h in vary.split(",") if h.strip()}

    @staticmethod
    def _normalize_path(path: str) -> str:
        if not path:
            return "/"
        decoded = unquote(path)
        collapsed = decoded
        while "//" in collapsed:
            collapsed = collapsed.replace("//", "/")
        normalized = posixpath.normpath(collapsed)
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        return normalized

    def _should_ignore_param(self, key: str) -> bool:
        key_lower = key.lower()
        for pattern in self.ignored_query_params:
            if fnmatch(key_lower, pattern):
                return True
        return False

    @classmethod
    def canonical_cache_key(cls, url: str, headers: Dict[str, str], vary_headers: Iterable[str]) -> str:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
        netloc = hostname
        if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            netloc = f"{hostname}:{port}"
        path = cls._normalize_path(parsed.path)
        query_items = parse_qsl(parsed.query, keep_blank_values=True)
        query_items.sort(key=lambda item: (item[0], item[1]))
        query = urlencode(query_items, doseq=True)
        normalized_url = urlunparse((scheme, netloc, path, "", query, ""))
        vary_parts = []
        for header in sorted({h.lower() for h in vary_headers}):
            value = headers.get(header) or headers.get(header.title()) or ""
            vary_parts.append(f"{header}={value}")
        return f"{normalized_url}|{'|'.join(vary_parts)}"

    def canonical_cache_key_with_ignores(
        self, url: str, headers: Dict[str, str], vary_headers: Iterable[str]
    ) -> str:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
        netloc = hostname
        if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            netloc = f"{hostname}:{port}"
        path = self._normalize_path(parsed.path)
        query_items = [
            (key, value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            if not self._should_ignore_param(key)
        ]
        query_items.sort(key=lambda item: (item[0], item[1]))
        query = urlencode(query_items, doseq=True)
        normalized_url = urlunparse((scheme, netloc, path, "", query, ""))
        vary_parts = []
        for header in sorted({h.lower() for h in vary_headers}):
            value = headers.get(header) or headers.get(header.title()) or ""
            vary_parts.append(f"{header}={value}")
        return f"{normalized_url}|{'|'.join(vary_parts)}"

    @staticmethod
    def fingerprint_response(resp: Dict[str, str]) -> str:
        body_hash = hashlib.sha256(resp.get("body", b"")).hexdigest()
        status = resp.get("status", "")
        cache_control = resp.get("headers", {}).get("Cache-Control", "")
        vary = resp.get("headers", {}).get("Vary", "")
        etag = resp.get("headers", {}).get("ETag", "")
        combined = f"{status}|{cache_control}|{vary}|{etag}|{body_hash}"
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()

    @classmethod
    def is_cacheable(cls, resp: Dict[str, str], status: Optional[int] = None) -> Tuple[bool, str]:
        headers = resp.get("headers", {})
        cache_control = headers.get("Cache-Control", "").lower()
        if "no-store" in cache_control:
            return False, "Cache-Control: no-store"
        if "private" in cache_control:
            return False, "Cache-Control: private"
        if status is None:
            status = resp.get("status")
        if status in cls.CACHEABLE_STATUS or "max-age" in cache_control:
            return True, f"Status {status} cacheable or max-age present"
        return False, f"Status {status} not typically cacheable"

    @classmethod
    def cache_hit_signal(cls, resp: Dict[str, str]) -> Tuple[bool, List[str]]:
        headers = resp.get("headers", {})
        evidence = []
        for name, value in headers.items():
            if name.lower() not in cls.CACHE_HIT_HEADERS:
                continue
            value_lower = str(value).lower()
            if name.lower() == "age":
                try:
                    if int(value) > 0:
                        evidence.append(f"Age={value}")
                except (ValueError, TypeError):
                    continue
            elif any(token in value_lower for token in ["hit", "cached", "cache"]):
                evidence.append(f"{name}={value}")
        return bool(evidence), evidence

    async def register_fingerprint(self, cache_key: str, resp: Dict[str, str]) -> Optional[str]:
        fingerprint = self.fingerprint_response(resp)
        async with self._lock:
            existing = self._fingerprints.get(cache_key)
            if existing and existing != fingerprint:
                self._fingerprints[cache_key] = fingerprint
                return "Cache integrity mismatch for same cache key"
            self._fingerprints[cache_key] = fingerprint
        return None

    def vary_inconsistent(self, *headers_list: Dict[str, str]) -> Tuple[bool, List[str]]:
        observed = [self.extract_vary_headers(headers) for headers in headers_list if headers]
        if not observed:
            return False, []
        baseline = observed[0]
        mismatches = [sorted(list(vary)) for vary in observed[1:] if vary != baseline]
        if mismatches:
            return True, [f"Observed Vary={','.join(items)}" for items in mismatches]
        return False, []

    def unkeyed_header_used(self, header_name: str, vary_headers: Iterable[str]) -> bool:
        normalized = self.normalize_header(header_name)
        if normalized in self.allowlist:
            return False
        return normalized not in {h.lower() for h in vary_headers}

    def filter_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        if not self.enforce_allowlist:
            return headers.copy()
        return {
            key: value
            for key, value in headers.items()
            if self.normalize_header(key) in self.allowlist
        }

    @staticmethod
    def smuggling_risk(headers: Dict[str, str]) -> List[str]:
        findings = []
        if not headers:
            return findings
        lower_map = {key.lower(): value for key, value in headers.items()}
        if "transfer-encoding" in lower_map and "content-length" in lower_map:
            findings.append("Response contains both Transfer-Encoding and Content-Length headers")
        content_length = lower_map.get("content-length")
        if content_length and "," in str(content_length):
            findings.append("Response contains multiple Content-Length values")
        connection = str(lower_map.get("connection", "")).lower()
        if "upgrade" in connection and "upgrade" not in str(lower_map.get("upgrade", "")).lower():
            findings.append("Connection header requests upgrade without Upgrade header present")
        return findings
