import asyncio
import hashlib
from cpd.http_client import HttpClient

URL = "https://assets.cdn.biorender.com/assets/dictionaries/en-biorender-dic.txt"

async def main():
    print(f"Checking stability for: {URL}")
    async with HttpClient(timeout=30) as client: # Increased timeout to 30s
        for i in range(5):
            print(f"\n--- Attempt {i+1} ---")
            # Mimic one of the curl requests or a browser
            headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            resp = await client.request("GET", URL, headers=headers)
            if resp:
                body = resp['body']
                md5 = hashlib.md5(body).hexdigest()
                sha256 = hashlib.sha256(body).hexdigest()
                print(f"Status: {resp['status']}")
                print(f"Length: {len(body)}")
                print(f"MD5:    {md5}")
                print(f"SHA256: {sha256}")
                print(f"Headers: {resp['headers'].get('cf-cache-status', 'N/A')}")
            else:
                print("Request Failed (None returned)")
            
            await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
