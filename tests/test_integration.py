import pytest_asyncio
import pytest
import asyncio
from aiohttp import web
from cpd.engine import Engine

@pytest.fixture
def mock_server_port():
    return 8081

@pytest_asyncio.fixture
async def mock_server(mock_server_port):
    app = web.Application()
    
    # Store state to simulate cache positioning
    cache = {}
    
    async def handler(request):
        # Simulate a vulnerability on /vulnerable
        # If X-Forwarded-Host is present, reflect it and cache it
        url = str(request.url)
        
        # Check cache
        if url in cache:
            # Serve cached response
            return web.Response(text=cache[url]["body"], headers=cache[url]["headers"])
        
        body = "Hello World"
        headers = {"X-Cache": "MISS"}
        
        if request.path == "/vulnerable":
            xfh = request.headers.get("X-Forwarded-Host")
            if xfh:
                body = f"Hello {xfh}"
                # Cache this malicious response
                cache[url] = {"body": body, "headers": headers}
        
        return web.Response(text=body, headers=headers)

    app.router.add_route('*', '/{tail:.*}', handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, 'localhost', mock_server_port)
    await site.start()
    
    yield f"http://localhost:{mock_server_port}"
    
    await runner.cleanup()

@pytest.mark.asyncio
async def test_integration_full_scan(mock_server):
    """
    Run a full scan against the mock server and expect 1 vulnerability.
    """
    target = f"{mock_server}/vulnerable"
    
    engine = Engine(concurrency=5)
    findings = await engine.run([target])
    
    # We expect at least one finding (X-Forwarded-Host)
    assert len(findings) > 0
    
    found = False
    for f in findings:
        if f["signature"]["name"] == "X-Forwarded-Host":
            found = True
            break
    
    assert found
