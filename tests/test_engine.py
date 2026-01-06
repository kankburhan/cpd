import pytest
import asyncio
from cpd.engine import Engine
from unittest.mock import AsyncMock, MagicMock, patch

@pytest.mark.asyncio
async def test_engine_concurrency():
    """
    Test that the engine limits concurrency using the semaphore.
    """
    # Create an engine with concurrency 2
    engine = Engine(concurrency=2)
    
    # Mock BaselineAnalyzer to take time
    async def mock_analyze(client, url):
        await asyncio.sleep(0.1)
        return MagicMock(is_stable=True, body_hash="abc", status=200)

    targets = ["http://test1.com", "http://test2.com", "http://test3.com", "http://test4.com"]
    
    # We patch BaselineAnalyzer.analyze. Note: It's imported inside _process_url
    # So we patch where it is defined
    with patch('cpd.logic.baseline.BaselineAnalyzer.analyze', side_effect=mock_analyze):
        with patch('cpd.logic.poison.Poisoner.run', return_value=[]): # Skip poisoning
             with patch('cpd.engine.HttpClient') as MockClient:
                mock_client_instance = AsyncMock()
                MockClient.return_value.__aenter__.return_value = mock_client_instance
                
                start_time = asyncio.get_event_loop().time()
                results = await engine.run(targets)
                end_time = asyncio.get_event_loop().time()
                
                # With concurrency 2 and 4 tasks taking 0.1s each, it should take approx 0.2s total
                duration = end_time - start_time
                assert duration >= 0.2
                assert duration < 0.35 # Should be close to 0.2s


