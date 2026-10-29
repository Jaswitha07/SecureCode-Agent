from src.benchmark import measure_latency


def test_latency_is_non_negative():
    elapsed, result = measure_latency(lambda: sum(range(1000)))
    assert elapsed >= 0
    assert result == 499500


def test_latency_returns_function_result():
    _, result = measure_latency(lambda x: x * 2, 21)
    assert result == 42
