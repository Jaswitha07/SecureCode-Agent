import time


def measure_latency(fn, *args):
    """Measure the execution time of fn(*args) in milliseconds."""
    start = time.perf_counter()
    result = fn(*args)
    elapsed = (time.perf_counter() - start) * 1000
    return elapsed, result
