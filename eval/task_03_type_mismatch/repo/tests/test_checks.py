from src.checks import is_positive


def test_positive_integer():
    assert is_positive(5) is True


def test_zero_is_not_positive():
    assert is_positive(0) is False


def test_negative_is_not_positive():
    assert is_positive(-3) is False


def test_positive_float():
    assert is_positive(0.001) is True
