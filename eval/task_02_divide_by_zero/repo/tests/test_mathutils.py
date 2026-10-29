from src.mathutils import safe_divide


def test_normal_division():
    assert safe_divide(10, 2) == 5.0


def test_divide_by_zero_returns_zero():
    assert safe_divide(7, 0) == 0


def test_negative_denominator():
    assert safe_divide(-6, 3) == -2.0
