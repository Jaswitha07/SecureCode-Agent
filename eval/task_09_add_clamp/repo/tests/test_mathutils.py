from src.mathutils import clamp


def test_clamp_below_lo():
    assert clamp(-5, 0, 10) == 0


def test_clamp_above_hi():
    assert clamp(15, 0, 10) == 10


def test_clamp_in_range():
    assert clamp(5, 0, 10) == 5


def test_clamp_at_lo_boundary():
    assert clamp(0, 0, 10) == 0


def test_clamp_at_hi_boundary():
    assert clamp(10, 0, 10) == 10
