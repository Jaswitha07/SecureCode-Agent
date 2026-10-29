from src.fence import count_spaces


def test_two_posts():
    assert count_spaces(2) == 1


def test_five_posts():
    assert count_spaces(5) == 4


def test_one_post():
    assert count_spaces(1) == 0
