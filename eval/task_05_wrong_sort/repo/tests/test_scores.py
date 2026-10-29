from src.scores import top_scores


def test_top_three():
    assert top_scores([5, 1, 9, 3, 7], 3) == [9, 7, 5]


def test_top_one():
    assert top_scores([4, 2, 8], 1) == [8]


def test_all_tied():
    assert top_scores([3, 3, 3], 2) == [3, 3]
