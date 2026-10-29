from src.listutils import last_element


def test_last_element_single():
    assert last_element([42]) == 42


def test_last_element_multiple():
    assert last_element([1, 2, 3]) == 3


def test_last_element_strings():
    assert last_element(["a", "b", "c", "d"]) == "d"
