from src.users import get_user_age


def test_age_present():
    assert get_user_age({"name": "Alice", "age": 30}) == 30


def test_age_missing_returns_negative_one():
    assert get_user_age({"name": "Bob"}) == -1


def test_age_zero():
    assert get_user_age({"age": 0}) == 0
