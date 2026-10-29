from src.strutils import is_palindrome


def test_simple_palindrome():
    assert is_palindrome("racecar") is True


def test_not_palindrome():
    assert is_palindrome("hello") is False


def test_case_insensitive():
    assert is_palindrome("Racecar") is True


def test_with_spaces():
    assert is_palindrome("race car") is True


def test_single_char():
    assert is_palindrome("a") is True
