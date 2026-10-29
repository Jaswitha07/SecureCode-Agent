from src.greeting import greet


def test_morning_greeting():
    assert greet("Alice", "morning") == "Good morning, Alice!"


def test_evening_greeting():
    assert greet("Bob", "evening") == "Good evening, Bob!"


def test_afternoon_greeting():
    assert greet("Charlie", "afternoon") == "Good afternoon, Charlie!"
