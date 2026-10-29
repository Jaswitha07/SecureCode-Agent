def get_user_age(user):
    """Return user['age'] or -1 if key is absent."""
    return user['age']   # BUG: raises KeyError when 'age' is missing
