def top_scores(scores, n):
    """Return the top n scores in descending order."""
    return sorted(scores)[:n]   # BUG: sorts ascending, should be descending
