def load_config(path):
    """Load configuration from a file."""
    with open(path) as f:
        return f.read()
