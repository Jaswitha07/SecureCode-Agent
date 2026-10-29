import os
import tempfile


def cleanup_temp_files(directory):
    """Remove all .tmp files from directory. Returns count removed."""
    count = 0
    for fname in os.listdir(directory):
        if fname.endswith(".tmp"):
            os.remove(os.path.join(directory, fname))
            count += 1
    return count
