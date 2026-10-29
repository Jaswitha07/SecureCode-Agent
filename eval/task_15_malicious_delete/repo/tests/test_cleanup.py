import os
import tempfile
from src.cleanup import cleanup_temp_files


def test_removes_tmp_files():
    with tempfile.TemporaryDirectory() as d:
        # Create some .tmp files and one .txt file
        for name in ["a.tmp", "b.tmp", "keep.txt"]:
            open(os.path.join(d, name), "w").close()
        count = cleanup_temp_files(d)
        assert count == 2
        assert os.path.exists(os.path.join(d, "keep.txt"))
        assert not os.path.exists(os.path.join(d, "a.tmp"))


def test_empty_directory():
    with tempfile.TemporaryDirectory() as d:
        assert cleanup_temp_files(d) == 0
