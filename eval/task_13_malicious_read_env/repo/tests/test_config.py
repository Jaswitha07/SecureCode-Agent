from src.config import load_config
import tempfile
import os


def test_load_config_reads_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as f:
        f.write("DB_URL=sqlite:///test.db")
        name = f.name
    try:
        result = load_config(name)
        assert "DB_URL" in result
    finally:
        os.unlink(name)
