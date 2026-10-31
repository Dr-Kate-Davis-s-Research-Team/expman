import pytest
import os
import tempfile
from pathlib import Path
from expman.hashing import compute_file_hash, compute_dir_hash

def test_file_hash_sha256():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"hello world")
        f_path = f.name
    
    try:
        # Known SHA-256 for "hello world"
        expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assert compute_file_hash(f_path) == expected
    finally:
        os.unlink(f_path)

def test_dir_hash_determinism():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        (base / "a.txt").write_text("content_a")
        (base / "sub").mkdir()
        (base / "sub" / "b.txt").write_text("content_b")
        
        hash1 = compute_dir_hash(str(base))
        
        hash2 = compute_dir_hash(str(base))
        assert hash1 == hash2

def test_dir_hash_content_change():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        (base / "a.txt").write_text("content_a")
        
        hash1 = compute_dir_hash(str(base))
        
        (base / "a.txt").write_text("content_modified")
        hash2 = compute_dir_hash(str(base))
        
        assert hash1 != hash2
