import hashlib
import os
import logging
from typing import List

logger = logging.getLogger("expman")

def compute_file_hash(path: str, alg: str = "sha256") -> str:
    """
    Computes the SHA-256 hash of a file using chunked reading for memory efficiency.
    
    Args:
        path: Path to the file.
        alg: Hash algorithm to use (default: sha256).
    
    Returns:
        Hex string of the hash.
        
    Raises:
        FileNotFoundError: If file does not exist.
        PermissionError: If file cannot be read.
        ValueError: If algorithm is not supported.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File not found: {path}")

    try:
        hash_func = hashlib.new(alg)
    except ValueError:
        raise ValueError(f"Unsupported hash algorithm: {alg}")

    try:
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hash_func.update(chunk)
    except PermissionError:
        logger.error(f"Permission denied reading file: {path}")
        raise

    return hash_func.hexdigest()

def compute_dir_hash(path: str, alg: str = "sha256") -> str:
    """
    Computes a deterministic hash of a directory structure and content.
    
    Rules:
    - Files are processed in strict sorted order (LC_ALL=C equivalent).
    - Ignores symlinks to prevent loops and nondeterminism.
    - Hashes the manifest string: "<relpath>\0<file_hash>\n"
    
    Args:
        path: Path to the directory.
        alg: Hash algorithm.
        
    Returns:
        Hex string of the directory hash.
    """
    if not os.path.isdir(path):
        raise FileNotFoundError(f"Directory not found: {path}")

    manifest_lines: List[str] = []
    
    try:
        for root, dirs, files in os.walk(path):
            dirs.sort()
            for filename in sorted(files):
                file_path = os.path.join(root, filename)
                
                if os.path.islink(file_path):
                    logger.debug(f"Skipping symlink: {file_path}")
                    continue
                    
                rel_path = os.path.relpath(file_path, path).replace("\\", "/")
                file_hash = compute_file_hash(file_path, alg)
                manifest_lines.append(f"{rel_path}\0{file_hash}\n")
    except OSError as e:
        logger.error(f"Error walking directory {path}: {e}")
        raise

    full_manifest = "".join(manifest_lines)
    return hashlib.new(alg, full_manifest.encode("utf-8")).hexdigest()

def compute_hash(path: str, alg: str = "sha256") -> str:
    """
    Polymorphic hash function for files or directories.
    """
    if os.path.isdir(path):
        return compute_dir_hash(path, alg)
    return compute_file_hash(path, alg)
