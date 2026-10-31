import json
import os
import tempfile
import logging
import subprocess
import sys
from typing import Any, Optional, Tuple, List
from pathlib import Path

logger = logging.getLogger("expman")

def atomic_write_json(data: Any, path: str, indent: int = 2) -> None:
    """
    Writes JSON data using an atomic write pattern (write-temp-move).
    Ensures data integrity even if the process crashes during write.
    
    Args:
        data: Serializable object.
        path: Target file path.
        indent: JSON indentation level.
        
    Raises:
        OSError: If directory creation or file writing fails.
    """
    target_path = Path(path).absolute()
    directory = target_path.parent

    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.error(f"Failed to create directory {directory}: {e}")
        raise

    try:
        fd, temp_path = tempfile.mkstemp(dir=directory, text=True)
    except OSError as e:
        logger.error(f"Failed to create temp file in {directory}: {e}")
        raise

    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())

        os.replace(temp_path, target_path)
        logger.info(f"Successfully wrote manifest to {target_path}")
        
    except (OSError, TypeError) as e:
        logger.error(f"Failed to write JSON to {target_path}: {e}")
        # Clean up temp file
        if os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass 
        raise

def get_git_info(cwd: Path) -> Tuple[Optional[str], Optional[bool]]:
    """
    Returns (commit_hash, is_dirty) if git is available and cwd is a repo.
    """
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=str(cwd),
            stderr=subprocess.DEVNULL,
            text=True
        ).strip()
        status = subprocess.check_output(
            ["git", "status", "--porcelain"],
            cwd=str(cwd),
            stderr=subprocess.DEVNULL,
            text=True
        )
        is_dirty = bool(status.strip())
        return commit or None, is_dirty
    except (OSError, subprocess.CalledProcessError):
        return None, None

def get_pip_freeze() -> Optional[List[str]]:
    try:
        output = subprocess.check_output(
            [sys.executable, "-m", "pip", "freeze"],
            stderr=subprocess.DEVNULL,
            text=True
        )
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        return lines or []
    except (OSError, subprocess.CalledProcessError):
        return None
