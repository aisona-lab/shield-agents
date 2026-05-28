"""Cryptographic utility functions for Shield Agents."""

import hashlib
import os
from typing import Optional


def hash_file(file_path: str, algorithm: str = "sha256") -> Optional[str]:
    """Compute hash of a file for caching/incremental scanning.
    
    Args:
        file_path: Path to the file.
        algorithm: Hash algorithm (sha256, md5, sha1).
    
    Returns:
        Hex digest string, or None if file cannot be read.
    """
    try:
        hasher = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, IOError, ValueError):
        return None


def hash_content(content: str, algorithm: str = "sha256") -> str:
    """Compute hash of string content.
    
    Args:
        content: String content to hash.
        algorithm: Hash algorithm.
    
    Returns:
        Hex digest string.
    """
    hasher = hashlib.new(algorithm)
    hasher.update(content.encode("utf-8"))
    return hasher.hexdigest()


def generate_id() -> str:
    """Generate a unique identifier.
    
    Returns:
        A random hex string.
    """
    return os.urandom(16).hex()
