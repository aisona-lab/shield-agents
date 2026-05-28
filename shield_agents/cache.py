"""
Caching and Incremental Scanning for Shield Agents.

Cache previous scan results and only re-scan changed files.
This is the difference between a demo and a production tool.
"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .utils.crypto import hash_file

logger = logging.getLogger("shield_agents.cache")


class ScanCache:
    """Manages scan result caching for incremental scanning.

    The cache stores:
    - File hashes (to detect changes)
    - Scan results per file
    - Timestamps (for cache invalidation)
    - Global metadata
    """

    def __init__(self, cache_dir: str = ".shield-cache", max_age_days: int = 30):
        """Initialize the scan cache.

        Args:
            cache_dir: Directory for cache storage.
            max_age_days: Maximum age of cache entries in days.
        """
        self.cache_dir = Path(cache_dir)
        self.max_age_days = max_age_days
        self.cache_file = self.cache_dir / "scan_cache.json"
        self._cache: Dict[str, Any] = {}
        self._loaded = False
        self.changed = False

    def _ensure_loaded(self) -> None:
        """Load cache from disk if not already loaded."""
        if not self._loaded:
            self._load()
            self._loaded = True

    def _load(self) -> None:
        """Load cache from disk."""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, "r") as f:
                    self._cache = json.load(f)
                logger.debug(f"Loaded cache with {len(self._cache.get('files', {}))} entries")
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load cache: {e}")
                self._cache = {"files": {}, "metadata": {}}
        else:
            self._cache = {"files": {}, "metadata": {}}

    def save(self) -> None:
        """Save cache to disk."""
        if not self.changed:
            return

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache["metadata"]["last_saved"] = time.time()

        try:
            with open(self.cache_file, "w") as f:
                json.dump(self._cache, f, indent=2)
            self.changed = False
            logger.debug("Cache saved successfully")
        except IOError as e:
            logger.warning(f"Failed to save cache: {e}")

    def get_file_hash(self, file_path: str) -> Optional[str]:
        """Get the cached hash for a file.

        Args:
            file_path: Path to the file.

        Returns:
            Cached hash, or None if not cached.
        """
        self._ensure_loaded()
        return self._cache.get("files", {}).get(file_path, {}).get("hash")

    def compute_file_hash(self, file_path: str) -> Optional[str]:
        """Compute current hash for a file.

        Args:
            file_path: Path to the file.

        Returns:
            Current file hash, or None if file cannot be read.
        """
        return hash_file(file_path)

    def is_file_changed(self, file_path: str) -> bool:
        """Check if a file has changed since last scan.

        Args:
            file_path: Path to the file.

        Returns:
            True if file is new or modified, False if unchanged.
        """
        self._ensure_loaded()
        current_hash = self.compute_file_hash(file_path)
        cached_hash = self.get_file_hash(file_path)

        if current_hash is None:
            # Can't read the file, treat as unchanged
            return False

        if cached_hash is None:
            # Not cached, treat as new
            return True

        return current_hash != cached_hash

    def get_changed_files(self, file_paths: List[str]) -> List[str]:
        """Get list of files that have changed since last scan.

        Args:
            file_paths: List of file paths to check.

        Returns:
            List of changed file paths.
        """
        return [fp for fp in file_paths if self.is_file_changed(fp)]

    def get_unchanged_files(self, file_paths: List[str]) -> List[str]:
        """Get list of files that haven't changed since last scan.

        Args:
            file_paths: List of file paths to check.

        Returns:
            List of unchanged file paths.
        """
        return [fp for fp in file_paths if not self.is_file_changed(fp)]

    def get_cached_findings(self, file_path: str) -> List[Dict[str, Any]]:
        """Get cached scan findings for a file.

        Args:
            file_path: Path to the file.

        Returns:
            List of cached findings, or empty list if not cached.
        """
        self._ensure_loaded()
        file_entry = self._cache.get("files", {}).get(file_path, {})
        return file_entry.get("findings", [])

    def update_file(self, file_path: str, findings: List[Dict[str, Any]]) -> None:
        """Update cache for a file with new findings.

        Args:
            file_path: Path to the file.
            findings: List of findings for this file.
        """
        self._ensure_loaded()
        current_hash = self.compute_file_hash(file_path)

        if "files" not in self._cache:
            self._cache["files"] = {}

        self._cache["files"][file_path] = {
            "hash": current_hash,
            "findings": findings,
            "last_scanned": time.time(),
            "finding_count": len(findings),
        }
        self.changed = True

    def invalidate_file(self, file_path: str) -> None:
        """Remove a file from the cache.

        Args:
            file_path: Path to the file.
        """
        self._ensure_loaded()
        if file_path in self._cache.get("files", {}):
            del self._cache["files"][file_path]
            self.changed = True

    def clear(self) -> None:
        """Clear the entire cache."""
        self._cache = {"files": {}, "metadata": {}}
        self.changed = True

    def cleanup_expired(self) -> int:
        """Remove expired cache entries.

        Returns:
            Number of expired entries removed.
        """
        self._ensure_loaded()
        if not self.max_age_days:
            return 0

        cutoff = time.time() - (self.max_age_days * 86400)
        expired = []

        for file_path, entry in self._cache.get("files", {}).items():
            if entry.get("last_scanned", 0) < cutoff:
                expired.append(file_path)

        for file_path in expired:
            del self._cache["files"][file_path]

        if expired:
            self.changed = True
            logger.info(f"Cleaned up {len(expired)} expired cache entries")

        return len(expired)

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary with cache statistics.
        """
        self._ensure_loaded()
        files = self._cache.get("files", {})
        total_findings = sum(e.get("finding_count", 0) for e in files.values())

        return {
            "cached_files": len(files),
            "total_cached_findings": total_findings,
            "cache_size_bytes": self.cache_file.stat().st_size if self.cache_file.exists() else 0,
            "last_saved": self._cache.get("metadata", {}).get("last_saved"),
        }
