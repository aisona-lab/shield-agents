"""Helper utility functions for Shield Agents."""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def read_file_safe(file_path: str, max_size: int = 1024 * 1024) -> Optional[str]:
    """Safely read a file with size limits.
    
    Args:
        file_path: Path to the file.
        max_size: Maximum file size in bytes.
    
    Returns:
        File content as string, or None if file cannot be read.
    """
    try:
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            return None
        if path.stat().st_size > max_size:
            return None
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except (OSError, IOError, UnicodeDecodeError):
        return None


def get_file_lines(content: str) -> List[str]:
    """Split file content into lines.
    
    Args:
        content: File content as string.
    
    Returns:
        List of lines.
    """
    return content.split("\n")


def find_files(
    root_path: str,
    extensions: Optional[List[str]] = None,
    exclude_dirs: Optional[List[str]] = None,
    max_depth: int = 20,
) -> List[str]:
    """Find files matching criteria.
    
    Args:
        root_path: Root directory to search.
        extensions: File extensions to include (e.g., ['.py', '.js']).
        exclude_dirs: Directory names to exclude.
        max_depth: Maximum directory depth.
    
    Returns:
        List of file paths.
    """
    if exclude_dirs is None:
        exclude_dirs = []
    
    found_files = []
    root = Path(root_path)
    
    for path in root.rglob("*"):
        # Check depth
        try:
            depth = len(path.relative_to(root).parts)
        except ValueError:
            continue
        if depth > max_depth:
            continue
        
        # Check excluded dirs
        if any(exc in path.parts for exc in exclude_dirs):
            continue
        
        if path.is_file():
            if extensions is None or path.suffix in extensions:
                found_files.append(str(path))
    
    return found_files


def extract_code_snippet(content: str, line_number: int, context: int = 3) -> str:
    """Extract a code snippet around a specific line.
    
    Args:
        content: Full file content.
        line_number: Target line number (1-based).
        context: Number of context lines before and after.
    
    Returns:
        Code snippet as string.
    """
    lines = content.split("\n")
    start = max(0, line_number - 1 - context)
    end = min(len(lines), line_number + context)
    snippet_lines = lines[start:end]
    
    result = []
    for i, line in enumerate(snippet_lines, start=start + 1):
        marker = ">>>" if i == line_number else "   "
        result.append(f"{marker} {i:4d} | {line}")
    
    return "\n".join(result)


def truncate_string(s: str, max_length: int = 200) -> str:
    """Truncate a string to a maximum length.
    
    Args:
        s: Input string.
        max_length: Maximum length.
    
    Returns:
        Truncated string with ellipsis if needed.
    """
    if len(s) <= max_length:
        return s
    return s[:max_length - 3] + "..."


def calculate_risk_score(findings: List[Dict]) -> int:
    """Calculate an overall risk score from findings.
    
    Args:
        findings: List of finding dictionaries.
    
    Returns:
        Risk score from 0-100.
    """
    if not findings:
        return 0
    
    severity_weights = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 8,
        "LOW": 3,
        "INFO": 1,
    }
    
    total = sum(
        severity_weights.get(f.get("severity", "MEDIUM").upper(), 5)
        for f in findings
    )
    
    # Cap at 100
    return min(total, 100)
