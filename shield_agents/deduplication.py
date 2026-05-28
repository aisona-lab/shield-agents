"""
Deduplication Engine for Shield Agents.

When VulnAgent finds "SQL Injection" and SAST also finds "SQL Injection",
this engine merges them into one finding with multiple sources. This prevents
duplicate findings from cluttering reports and inflating risk scores.
"""

import logging
import re
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("shield_agents.deduplication")


class FindingDeduplicator:
    """Deduplicate findings across multiple agents and scanners.

    Uses multiple strategies:
    1. Exact match: Same file, line, and category
    2. Fuzzy match: Similar title/description within same file
    3. Category merge: Same vulnerability type at nearby lines
    """

    def __init__(self, similarity_threshold: float = 0.85, merge_sources: bool = True):
        """Initialize the deduplicator.

        Args:
            similarity_threshold: Threshold for fuzzy matching (0.0-1.0).
            merge_sources: Whether to merge sources into a single finding.
        """
        self.similarity_threshold = similarity_threshold
        self.merge_sources = merge_sources
        self.dedup_stats = {
            "total_input": 0,
            "exact_duplicates": 0,
            "fuzzy_duplicates": 0,
            "category_merges": 0,
            "final_count": 0,
        }

    def deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate a list of findings.

        Args:
            findings: List of finding dictionaries from multiple sources.

        Returns:
            Deduplicated list of findings.
        """
        if not findings:
            return []

        self.dedup_stats["total_input"] = len(findings)
        result = []
        seen_keys: Set[str] = set()
        merged_findings: Dict[str, Dict[str, Any]] = {}

        # Phase 1: Exact deduplication
        for finding in findings:
            key = self._exact_key(finding)
            if key in seen_keys:
                self.dedup_stats["exact_duplicates"] += 1
                # Merge sources into existing finding
                if self.merge_sources and key in merged_findings:
                    self._merge_into(merged_findings[key], finding)
                continue

            seen_keys.add(key)
            merged_findings[key] = {**finding}
            if "sources" not in merged_findings[key]:
                merged_findings[key]["sources"] = [finding.get("source", finding.get("agent", "unknown"))]

        # Phase 2: Fuzzy deduplication (nearby lines, similar titles)
        keys_list = list(merged_findings.keys())
        to_remove: Set[str] = set()

        for i, key1 in enumerate(keys_list):
            if key1 in to_remove:
                continue
            for j in range(i + 1, len(keys_list)):
                key2 = keys_list[j]
                if key2 in to_remove:
                    continue

                f1 = merged_findings[key1]
                f2 = merged_findings[key2]

                if self._is_fuzzy_duplicate(f1, f2):
                    self.dedup_stats["fuzzy_duplicates"] += 1
                    self._merge_into(f1, f2)
                    to_remove.add(key2)

        # Phase 3: Category merge (same vuln type within 3 lines)
        for i, key1 in enumerate(keys_list):
            if key1 in to_remove:
                continue
            for j in range(i + 1, len(keys_list)):
                key2 = keys_list[j]
                if key2 in to_remove:
                    continue

                f1 = merged_findings[key1]
                f2 = merged_findings[key2]

                if self._is_category_duplicate(f1, f2):
                    self.dedup_stats["category_merges"] += 1
                    self._merge_into(f1, f2)
                    to_remove.add(key2)

        # Build final result
        for key in keys_list:
            if key not in to_remove:
                result.append(merged_findings[key])

        self.dedup_stats["final_count"] = len(result)
        logger.info(
            f"Deduplication: {len(findings)} → {len(result)} findings "
            f"(removed {len(findings) - len(result)} duplicates)"
        )
        return result

    def _exact_key(self, finding: Dict[str, Any]) -> str:
        """Generate an exact deduplication key.

        Args:
            finding: Finding dictionary.

        Returns:
            String key for exact matching.
        """
        file_path = finding.get("file", "")
        line = finding.get("line", 0)
        category = finding.get("category", "").lower()
        title = finding.get("title", "").lower().strip()

        # Normalize the title
        title = re.sub(r'[^a-z0-9]', '', title)

        return f"{file_path}:{line}:{category}:{title}"

    def _is_fuzzy_duplicate(self, f1: Dict[str, Any], f2: Dict[str, Any]) -> bool:
        """Check if two findings are fuzzy duplicates.

        Two findings are fuzzy duplicates if:
        - They are in the same file
        - Their titles are similar (above threshold)
        - Their line numbers are within 5 lines of each other

        Args:
            f1: First finding.
            f2: Second finding.

        Returns:
            True if they are likely duplicates.
        """
        # Must be in the same file
        if f1.get("file", "") != f2.get("file", ""):
            return False

        # Check line proximity (within 5 lines)
        line1 = f1.get("line", 0)
        line2 = f2.get("line", 0)
        if isinstance(line1, int) and isinstance(line2, int):
            if abs(line1 - line2) > 5:
                return False

        # Check title similarity
        title1 = f1.get("title", "").lower()
        title2 = f2.get("title", "").lower()
        similarity = SequenceMatcher(None, title1, title2).ratio()

        if similarity >= self.similarity_threshold:
            return True

        # Also check category match with high title similarity
        if (f1.get("category", "").lower() == f2.get("category", "").lower() and
                similarity >= self.similarity_threshold * 0.8):
            return True

        return False

    def _is_category_duplicate(self, f1: Dict[str, Any], f2: Dict[str, Any]) -> bool:
        """Check if two findings are category-level duplicates.

        Same vulnerability type at nearby lines in the same file.

        Args:
            f1: First finding.
            f2: Second finding.

        Returns:
            True if they are category-level duplicates.
        """
        # Must be in same file and same category
        if (f1.get("file", "") != f2.get("file", "") or
                f1.get("category", "").lower() != f2.get("category", "").lower()):
            return False

        # Must be within 3 lines
        line1 = f1.get("line", 0)
        line2 = f2.get("line", 0)
        if isinstance(line1, int) and isinstance(line2, int):
            if abs(line1 - line2) <= 3:
                return True

        return False

    def _merge_into(self, target: Dict[str, Any], source: Dict[str, Any]) -> None:
        """Merge source finding into target finding.

        Keeps the higher severity, combines sources, and adds alternate references.

        Args:
            target: Target finding (modified in place).
            source: Source finding to merge from.
        """
        # Merge sources
        if "sources" not in target:
            target["sources"] = [target.get("source", target.get("agent", "unknown"))]

        source_name = source.get("source", source.get("agent", "unknown"))
        if source_name not in target["sources"]:
            target["sources"].append(source_name)

        # Keep higher severity
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        target_sev = severity_order.get(target.get("severity", "MEDIUM").upper(), 2)
        source_sev = severity_order.get(source.get("severity", "MEDIUM").upper(), 2)

        if source_sev > target_sev:
            target["severity"] = source.get("severity", "MEDIUM")

        # Keep higher confidence
        target_conf = target.get("confidence", 0.8)
        source_conf = source.get("confidence", 0.8)
        target["confidence"] = max(target_conf, source_conf)

        # Merge descriptions if different
        if source.get("description", "") != target.get("description", ""):
            target.setdefault("alternate_descriptions", [])
            target["alternate_descriptions"].append(source.get("description", ""))

        # Mark as merged
        target["deduplicated"] = True

    def get_stats(self) -> Dict[str, int]:
        """Get deduplication statistics.

        Returns:
            Dictionary of deduplication statistics.
        """
        return self.dedup_stats.copy()
