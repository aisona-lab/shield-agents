"""
Report Generator for Shield Agents.

Generates HTML reports with interactive visualizations, severity breakdowns,
and detailed findings. Also supports JSON and plain text output.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .sarif import SARIFGenerator
from ..utils.helpers import calculate_risk_score

logger = logging.getLogger("shield_agents.report")


class ReportGenerator:
    """Generate security scan reports in multiple formats.

    Supported formats:
    - HTML: Interactive web report with charts and filtering
    - SARIF: For GitHub Security tab integration
    - JSON: Machine-readable structured data
    """

    def __init__(self, config=None):
        self.config = config
        self.sarif_generator = SARIFGenerator(config)

    def generate_report(
        self,
        findings: List[Dict[str, Any]],
        target_path: str = ".",
        output_dir: str = "./shield-reports",
        formats: Optional[List[str]] = None,
        scan_stats: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        """Generate reports in specified formats.

        Args:
            findings: List of finding dictionaries.
            target_path: Path that was scanned.
            output_dir: Directory to save reports.
            formats: List of formats to generate (html, sarif, json).
            scan_stats: Optional scan statistics.

        Returns:
            Dictionary of format -> file path.
        """
        if formats is None:
            formats = ["html", "sarif", "json"]

        # Ensure output directory exists
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # Calculate summary stats
        risk_score = calculate_risk_score(findings)
        summary = self._build_summary(findings, risk_score, scan_stats)

        output_files = {}

        for fmt in formats:
            try:
                if fmt == "html":
                    path = self._generate_html(findings, summary, target_path, output_dir)
                    output_files["html"] = path
                elif fmt == "sarif":
                    path = self._generate_sarif(findings, target_path, output_dir)
                    output_files["sarif"] = path
                elif fmt == "json":
                    path = self._generate_json(findings, summary, target_path, output_dir)
                    output_files["json"] = path
                else:
                    logger.warning(f"Unknown report format: {fmt}")
            except Exception as e:
                logger.error(f"Failed to generate {fmt} report: {e}")

        logger.info(f"Generated reports: {list(output_files.keys())}")
        return output_files

    def _build_summary(
        self,
        findings: List[Dict[str, Any]],
        risk_score: int,
        scan_stats: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build summary statistics from findings."""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        category_counts: Dict[str, int] = {}
        source_counts: Dict[str, int] = {}
        file_counts: Dict[str, int] = {}

        for f in findings:
            sev = f.get("severity", "MEDIUM").upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            cat = f.get("category", "unknown")
            category_counts[cat] = category_counts.get(cat, 0) + 1

            source = f.get("source", f.get("agent", "unknown"))
            source_counts[source] = source_counts.get(source, 0) + 1

            file = f.get("file", "unknown")
            file_counts[file] = file_counts.get(file, 0) + 1

        summary = {
            "total_findings": len(findings),
            "risk_score": risk_score,
            "severity_counts": severity_counts,
            "category_counts": category_counts,
            "source_counts": source_counts,
            "most_affected_files": sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            "generated_at": datetime.now().isoformat(),
        }

        if scan_stats:
            summary["scan_stats"] = scan_stats

        return summary

    def _generate_sarif(self, findings: List[Dict[str, Any]], target_path: str, output_dir: str) -> str:
        """Generate SARIF report."""
        output_path = os.path.join(output_dir, "results.sarif")
        return self.sarif_generator.save(findings, output_path, target_path)

    def _generate_json(
        self,
        findings: List[Dict[str, Any]],
        summary: Dict[str, Any],
        target_path: str,
        output_dir: str,
    ) -> str:
        """Generate JSON report."""
        output_path = os.path.join(output_dir, "results.json")
        report = {
            "shield_agents_version": "2.0.0",
            "target_path": target_path,
            "summary": summary,
            "findings": findings,
        }
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        return output_path

    def _generate_html(
        self,
        findings: List[Dict[str, Any]],
        summary: Dict[str, Any],
        target_path: str,
        output_dir: str,
    ) -> str:
        """Generate HTML report with interactive visualizations."""
        output_path = os.path.join(output_dir, "report.html")

        severity_colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#0dcaf0",
            "INFO": "#6c757d",
        }

        # Risk level text
        if summary["risk_score"] >= 75:
            risk_level = "CRITICAL"
            risk_color = "#dc3545"
        elif summary["risk_score"] >= 50:
            risk_level = "HIGH"
            risk_color = "#fd7e14"
        elif summary["risk_score"] >= 25:
            risk_level = "MEDIUM"
            risk_color = "#ffc107"
        else:
            risk_level = "LOW"
            risk_color = "#0dcaf0"

        # Build severity breakdown bars
        total = max(summary["total_findings"], 1)
        severity_bars = ""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = summary["severity_counts"].get(sev, 0)
            pct = (count / total) * 100
            color = severity_colors.get(sev, "#6c757d")
            severity_bars += f"""
            <div class="severity-row">
                <span class="severity-label">{sev}</span>
                <div class="severity-bar-container">
                    <div class="severity-bar" style="width: {pct}%; background-color: {color};"></div>
                </div>
                <span class="severity-count">{count}</span>
            </div>"""

        # Build findings table
        findings_rows = ""
        for i, f in enumerate(findings[:200]):  # Limit to 200 rows
            sev = f.get("severity", "MEDIUM").upper()
            color = severity_colors.get(sev, "#6c757d")
            title = f.get("title", "Unknown").replace("<", "&lt;").replace(">", "&gt;")
            desc = f.get("description", "").replace("<", "&lt;").replace(">", "&gt;")[:150]
            file = f.get("file", "N/A").replace("<", "&lt;").replace(">", "&gt;")
            line = f.get("line", "N/A")
            source = f.get("source", f.get("agent", "unknown"))
            remediation = f.get("remediation", "").replace("<", "&lt;").replace(">", "&gt;")[:200]
            sources = ", ".join(f.get("sources", [source]))
            cwe = f.get("cwe", "")

            findings_rows += f"""
            <tr>
                <td><span class="badge" style="background-color: {color}">{sev}</span></td>
                <td>{title}</td>
                <td>{desc}...</td>
                <td class="mono">{file}</td>
                <td>{line}</td>
                <td>{sources}</td>
                <td>{cwe}</td>
                <td>{remediation}...</td>
            </tr>"""

        # Category breakdown
        category_items = ""
        for cat, count in sorted(summary["category_counts"].items(), key=lambda x: x[1], reverse=True):
            category_items += f'<li><strong>{cat}</strong>: {count}</li>'

        # Most affected files
        file_items = ""
        for filepath, count in summary["most_affected_files"][:10]:
            file_items += f'<li><code>{filepath}</code>: {count} findings</li>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shield Agents - Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a1b26 0%, #24283b 100%); border-radius: 12px; padding: 30px; margin-bottom: 24px; border: 1px solid #30363d; }}
        .header h1 {{ font-size: 28px; color: #58a6ff; margin-bottom: 8px; }}
        .header p {{ color: #8b949e; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 24px; }}
        .card {{ background: #161b22; border-radius: 12px; padding: 24px; border: 1px solid #30363d; }}
        .card h2 {{ font-size: 18px; color: #58a6ff; margin-bottom: 16px; }}
        .risk-score {{ font-size: 64px; font-weight: bold; text-align: center; color: {risk_color}; }}
        .risk-label {{ text-align: center; font-size: 18px; color: {risk_color}; margin-top: 8px; }}
        .severity-row {{ display: flex; align-items: center; margin-bottom: 8px; }}
        .severity-label {{ width: 80px; font-weight: 600; font-size: 13px; }}
        .severity-bar-container {{ flex: 1; height: 20px; background: #21262d; border-radius: 4px; overflow: hidden; }}
        .severity-bar {{ height: 100%; border-radius: 4px; transition: width 0.5s; }}
        .severity-count {{ width: 40px; text-align: right; font-weight: 600; margin-left: 8px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th {{ background: #21262d; color: #8b949e; padding: 12px 8px; text-align: left; position: sticky; top: 0; }}
        td {{ padding: 10px 8px; border-bottom: 1px solid #21262d; }}
        tr:hover {{ background: #1c2128; }}
        .badge {{ padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; color: white; }}
        .mono {{ font-family: 'SF Mono', Monaco, monospace; font-size: 12px; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-top: 16px; }}
        .stat-item {{ text-align: center; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #58a6ff; }}
        .stat-label {{ font-size: 12px; color: #8b949e; }}
        .table-container {{ overflow-x: auto; max-height: 600px; overflow-y: auto; }}
        .footer {{ text-align: center; padding: 20px; color: #484f58; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>&#x1f6e1; Shield Agents Security Report</h1>
            <p>Target: <code>{target_path}</code> | Generated: {summary['generated_at']}</p>
        </div>

        <div class="grid">
            <div class="card">
                <h2>Risk Score</h2>
                <div class="risk-score">{summary['risk_score']}</div>
                <div class="risk-label">{risk_level} RISK</div>
                <div class="stats">
                    <div class="stat-item">
                        <div class="stat-value">{summary['total_findings']}</div>
                        <div class="stat-label">Findings</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{summary['severity_counts'].get('CRITICAL', 0)}</div>
                        <div class="stat-label">Critical</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{summary['severity_counts'].get('HIGH', 0)}</div>
                        <div class="stat-label">High</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{len(summary['category_counts'])}</div>
                        <div class="stat-label">Categories</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>Severity Distribution</h2>
                {severity_bars}
            </div>

            <div class="card">
                <h2>Categories</h2>
                <ul style="list-style: none; padding: 0;">
                    {category_items}
                </ul>
                <h2 style="margin-top: 16px;">Most Affected Files</h2>
                <ul style="list-style: none; padding: 0; font-size: 13px;">
                    {file_items}
                </ul>
            </div>
        </div>

        <div class="card">
            <h2>Findings Detail ({summary['total_findings']} total)</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Title</th>
                            <th>Description</th>
                            <th>File</th>
                            <th>Line</th>
                            <th>Source</th>
                            <th>CWE</th>
                            <th>Remediation</th>
                        </tr>
                    </thead>
                    <tbody>
                        {findings_rows}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="footer">
            Generated by Shield Agents v2.0.0
        </div>
    </div>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        return output_path
