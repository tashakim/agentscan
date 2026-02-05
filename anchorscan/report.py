"""
AnchorScan Report Generator

Generates beautiful terminal output and exportable reports.
"""

import json
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from anchorscan.models import AnalysisReport, Status, Severity, CheckResult


console = Console()


def get_status_icon(status: Status) -> str:
    """Get icon for status."""
    icons = {
        Status.PASS: "[green]✓ PASS[/green]",
        Status.FAIL: "[red]✗ FAIL[/red]",
        Status.PARTIAL: "[yellow]~ PARTIAL[/yellow]",
        Status.UNKNOWN: "[dim]? UNKNOWN[/dim]",
    }
    return icons.get(status, "?")


def get_severity_color(severity: Severity) -> str:
    """Get color for severity."""
    colors = {
        Severity.CRITICAL: "red",
        Severity.HIGH: "orange1",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }
    return colors.get(severity, "white")


def get_score_color(score: int) -> str:
    """Get color based on score."""
    if score >= 80:
        return "green"
    elif score >= 60:
        return "yellow"
    elif score >= 40:
        return "orange1"
    else:
        return "red"


def get_score_label(score: int) -> str:
    """Get label for score."""
    if score >= 80:
        return "COMPLIANT"
    elif score >= 60:
        return "NEEDS WORK"
    elif score >= 40:
        return "SIGNIFICANT GAPS"
    else:
        return "CRITICAL GAPS"


def print_report(report: AnalysisReport):
    """Print a beautiful terminal report."""
    
    # Header with honest positioning
    header = Text()
    header.append("ANCHOR-SCAN - CODE PATTERN ANALYSIS\n", style="bold white")
    header.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", style="dim")
    
    console.print(Panel(
        header,
        box=box.DOUBLE,
        border_style="blue",
        padding=(1, 2),
    ))
    
    # Important disclaimer
    disclaimer = Panel(
        Text.from_markup(
            "[bold]WHAT THIS REPORT IS[/bold]\n"
            "This report detects the PRESENCE of specific governance-related code\n"
            "patterns we check for. It uses AST parsing to identify imports,\n"
            "function calls, and definitions. Each finding is syntactically\n"
            "provable from source code.\n\n"
            "[bold]WHAT THIS REPORT IS NOT[/bold]\n"
            "This is NOT a compliance certification.\n"
            "This does NOT verify runtime behavior.\n"
            "This does NOT guarantee implementations work correctly.\n"
            "This does NOT detect custom implementations or patterns not in our list.\n\n"
            "[bold]IMPORTANT LIMITATION[/bold]\n"
            "We detect SPECIFIC patterns (pickle.dump(), presidio, prometheus, etc.).\n"
            "Custom implementations may not be detected. See LIMITATIONS.md for details.\n\n"
            "Manual review and testing are required for compliance verification."
        ),
        box=box.ROUNDED,
        border_style="yellow",
        padding=(1, 2),
    )
    console.print(disclaimer)
    console.print()
    
    # Summary
    summary_table = Table(show_header=False, box=None, padding=(0, 2))
    summary_table.add_column("Key", style="dim")
    summary_table.add_column("Value")
    
    summary_table.add_row("Target", f"[bold]{report.target_path}[/bold]")
    summary_table.add_row("Files Analyzed", str(report.files_analyzed))
    summary_table.add_row("Lines Analyzed", str(report.lines_analyzed))
    
    if report.agent_framework_detected:
        summary_table.add_row(
            "Agent Framework", 
            f"[cyan]{report.agent_framework_detected}[/cyan]"
        )
    
    # Count patterns detected
    total_patterns = sum(len(fw.checks) for fw in report.frameworks)
    patterns_found = sum(sum(1 for c in fw.checks if c.status == Status.PASS) for fw in report.frameworks)
    violations_found = sum(sum(1 for c in fw.checks if c.status == Status.FAIL and "secret" in c.requirement.id.lower()) for fw in report.frameworks)
    
    summary_table.add_row(
        "Patterns Detected",
        f"[green]{patterns_found}[/green] / {total_patterns}"
    )
    
    if violations_found > 0:
        summary_table.add_row(
            "Potential Issues",
            f"[red]{violations_found} violation(s) detected[/red]"
        )
    
    console.print(Panel(summary_table, title="Summary", border_style="dim"))
    console.print()
    
    # Pattern check results
    for fw in report.frameworks:
        console.print(Panel(
            f"[bold]{fw.framework_name}[/bold]",
            box=box.ROUNDED,
            border_style="blue",
        ))
        
        for check in fw.checks:
            # Show what we checked
            console.print(f"\n[bold]CHECK: {check.requirement.name}[/bold]")
            console.print("─" * 70)
            
            # Show findings
            if check.evidence:
                console.print("[dim]Findings:[/dim]")
                for ev in check.evidence[:5]:
                    icon = "✓" if check.status == Status.PASS else "✗"
                    color = "green" if check.status == Status.PASS else "red"
                    console.print(
                        f"  [{color}]{icon}[/{color}] DETECTED  "
                        f"[bold]{ev.description or check.requirement.name}[/bold]  "
                        f"[dim]line {ev.line_number}[/dim]  "
                        f"[dim]{ev.code_snippet[:50]}[/dim]"
                    )
            else:
                console.print("[dim](no patterns detected - custom implementations may not be detected)[/dim]")
            
            console.print(f"\n[dim]Summary: {check.message}[/dim]")
            console.print()
    
    # Priority remediation
    if report.all_gaps:
        console.print(Panel(
            "[bold]PRIORITY REMEDIATION[/bold]",
            box=box.SIMPLE,
            border_style="red",
        ))
        
        for i, gap in enumerate(report.all_gaps[:7], 1):
            sev_color = get_severity_color(gap.requirement.severity)
            sev_label = gap.requirement.severity.value.upper()
            
            console.print(
                f"  {i}. [[{sev_color}]{sev_label}[/{sev_color}]] "
                f"[bold]{gap.requirement.name}[/bold]"
            )
            if gap.remediation:
                console.print(f"     [dim]{gap.remediation[:80]}...[/dim]")
            console.print()
    
    # Evidence section (if any)
    evidence_found = False
    for fw in report.frameworks:
        for check in fw.checks:
            if check.evidence and check.status != Status.PASS:
                if not evidence_found:
                    console.print(Panel("EVIDENCE", box=box.SIMPLE, border_style="dim"))
                    evidence_found = True
                
                console.print(f"  [bold]{check.requirement.name}[/bold]")
                for ev in check.evidence[:2]:
                    if ev.line_number:
                        console.print(f"    Line {ev.line_number}: [dim]{ev.code_snippet}[/dim]")
                console.print()


def generate_markdown(report: AnalysisReport) -> str:
    """Generate a Markdown report."""
    
    lines = [
        "# AnchorScan - Code Pattern Analysis Report",
        "",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Summary",
        "",
        f"- **Target:** `{report.target_path}`",
        f"- **Files Analyzed:** {report.files_analyzed}",
        f"- **Lines Analyzed:** {report.lines_analyzed}",
        f"- **Agent Framework:** {report.agent_framework_detected or 'Unknown'}",
        f"- **Overall Score:** {report.overall_score}/100 ({get_score_label(report.overall_score)})",
        "",
    ]
    
    for fw in report.frameworks:
        lines.extend([
            f"## {fw.framework_name}",
            "",
            f"**Score:** {fw.score}/100 | Passed: {fw.passed} | Failed: {fw.failed} | Partial: {fw.partial}",
            "",
            "| Status | Requirement | Finding | Severity |",
            "|--------|-------------|---------|----------|",
        ])
        
        for check in fw.checks:
            status_icon = {"pass": "✓", "fail": "✗", "partial": "~"}.get(check.status.value, "?")
            lines.append(
                f"| {status_icon} {check.status.value.upper()} | {check.requirement.name} | "
                f"{check.message[:40]} | {check.requirement.severity.value.upper()} |"
            )
        
        lines.append("")
    
    if report.all_gaps:
        lines.extend([
            "## Priority Remediation",
            "",
        ])
        
        for i, gap in enumerate(report.all_gaps[:10], 1):
            lines.append(f"{i}. **[{gap.requirement.severity.value.upper()}] {gap.requirement.name}**")
            if gap.remediation:
                lines.append(f"   - {gap.remediation}")
            lines.append("")
    
    return "\n".join(lines)


def generate_json(report: AnalysisReport) -> str:
    """Generate a JSON report."""
    
    data = {
        "generated_at": datetime.now().isoformat(),
        "target_path": report.target_path,
        "files_analyzed": report.files_analyzed,
        "lines_analyzed": report.lines_analyzed,
        "agent_framework": report.agent_framework_detected,
        "overall_score": report.overall_score,
        "frameworks": [],
    }
    
    for fw in report.frameworks:
        fw_data = {
            "name": fw.framework_name,
            "version": fw.framework_version,
            "score": fw.score,
            "passed": fw.passed,
            "failed": fw.failed,
            "partial": fw.partial,
            "checks": [],
        }
        
        for check in fw.checks:
            check_data = {
                "requirement_id": check.requirement.id,
                "requirement_name": check.requirement.name,
                "status": check.status.value,
                "score": check.score,
                "message": check.message,
                "severity": check.requirement.severity.value,
                "remediation": check.remediation,
                "evidence": [
                    {
                        "file": ev.file_path,
                        "line": ev.line_number,
                        "snippet": ev.code_snippet,
                    }
                    for ev in check.evidence
                ],
            }
            fw_data["checks"].append(check_data)
        
        data["frameworks"].append(fw_data)
    
    return json.dumps(data, indent=2)


def generate_html(report: AnalysisReport) -> str:
    """Generate an HTML report with light/dark mode toggle."""
    
    score_color = get_score_color(report.overall_score)
    color_map = {"green": "#10b981", "yellow": "#f59e0b", "orange1": "#f97316", "red": "#ef4444"}
    score_hex = color_map.get(score_color, "#666")
    
    # Generate framework sections
    framework_html = ""
    for fw in report.frameworks:
        fw_score_color = get_score_color(fw.score)
        fw_score_hex = color_map.get(fw_score_color, "#666")
        
        rows = ""
        for check in fw.checks:
            status_class = check.status.value
            sev_class = check.requirement.severity.value
            icon = {"pass": "✓", "fail": "✗", "partial": "~"}.get(status_class, "?")
            rows += f"""
                <tr>
                    <td><span class="status-badge {status_class}">{icon} {status_class.upper()}</span></td>
                    <td class="req-name">{check.requirement.name}</td>
                    <td class="finding">{check.message[:55]}</td>
                    <td><span class="severity-badge {sev_class}">{sev_class.upper()}</span></td>
                </tr>"""
        
        framework_html += f"""
        <section class="framework-section">
            <div class="framework-header">
                <h2>{fw.framework_name}</h2>
                <span class="framework-version">v{fw.framework_version}</span>
            </div>
            <div class="framework-stats">
                <div class="stat">
                    <span class="stat-value" style="color: {fw_score_hex}">{fw.score}</span>
                    <span class="stat-label">Score</span>
                </div>
                <div class="stat">
                    <span class="stat-value pass-text">{fw.passed}</span>
                    <span class="stat-label">Passed</span>
                </div>
                <div class="stat">
                    <span class="stat-value fail-text">{fw.failed}</span>
                    <span class="stat-label">Failed</span>
                </div>
                <div class="stat">
                    <span class="stat-value partial-text">{fw.partial}</span>
                    <span class="stat-label">Partial</span>
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 120px;">Status</th>
                        <th style="width: 200px;">Requirement</th>
                        <th>Finding</th>
                        <th style="width: 100px;">Severity</th>
                    </tr>
                </thead>
                <tbody>{rows}
                </tbody>
            </table>
        </section>"""
    
    # Generate remediation section
    remediation_html = ""
    if report.all_gaps:
        items = ""
        for i, gap in enumerate(report.all_gaps[:7], 1):
            sev_class = gap.requirement.severity.value
            items += f"""
            <div class="remediation-item">
                <div class="remediation-header">
                    <span class="remediation-number">{i}</span>
                    <span class="severity-badge {sev_class}">{sev_class.upper()}</span>
                    <span class="remediation-title">{gap.requirement.name}</span>
                </div>
                <p class="remediation-text">{gap.remediation or 'See framework documentation.'}</p>
            </div>"""
        
        remediation_html = f"""
        <section class="remediation-section">
            <h2>Priority Remediation</h2>
            {items}
        </section>"""
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AnchorScan - Code Pattern Analysis</title>
    <style>
        :root {{
            --bg-primary: #ffffff;
            --bg-secondary: #f8fafc;
            --bg-tertiary: #f1f5f9;
            --text-primary: #0f172a;
            --text-secondary: #475569;
            --text-muted: #94a3b8;
            --border-color: #e2e8f0;
            --border-light: #f1f5f9;
            --shadow: 0 1px 3px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.06);
            --shadow-lg: 0 4px 6px rgba(0,0,0,0.07), 0 2px 4px rgba(0,0,0,0.06);
        }}
        
        [data-theme="dark"] {{
            --bg-primary: #111111;
            --bg-secondary: #1a1a1a;
            --bg-tertiary: #222222;
            --text-primary: #f1f5f9;
            --text-secondary: #a1a1aa;
            --text-muted: #71717a;
            --border-color: #2a2a2a;
            --border-light: #333333;
            --shadow: 0 1px 3px rgba(0,0,0,0.3);
            --shadow-lg: 0 4px 6px rgba(0,0,0,0.4);
        }}
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Inter', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            transition: background 0.2s, color 0.2s;
        }}
        
        .container {{
            max-width: 960px;
            margin: 0 auto;
            padding: 2rem 1.5rem;
        }}
        
        /* Header */
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 2rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .header-content h1 {{
            font-size: 1.5rem;
            font-weight: 600;
            letter-spacing: -0.025em;
            margin-bottom: 0.25rem;
        }}
        
        .header-content .subtitle {{
            color: var(--text-muted);
            font-size: 0.875rem;
        }}
        
        .theme-toggle {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 0.5rem 0.75rem;
            cursor: pointer;
            font-size: 0.8125rem;
            color: var(--text-secondary);
            transition: all 0.15s;
            display: flex;
            align-items: center;
            gap: 0.375rem;
        }}
        
        .theme-toggle:hover {{
            background: var(--bg-secondary);
            border-color: var(--text-muted);
        }}
        
        /* Summary Card */
        .summary-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow);
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 1.5rem;
            align-items: center;
        }}
        
        .summary-details {{
            display: flex;
            flex-direction: column;
            gap: 0.375rem;
        }}
        
        .summary-details p {{
            font-size: 0.875rem;
            color: var(--text-secondary);
        }}
        
        .summary-details strong {{
            color: var(--text-primary);
            font-weight: 500;
        }}
        
        .score-display {{
            text-align: center;
            padding: 1rem 1.5rem;
            background: var(--bg-primary);
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}
        
        .score-value {{
            font-size: 2.5rem;
            font-weight: 700;
            letter-spacing: -0.05em;
            line-height: 1;
        }}
        
        .score-label {{
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-top: 0.375rem;
            font-weight: 500;
        }}
        
        /* Framework Section */
        .framework-section {{
            margin-bottom: 2rem;
        }}
        
        .framework-header {{
            display: flex;
            align-items: baseline;
            gap: 0.75rem;
            margin-bottom: 1rem;
        }}
        
        .framework-header h2 {{
            font-size: 1.125rem;
            font-weight: 600;
        }}
        
        .framework-version {{
            font-size: 0.75rem;
            color: var(--text-muted);
            background: var(--bg-tertiary);
            padding: 0.125rem 0.5rem;
            border-radius: 4px;
        }}
        
        .framework-stats {{
            display: flex;
            gap: 1.5rem;
            margin-bottom: 1rem;
            padding: 0.75rem 0;
        }}
        
        .stat {{
            display: flex;
            flex-direction: column;
        }}
        
        .stat-value {{
            font-size: 1.25rem;
            font-weight: 600;
        }}
        
        .stat-label {{
            font-size: 0.6875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
        }}
        
        .pass-text {{ color: #10b981; }}
        .fail-text {{ color: #ef4444; }}
        .partial-text {{ color: #f59e0b; }}
        
        /* Table */
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }}
        
        th {{
            text-align: left;
            padding: 0.75rem 1rem;
            font-size: 0.6875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            background: var(--bg-tertiary);
            border-bottom: 1px solid var(--border-color);
        }}
        
        td {{
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border-light);
            vertical-align: middle;
        }}
        
        tr:last-child td {{
            border-bottom: none;
        }}
        
        tr:hover td {{
            background: var(--bg-tertiary);
        }}
        
        .req-name {{
            font-weight: 500;
            color: var(--text-primary);
        }}
        
        .finding {{
            color: var(--text-secondary);
            font-size: 0.8125rem;
        }}
        
        /* Badges */
        .status-badge {{
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.6875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }}
        
        .status-badge.pass {{
            background: rgba(16, 185, 129, 0.1);
            color: #10b981;
        }}
        
        .status-badge.fail {{
            background: rgba(239, 68, 68, 0.1);
            color: #ef4444;
        }}
        
        .status-badge.partial {{
            background: rgba(245, 158, 11, 0.1);
            color: #f59e0b;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 0.125rem 0.375rem;
            border-radius: 3px;
            font-size: 0.625rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }}
        
        .severity-badge.critical {{
            background: rgba(239, 68, 68, 0.1);
            color: #ef4444;
        }}
        
        .severity-badge.high {{
            background: rgba(249, 115, 22, 0.1);
            color: #f97316;
        }}
        
        .severity-badge.medium {{
            background: rgba(245, 158, 11, 0.1);
            color: #f59e0b;
        }}
        
        .severity-badge.low {{
            background: rgba(59, 130, 246, 0.1);
            color: #3b82f6;
        }}
        
        /* Remediation */
        .remediation-section {{
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border-color);
        }}
        
        .remediation-section h2 {{
            font-size: 1.125rem;
            font-weight: 600;
            margin-bottom: 1rem;
        }}
        
        .remediation-item {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 1rem;
            margin-bottom: 0.75rem;
        }}
        
        .remediation-header {{
            display: flex;
            align-items: center;
            gap: 0.625rem;
            margin-bottom: 0.5rem;
        }}
        
        .remediation-number {{
            width: 1.5rem;
            height: 1.5rem;
            background: var(--bg-tertiary);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-muted);
        }}
        
        .remediation-title {{
            font-weight: 500;
            color: var(--text-primary);
        }}
        
        .remediation-text {{
            font-size: 0.8125rem;
            color: var(--text-secondary);
            line-height: 1.5;
            margin-left: 2.125rem;
        }}
        
        /* Footer */
        .footer {{
            margin-top: 3rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border-color);
            text-align: center;
            color: var(--text-muted);
            font-size: 0.75rem;
        }}
        
        .footer a {{
            color: var(--text-secondary);
            text-decoration: none;
        }}
        
        .footer a:hover {{
            text-decoration: underline;
        }}
        
        @media (max-width: 640px) {{
            .summary-grid {{
                grid-template-columns: 1fr;
            }}
            .score-display {{
                justify-self: start;
            }}
            .framework-stats {{
                flex-wrap: wrap;
                gap: 1rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="header-content">
                <h1>AnchorScan - Code Pattern Analysis</h1>
                <p class="subtitle">Generated {datetime.now().strftime('%B %d, %Y at %H:%M')}</p>
            </div>
            <button class="theme-toggle" onclick="toggleTheme()">
                <span id="theme-icon">◐</span>
                <span id="theme-text">Toggle theme</span>
            </button>
        </header>
        
        <div class="summary-card">
            <div class="summary-grid">
                <div class="summary-details">
                    <p><strong>Target:</strong> {report.target_path}</p>
                    <p><strong>Files analyzed:</strong> {report.files_analyzed}</p>
                    <p><strong>Lines analyzed:</strong> {report.lines_analyzed:,}</p>
                    <p><strong>Agent framework:</strong> {report.agent_framework_detected or 'Not detected'}</p>
                </div>
                <div class="score-display">
                    <div class="score-value" style="color: {score_hex}">{report.overall_score}</div>
                    <div class="score-label">{get_score_label(report.overall_score)}</div>
                </div>
            </div>
        </div>
        
        {framework_html}
        
        {remediation_html}
        
        <footer class="footer">
            <p>Generated by AnchorScan</p>
        </footer>
    </div>
    
    <script>
        function toggleTheme() {{
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            html.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            updateThemeIcon(newTheme);
        }}
        
        function updateThemeIcon(theme) {{
            const icon = document.getElementById('theme-icon');
            icon.textContent = theme === 'dark' ? '○' : '◐';
        }}
        
        // Load saved theme or default to light
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-theme', savedTheme);
        updateThemeIcon(savedTheme);
    </script>
</body>
</html>"""
    return html
