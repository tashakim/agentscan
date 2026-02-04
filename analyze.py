#!/usr/bin/env python3
"""
AnchorScan - Governance Pattern Scanner for AI Agent Code

Detects governance-related code patterns (logging, error handling, secret management, etc.)
using AST parsing. Reports only syntactically provable facts from source code.

Usage:
    python analyze.py <path> [--format FORMAT] [--output FILE]
    
Examples:
    python analyze.py ./my_agent.py
    python analyze.py ./agent_project/ --format markdown --output report.md
    python analyze.py ./agent.py --format html --output report.html
"""

import sys
import argparse
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from anchor_scan import scan, print_report, generate_markdown, generate_json, generate_html


def main():
    parser = argparse.ArgumentParser(
        description="Detect governance-related code patterns in AI agent code using AST parsing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s ./agent.py                          Analyze a single file
  %(prog)s ./project/                          Analyze all Python files in directory
  %(prog)s ./agent.py --format json            Output as JSON
  %(prog)s ./agent.py -f html -o report.html   Save HTML report to file
        """
    )
    
    parser.add_argument(
        "path",
        type=str,
        help="Path to Python file or directory to analyze"
    )
    
    parser.add_argument(
        "-f", "--format",
        type=str,
        choices=["terminal", "markdown", "json", "html"],
        default="terminal",
        help="Output format (default: terminal)"
    )
    
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Output file path (default: stdout)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed evidence for each check"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0"
    )
    
    args = parser.parse_args()
    
    # Validate path
    target_path = Path(args.path)
    if not target_path.exists():
        print(f"Error: Path '{args.path}' does not exist", file=sys.stderr)
        sys.exit(1)
    
    # Run analysis
    try:
        report = scan(args.path)
    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Generate output
    if args.format == "terminal":
        print_report(report)
        output = None
    elif args.format == "markdown":
        output = generate_markdown(report)
    elif args.format == "json":
        output = generate_json(report)
    elif args.format == "html":
        output = generate_html(report)
    
    # Write output
    if output:
        if args.output:
            Path(args.output).write_text(output)
            print(f"Report written to {args.output}")
        else:
            print(output)
    
    # Exit with code based on pattern detection results
    if report.overall_score < 40:
        sys.exit(2)  # Few patterns detected
    elif report.overall_score < 70:
        sys.exit(1)  # Some patterns detected
    else:
        sys.exit(0)  # Many patterns detected


if __name__ == "__main__":
    main()
