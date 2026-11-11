"""
CLI entry point for nixcheck.
"""

import argparse
import json
import logging
import sys

from rich.console import Console

from .graph import run_nixcheck

__all__ = ["main"]

logger = logging.getLogger(__name__)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="nixcheck - Linux system health checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  nixcheck                    Run full system check
  nixcheck --no-security      Skip security checks
  nixcheck --no-containers    Skip container detection
  nixcheck --json             Output as JSON
  nixcheck --verbose          Enable debug logging
        """,
    )
    
    parser.add_argument(
        "--hostname", "-H",
        default="localhost",
        help="Hostname to report (default: localhost)"
    )
    parser.add_argument(
        "--no-containers",
        action="store_true",
        help="Skip container detection"
    )
    parser.add_argument(
        "--no-security",
        action="store_true",
        help="Skip security checks"
    )
    parser.add_argument(
        "--log-lines", "-n",
        type=int,
        default=1000,
        help="Number of log lines to analyze (default: 1000)"
    )
    parser.add_argument(
        "--threshold", "-t",
        type=float,
        default=80.0,
        help="Resource warning threshold percentage (default: 80)"
    )
    parser.add_argument(
        "--miner-list",
        type=str,
        default=None,
        help="Path to custom crypto miner list (YAML, JSON, or text file)"
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Fast mode: skip blocking CPU measurement (non-blocking cpu_percent)"
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output results as JSON"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress detailed output, only show summary"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging output"
    )
    # AI analysis options
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Run AI-powered diagnostic analysis on the check results (requires openai package)"
    )
    parser.add_argument(
        "--model", "-m",
        type=str,
        default="gemma4:31b-cloud",
        help="LLM model name for AI analysis (default: gemma4:31b-cloud, served via Ollama Cloud)"
    )
    parser.add_argument(
        "--ai-base-url",
        type=str,
        default=None,
        help="Override API base URL (default: OPENAI_BASE_URL env, else local Ollama at http://localhost:11434/v1)."
    )
    parser.add_argument(
        "--ai-api-key",
        type=str,
        default=None,
        help="API key for AI analysis. Prefer the OPENAI_API_KEY env var over this flag (CLI args are visible in `ps aux`)."
    )

    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    logger.debug("nixcheck starting with args: %s", args)
    
    console = Console()
    
    # Run the check
    try:
        if not args.quiet and not args.json:
            console.print("[bold blue]🔍 Running nixcheck...[/]")
        
        result = run_nixcheck(
            hostname=args.hostname,
            check_containers=not args.no_containers,
            check_security=not args.no_security,
            log_lines_limit=args.log_lines,
            resource_warning_threshold=args.threshold,
            miner_list_path=args.miner_list,
            fast_mode=args.fast,
        )

        # LangGraph returns a dict — reconstruct a proper NixCheckState
        if isinstance(result, dict):
            from .models import NixCheckState
            state = NixCheckState(**result)
        else:
            state = result
        
        if args.json:
            # Build JSON summary (printed after optional AI merge)
            from .reporter import generate_json_summary
            summary = generate_json_summary(state)
        elif args.quiet:
            from .rich_reporter import render_quiet_report
            console.print(render_quiet_report(state))
        else:
            # Rich interactive report
            from .rich_reporter import render_report
            console.print(render_report(state))

        # AI analysis
        if args.ai:
            from .ai_analyzer import analyze_with_ai, AIAnalyzerError
            if not args.quiet and not args.json:
                console.print("\n[bold blue]🤖 Running AI analysis...[/]")
            try:
                diagnosis = analyze_with_ai(
                    state,
                    model=args.model,
                    base_url=args.ai_base_url,
                    api_key=args.ai_api_key,
                )
                if args.json:
                    summary["ai_diagnosis"] = diagnosis
                else:
                    console.print("\n[bold cyan]🤖 AI Diagnosis[/]")
                    console.print(diagnosis)
            except AIAnalyzerError as e:
                if args.json:
                    summary["ai_error"] = str(e)
                else:
                    console.print(f"\n[red]AI analysis failed: {e}[/]")
                    sys.exit(1)

        # Print JSON output (after AI merge so diagnosis is included)
        if args.json:
            print(json.dumps(summary, indent=2))
        
        # Exit with error code if critical issues found (logic in reporter)
        from .reporter import compute_exit_code
        exit_code = compute_exit_code(state)
        if exit_code != 0:
            sys.exit(exit_code)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/]")
        sys.exit(130)
    except Exception as e:
        logger.exception("Fatal error: %s", e)
        console.print(f"[red]Error: {e}[/]")
        if args.verbose:
            console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    main()
