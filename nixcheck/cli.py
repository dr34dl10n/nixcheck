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
        if not args.quiet:
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
            # Output JSON
            from .reporter import generate_json_summary
            summary = generate_json_summary(state)
            print(json.dumps(summary, indent=2))
        elif args.quiet:
            from .rich_reporter import render_quiet_report
            console.print(render_quiet_report(state))
        else:
            # Rich interactive report
            from .rich_reporter import render_report
            console.print(render_report(state))
        
        # Exit with error code if critical issues found
        critical_errors = len([e for e in state.log_errors if e.severity.value in ("critical", "high")])
        security_critical = len([s for s in state.security_issues if s.severity.value in ("critical", "high")])
        
        if critical_errors > 0 or security_critical > 0:
            sys.exit(2)
        
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
