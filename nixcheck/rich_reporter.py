"""
Rich-based report rendering for nixcheck.
"""

import logging

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import NixCheckState, Severity

__all__ = [
    "render_quiet_report",
    "render_report",
]

logger = logging.getLogger(__name__)


def _severity_style(severity: Severity) -> str:
    """Map severity to Rich style."""
    return {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "bold yellow",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "green",
        Severity.INFO: "dim",
    }.get(severity, "")


def render_report(state: NixCheckState) -> Panel:
    """Render the full report as Rich renderables."""
    panels: list[Panel] = []

    # ── Services ──
    svc_table = Table(title="📋 SERVICES RUNNING", show_header=True, header_style="bold")
    svc_table.add_column("Name")
    svc_table.add_column("Status")
    svc_table.add_column("Enabled")
    svc_table.add_column("Memory (MB)")
    svc_table.add_column("CPU %")
    if state.services:
        for svc in state.services[:15]:
            mem = f"{svc.memory_mb:.1f}" if svc.memory_mb else "—"
            cpu = f"{svc.cpu_percent:.1f}" if svc.cpu_percent else "—"
            svc_table.add_row(svc.name, "✅ running", "✓" if svc.enabled else "—", mem, cpu)
        if len(state.services) > 15:
            svc_table.caption = f"... and {len(state.services) - 15} more"
    else:
        svc_table.add_row("—", "No services detected", "", "", "")
    panels.append(Panel(svc_table, border_style="blue"))

    # ── Containers ──
    if state.check_containers:
        ctn_table = Table(title="🐳 CONTAINERS", show_header=True, header_style="bold")
        ctn_table.add_column("Name")
        ctn_table.add_column("Container ID")
        if state.containers:
            for c in state.containers:
                ctn_table.add_row(c.name, c.container_id or "—")
        else:
            ctn_table.add_row("—", "No containers detected")
        panels.append(Panel(ctn_table, border_style="blue"))

    # ── Resources ──
    if state.resource_usage:
        r = state.resource_usage
        res_table = Table(title="💻 SYSTEM RESOURCES", show_header=True, header_style="bold")
        res_table.add_column("Resource")
        res_table.add_column("Usage")
        res_table.add_column("Status")

        threshold = state.resource_warning_threshold
        cpu_ok = r.cpu_percent < threshold
        mem_ok = r.memory_percent < threshold
        disk_ok = r.disk_percent < threshold

        res_table.add_row(
            "CPU", f"{r.cpu_percent:.1f}% ({r.cpu_cores} cores)",
            "[green]✅ OK[/]" if cpu_ok else "[red]⚠️ HIGH[/]"
        )
        res_table.add_row(
            "Memory", f"{r.memory_percent:.1f}% ({r.memory_used_gb:.1f}/{r.memory_total_gb:.1f} GB)",
            "[green]✅ OK[/]" if mem_ok else "[red]⚠️ HIGH[/]"
        )
        res_table.add_row(
            "Disk", f"{r.disk_percent:.1f}% ({r.disk_used_gb:.1f}/{r.disk_total_gb:.1f} GB)",
            "[green]✅ OK[/]" if disk_ok else "[red]⚠️ HIGH[/]"
        )
        res_table.add_row(
            "Load Average", f"{r.load_average[0]:.2f}, {r.load_average[1]:.2f}, {r.load_average[2]:.2f}",
            "[dim]—[/]"
        )
        if r.swap_percent is not None:
            swap_ok = r.swap_percent < 50
            res_table.add_row(
                "Swap", f"{r.swap_percent:.1f}%",
                "[green]✅ OK[/]" if swap_ok else "[yellow]⚠️[/]"
            )
        panels.append(Panel(res_table, border_style="blue"))
    else:
        panels.append(Panel("[yellow]Unable to collect resource information[/]", title="💻 SYSTEM RESOURCES"))

    # ── Log Errors ──
    log_table = Table(title="📝 LOG ERRORS", show_header=True, header_style="bold")
    log_table.add_column("Severity")
    log_table.add_column("Source")
    log_table.add_column("Message")
    if state.log_errors:
        criticals = [e for e in state.log_errors if e.severity == Severity.CRITICAL][:5]
        highs = [e for e in state.log_errors if e.severity == Severity.HIGH][:5]
        others = [e for e in state.log_errors if e.severity not in (Severity.CRITICAL, Severity.HIGH)][:10]
        for err in criticals + highs + others:
            sev_style = _severity_style(err.severity)
            log_table.add_row(
                f"[{sev_style}]{err.severity.value.upper()}[/]",
                err.source,
                err.message[:90]
            )
        if len(state.log_errors) > 20:
            log_table.caption = f"... and {len(state.log_errors) - 20} more errors"
    else:
        log_table.add_row("[green]✅[/]", "", "No errors found in logs")
    panels.append(Panel(log_table, border_style="blue"))

    # ── JVM ──
    if state.java_detected and state.jvm_configs:
        jvm_table = Table(title="☕ JAVA PROCESSES", show_header=True, header_style="bold")
        jvm_table.add_column("PID")
        jvm_table.add_column("Process")
        jvm_table.add_column("-Xmx")
        jvm_table.add_column("-Xms")
        jvm_table.add_column("Recommendations")
        for jvm in state.jvm_configs:
            xmx = f"{jvm.heap_max_mb:.0f} MB" if jvm.xmx_found else "[yellow]NOT SET[/]"
            xms = f"{jvm.heap_min_mb:.0f} MB" if jvm.xms_found else "—"
            recs = "\n".join(jvm.recommendations) if jvm.recommendations else "—"
            jvm_table.add_row(str(jvm.pid), jvm.java_process, xmx, xms, recs)
        panels.append(Panel(jvm_table, border_style="blue"))

    # ── Security ──
    if state.check_security:
        sec_table = Table(title="🔒 SECURITY CHECK", show_header=True, header_style="bold")
        sec_table.add_column("Severity")
        sec_table.add_column("Type")
        sec_table.add_column("Description")
        sec_table.add_column("Remediation")
        if state.security_issues:
            for issue in state.security_issues:
                sev_style = _severity_style(issue.severity)
                sec_table.add_row(
                    f"[{sev_style}]{issue.severity.value.upper()}[/]",
                    issue.issue_type,
                    issue.description[:80],
                    issue.remediation or "—"
                )
        else:
            sec_table.add_row("[green]✅[/]", "", "No security issues detected", "")
        panels.append(Panel(sec_table, border_style="blue"))

    # ── Summary ──
    warnings: list[str] = []
    if state.resource_usage:
        r = state.resource_usage
        if r.cpu_percent >= state.resource_warning_threshold:
            warnings.append(f"High CPU: {r.cpu_percent:.1f}%")
        if r.memory_percent >= state.resource_warning_threshold:
            warnings.append(f"High memory: {r.memory_percent:.1f}%")
        if r.disk_percent >= state.resource_warning_threshold:
            warnings.append(f"High disk: {r.disk_percent:.1f}%")

    critical_logs = len([e for e in state.log_errors if e.severity == Severity.CRITICAL])
    high_logs = len([e for e in state.log_errors if e.severity == Severity.HIGH])
    sec_crit = len([s for s in state.security_issues if s.severity in (Severity.CRITICAL, Severity.HIGH)])
    if critical_logs:
        warnings.append(f"{critical_logs} critical log errors")
    if high_logs:
        warnings.append(f"{high_logs} high-severity log errors")
    if sec_crit:
        warnings.append(f"{sec_crit} critical/high security issues")

    if warnings:
        summary_text = Text()
        summary_text.append("⚠️ WARNINGS:\n", style="bold yellow")
        for w in warnings:
            summary_text.append(f"  • {w}\n")
    else:
        summary_text = Text("✅ System appears healthy — no warnings.", style="bold green")

    panels.append(Panel(summary_text, title="📊 SUMMARY", border_style="green" if not warnings else "red"))

    return Panel(Group(*panels), title=f"🔍 NIXCHECK — {state.hostname}", border_style="bold blue")


def render_quiet_report(state: NixCheckState) -> str:
    """Render a minimal one-line status for quiet mode."""
    warnings = 0
    if state.resource_usage:
        if state.resource_usage.cpu_percent >= state.resource_warning_threshold:
            warnings += 1
        if state.resource_usage.memory_percent >= state.resource_warning_threshold:
            warnings += 1
        if state.resource_usage.disk_percent >= state.resource_warning_threshold:
            warnings += 1
    critical = len([e for e in state.log_errors if e.severity == Severity.CRITICAL])
    sec = len([s for s in state.security_issues if s.severity in (Severity.CRITICAL, Severity.HIGH)])

    if warnings or critical or sec:
        return f"⚠️ {state.hostname}: {warnings} resource warnings, {critical} critical logs, {sec} security issues"
    return f"✅ {state.hostname}: healthy"
