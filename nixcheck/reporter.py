"""
Report generation for nixcheck.
"""

import logging
from typing import Any

from .models import NixCheckState, Severity

__all__ = [
    "generate_json_summary",
    "generate_report",
    "severity_emoji",
]

logger = logging.getLogger(__name__)


def severity_emoji(severity: Severity) -> str:
    """Get emoji for severity level."""
    return {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🟢",
        Severity.INFO: "ℹ️",
    }.get(severity, "❓")


def generate_report(state: NixCheckState) -> str:
    """Generate a comprehensive report from the collected data."""
    lines = []
    
    # Header
    lines.append("=" * 60)
    lines.append("🔍 NIXCHECK - System Health Report")
    lines.append("=" * 60)
    lines.append(f"Hostname: {state.hostname}")
    lines.append("")
    
    # Services Section
    lines.append("📋 SERVICES RUNNING")
    lines.append("-" * 40)
    if state.services:
        lines.append(f"Total services: {len(state.services)}")
        for svc in state.services[:10]:  # Show first 10
            status = "✅" if svc.status == "running" else "⚠️"
            enabled = " [enabled]" if svc.enabled else ""
            mem = f" ({svc.memory_mb:.1f} MB)" if svc.memory_mb else ""
            lines.append(f"  {status} {svc.name}{enabled}{mem}")
        if len(state.services) > 10:
            lines.append(f"  ... and {len(state.services) - 10} more")
    else:
        lines.append("  No services detected or unable to query systemd.")
    lines.append("")
    
    # Containers Section
    if state.check_containers:
        lines.append("🐳 CONTAINERS")
        lines.append("-" * 40)
        if state.containers:
            lines.append(f"Total containers: {len(state.containers)}")
            for c in state.containers:
                lines.append(f"  ✅ {c.name} (ID: {c.container_id})")
        else:
            lines.append("  No containers detected.")
        lines.append("")
    
    # Resources Section
    lines.append("💻 SYSTEM RESOURCES")
    lines.append("-" * 40)
    if state.resource_usage:
        r = state.resource_usage
        
        # CPU
        cpu_status = "✅" if r.cpu_percent < state.resource_warning_threshold else "⚠️"
        lines.append(f"  {cpu_status} CPU: {r.cpu_percent:.1f}% ({r.cpu_cores} cores)")
        
        # Memory
        mem_status = "✅" if r.memory_percent < state.resource_warning_threshold else "⚠️"
        lines.append(f"  {mem_status} Memory: {r.memory_percent:.1f}% ({r.memory_used_gb:.1f}/{r.memory_total_gb:.1f} GB)")
        
        # Disk
        disk_status = "✅" if r.disk_percent < state.resource_warning_threshold else "⚠️"
        lines.append(f"  {disk_status} Disk: {r.disk_percent:.1f}% ({r.disk_used_gb:.1f}/{r.disk_total_gb:.1f} GB)")
        
        # Load Average
        load = r.load_average
        lines.append(f"  📊 Load Average: {load[0]:.2f}, {load[1]:.2f}, {load[2]:.2f}")
        
        # Swap
        if r.swap_percent is not None:
            swap_status = "✅" if r.swap_percent < 50 else "⚠️"
            lines.append(f"  {swap_status} Swap: {r.swap_percent:.1f}%")
    else:
        lines.append("  Unable to collect resource information.")
    lines.append("")
    
    # Log Errors Section
    lines.append("📝 LOG ERRORS")
    lines.append("-" * 40)
    if state.log_errors:
        # Group by source
        sources: dict[str, list] = {}
        for err in state.log_errors:
            if err.source not in sources:
                sources[err.source] = []
            sources[err.source].append(err)
        
        lines.append(f"Total errors found: {len(state.log_errors)} in {len(sources)} sources")
        lines.append("")
        
        # Show top errors by severity
        critical_errors = [e for e in state.log_errors if e.severity == Severity.CRITICAL]
        high_errors = [e for e in state.log_errors if e.severity == Severity.HIGH]
        
        if critical_errors:
            lines.append(f"  🔴 CRITICAL ({len(critical_errors)}):")
            for err in critical_errors[:3]:
                lines.append(f"    [{err.source}] {err.message[:80]}")
        
        if high_errors:
            lines.append(f"  🟠 HIGH ({len(high_errors)}):")
            for err in high_errors[:5]:
                lines.append(f"    [{err.source}] {err.message[:80]}")
        
        # Summary by source
        lines.append("")
        lines.append("  Errors by source:")
        for source, errs in sorted(sources.items(), key=lambda x: -len(x[1]))[:10]:
            lines.append(f"    {source}: {len(errs)} errors")
    else:
        lines.append("  ✅ No errors found in logs.")
    lines.append("")
    
    # JVM Section
    if state.java_detected:
        lines.append("☕ JAVA PROCESSES")
        lines.append("-" * 40)
        if state.jvm_configs:
            for jvm in state.jvm_configs:
                lines.append(f"  Process: {jvm.java_process} (PID: {jvm.pid})")
                if jvm.xmx_found:
                    lines.append(f"    -Xmx: {jvm.heap_max_mb} MB")
                else:
                    lines.append("    -Xmx: NOT SET ⚠️")
                
                if jvm.xms_found:
                    lines.append(f"    -Xms: {jvm.heap_min_mb} MB")
                
                if jvm.properties_file:
                    lines.append(f"    Properties: {jvm.properties_file}")
                
                if jvm.recommendations:
                    lines.append("    Recommendations:")
                    for rec in jvm.recommendations:
                        lines.append(f"      ⚠️ {rec}")
        lines.append("")
    
    # Security Section
    if state.check_security:
        lines.append("🔒 SECURITY CHECK")
        lines.append("-" * 40)
        if state.security_issues:
            lines.append(f"Total issues: {len(state.security_issues)}")
            for issue in state.security_issues:
                emoji = severity_emoji(issue.severity)
                lines.append(f"  {emoji} [{issue.issue_type}] {issue.description}")
                if issue.remediation:
                    lines.append(f"      → {issue.remediation}")
        else:
            lines.append("  ✅ No security issues detected.")
        lines.append("")
    
    # Summary
    lines.append("=" * 60)
    lines.append("📊 SUMMARY")
    lines.append("=" * 60)
    
    warnings = []
    if state.resource_usage:
        if state.resource_usage.cpu_percent >= state.resource_warning_threshold:
            warnings.append(f"High CPU usage: {state.resource_usage.cpu_percent:.1f}%")
        if state.resource_usage.memory_percent >= state.resource_warning_threshold:
            warnings.append(f"High memory usage: {state.resource_usage.memory_percent:.1f}%")
        if state.resource_usage.disk_percent >= state.resource_warning_threshold:
            warnings.append(f"High disk usage: {state.resource_usage.disk_percent:.1f}%")
    
    critical_count = len([e for e in state.log_errors if e.severity == Severity.CRITICAL])
    high_count = len([e for e in state.log_errors if e.severity == Severity.HIGH])
    security_critical = len([s for s in state.security_issues if s.severity in (Severity.CRITICAL, Severity.HIGH)])
    
    if critical_count > 0:
        warnings.append(f"{critical_count} critical log errors")
    if high_count > 0:
        warnings.append(f"{high_count} high severity log errors")
    if security_critical > 0:
        warnings.append(f"{security_critical} critical security issues")
    
    if warnings:
        lines.append("⚠️ WARNINGS:")
        for w in warnings:
            lines.append(f"  • {w}")
    else:
        lines.append("✅ System appears healthy - no warnings.")
    
    lines.append("")
    lines.append("=" * 60)
    
    return "\n".join(lines)


def generate_json_summary(state: NixCheckState) -> dict[str, Any]:
    """Generate a JSON-serializable summary."""
    return {
        "hostname": state.hostname,
        "services_count": len(state.services),
        "containers_count": len(state.containers),
        "resources": {
            "cpu_percent": state.resource_usage.cpu_percent if state.resource_usage else None,
            "memory_percent": state.resource_usage.memory_percent if state.resource_usage else None,
            "disk_percent": state.resource_usage.disk_percent if state.resource_usage else None,
        },
        "errors_count": len(state.log_errors),
        "java_detected": state.java_detected,
        "jvm_configs_count": len(state.jvm_configs),
        "security_issues_count": len(state.security_issues),
        "has_warnings": (
            bool(state.resource_usage and (
                state.resource_usage.cpu_percent >= state.resource_warning_threshold or
                state.resource_usage.memory_percent >= state.resource_warning_threshold or
                state.resource_usage.disk_percent >= state.resource_warning_threshold
            )) or
            len(state.log_errors) > 0 or
            len(state.security_issues) > 0
        ),
    }