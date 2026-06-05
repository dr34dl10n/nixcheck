"""System collectors - gather data from the Linux system."""

import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import psutil

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

from .models import (
    JVMConfig,
    LogError,
    ResourceUsage,
    SecurityIssue,
    ServiceInfo,
    Severity,
)

__all__ = [
    "CRYPTO_MINER_NAMES",
    "analyze_jvm_config",
    "collect_containers",
    "collect_journal_errors",
    "collect_resource_usage",
    "collect_security_issues",
    "collect_services",
    "collect_var_log_errors",
    "detect_java_processes",
    "load_miner_names",
    "run_cmd",
]

logger = logging.getLogger(__name__)

CRYPTO_MINER_NAMES = {
    "xmrig", "minerd", "cgminer", "cpuminer", "ethminer",
    "bfgminer", "sgminer", "ccminer", "claymore", "phoenixminer",
    "t-rex", "nanominer", "lolminer", "nbminer", "teamredminer",
    "wildrig-multi", "xmr-stak", "xmrig-proxy",
}


def load_miner_names(path: str | None = None) -> set[str]:
    """Load crypto miner names from a YAML or JSON file, or use built-in defaults."""
    if path:
        file_path = Path(path)
        if not file_path.exists():
            logger.warning("Miner list file not found: %s, using defaults", path)
            return CRYPTO_MINER_NAMES.copy()
        try:
            content = file_path.read_text()
            if file_path.suffix in (".yaml", ".yml"):
                if yaml is None:
                    logger.warning("PyYAML not installed, falling back to JSON parser")
                    return CRYPTO_MINER_NAMES.copy()
                data = yaml.safe_load(content)
                if isinstance(data, dict) and "miners" in data:
                    return set(data["miners"])
                if isinstance(data, list):
                    return set(data)
                logger.warning("Unrecognized YAML structure in %s, using defaults", path)
            elif file_path.suffix == ".json":
                data = json.loads(content)
                if isinstance(data, dict) and "miners" in data:
                    return set(data["miners"])
                if isinstance(data, list):
                    return set(data)
                logger.warning("Unrecognized JSON structure in %s, using defaults", path)
            else:
                # Treat as simple text file: one name per line
                return {line.strip() for line in content.split("\n") if line.strip() and not line.startswith("#")}
        except Exception:
            logger.exception("Failed to load miner list from %s, using defaults", path)
    return CRYPTO_MINER_NAMES.copy()


def run_cmd(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logger.warning("Command %s timed out after %ds", cmd, timeout)
        return -1, "", "Command timed out"
    except FileNotFoundError:
        logger.debug("Command not found: %s", cmd[0])
        return -1, "", "Command not found"
    except Exception as e:
        logger.error("Error running command %s: %s", cmd, e)
        return -1, "", str(e)


def collect_services(fast: bool = False) -> list[ServiceInfo]:
    """Collect running systemd services."""
    cpu_interval = None if fast else 0.1
    services = []
    code, stdout, _ = run_cmd(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"])
    if code == 0 and stdout:
        for line in stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 4:
                name = parts[0].replace(".service", "")
                services.append(ServiceInfo(name=name, status="running", enabled=False))
    code, stdout, _ = run_cmd(["systemctl", "list-unit-files", "--type=service", "--no-pager", "--no-legend"])
    if code == 0 and stdout:
        enabled_services = set()
        for line in stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "enabled":
                enabled_services.add(parts[0].replace(".service", ""))
        for svc in services:
            if svc.name in enabled_services:
                svc.enabled = True

    # Enhance top 15 services with details
    for svc in services[:15]:
        code, stdout, _ = run_cmd([
            "systemctl", "show", f"{svc.name}.service",
            "--property=MainPID,MemoryCurrent,ActiveState,LoadState"
        ])
        if code != 0:
            continue
        props = {}
        for line in stdout.strip().split("\n"):
            if "=" in line:
                k, v = line.split("=", 1)
                props[k] = v
        pid_str = props.get("MainPID")
        if pid_str and pid_str.isdigit():
            pid = int(pid_str)
            try:
                p = psutil.Process(pid)
                svc.pid = pid
                svc.memory_mb = p.memory_info().rss / (1024 ** 2)
                svc.cpu_percent = p.cpu_percent(interval=cpu_interval)
            except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
                logger.debug("Could not query process for service %s", svc.name)
        mem_str = props.get("MemoryCurrent", "0")
        try:
            mem_bytes = int(mem_str)
            svc.memory_mb = max(svc.memory_mb or 0.0, mem_bytes / (1024 ** 2))
        except ValueError:
            logger.debug("Invalid MemoryCurrent value for service %s", svc.name)
    return services


def collect_containers() -> list[ServiceInfo]:
    """Collect running containers (Docker, Podman)."""
    containers = []
    # Docker
    code, stdout, _ = run_cmd(["docker", "ps", "--format", "{{json .}}"])
    if code == 0 and stdout:
        for line in stdout.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                containers.append(ServiceInfo(
                    name=data.get("Names", data.get("Image", "unknown")),
                    status="running", is_container=True,
                    container_id=data.get("ID", data.get("Id", ""))[:12]))
            except json.JSONDecodeError:
                logger.debug("Failed to parse docker container JSON")
                continue
    # Podman
    code, stdout, _ = run_cmd(["podman", "ps", "--format", "{{json .}}"])
    if code == 0 and stdout:
        for line in stdout.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                containers.append(ServiceInfo(
                    name=data.get("Names", data.get("Image", "unknown")),
                    status="running", is_container=True,
                    container_id=data.get("ID", data.get("Id", ""))[:12]))
            except json.JSONDecodeError:
                logger.debug("Failed to parse podman container JSON")
                continue
    return containers


def collect_resource_usage(fast: bool = False) -> ResourceUsage | None:
    """Collect system resource usage."""
    try:
        cpu_interval = None if fast else 1
        cpu_percent = psutil.cpu_percent(interval=cpu_interval)
        cpu_cores = psutil.cpu_count()
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        load_avg = os.getloadavg()
        swap = psutil.swap_memory()
        return ResourceUsage(
            cpu_percent=cpu_percent, cpu_cores=cpu_cores,
            memory_percent=mem.percent, memory_total_gb=mem.total / 1024**3,
            memory_used_gb=mem.used / 1024**3, memory_available_gb=mem.available / 1024**3,
            disk_percent=disk.percent, disk_total_gb=disk.total / 1024**3,
            disk_used_gb=disk.used / 1024**3, disk_available_gb=disk.free / 1024**3,
            load_average=(load_avg[0], load_avg[1], load_avg[2]),
            swap_percent=swap.percent if swap.total > 0 else None)
    except Exception:
        logger.exception("Failed to collect resource usage")
        return None


def collect_journal_errors(limit: int = 1000) -> list[LogError]:
    """Collect errors from journalctl."""
    errors = []
    code, stdout, _ = run_cmd(["journalctl", "-p", "err", "-n", str(limit), "--no-pager", "--output", "json"])
    if code == 0 and stdout:
        for line in stdout.strip().split("\n")[:limit]:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                msg = data.get("MESSAGE", "")
                if not msg:
                    continue
                source = data.get("_COMM", data.get("SYSLOG_IDENTIFIER", "journal"))
                priority_str = data.get("PRIORITY")
                severity = Severity.MEDIUM
                if priority_str:
                    try:
                        pri = int(priority_str)
                        if pri <= 2:
                            severity = Severity.CRITICAL
                        elif pri <= 4:
                            severity = Severity.HIGH
                        elif pri == 5:
                            severity = Severity.MEDIUM
                        else:
                            severity = Severity.LOW
                    except ValueError:
                        logger.debug("Invalid journal PRIORITY value: %s", priority_str)
                if "critical" in msg.lower() or "fatal" in msg.lower():
                    severity = Severity.HIGH if severity.value not in ["critical"] else severity  # upgrade
                errors.append(LogError(source=source, message=msg[:500],
                    timestamp=data.get("__REALTIME_TIMESTAMP"), severity=severity, raw_line=msg))
            except json.JSONDecodeError:
                logger.debug("Failed to parse journalctl JSON line")
                continue
    return errors


def collect_var_log_errors() -> list[LogError]:
    """Collect errors from /var/log files."""
    errors = []
    log_paths = ["/var/log/syslog", "/var/log/messages", "/var/log/kern.log"]
    error_pattern = re.compile(r"(?i)(error|fail|critical|fatal|warn)")
    for log_path in log_paths:
        path = Path(log_path)
        if not path.exists():
            continue
        try:
            content = path.read_text(errors="ignore")
            for line in content.split("\n")[-500:]:
                msg_lower = line.lower()
                if not error_pattern.search(line):
                    continue
                sev = Severity.LOW
                if any(word in msg_lower for word in ["critical", "fatal"]):
                    sev = Severity.HIGH
                elif any(word in msg_lower for word in ["error", "failed", "fail"]):
                    sev = Severity.MEDIUM
                elif "warn" in msg_lower:
                    sev = Severity.MEDIUM
                errors.append(LogError(source=path.name, message=line[:500],
                    timestamp=None, severity=sev, raw_line=line))
        except Exception:
            logger.exception("Error reading log file %s", log_path)
            continue
    return errors


def detect_java_processes() -> list[dict[str, Any]]:
    """Detect running Java processes."""
    java_procs = []
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            name = proc.info.get("name", "")
            cmdline = proc.info.get("cmdline") or []
            if "java" in name.lower() or any("java" in c.lower() for c in cmdline):
                java_procs.append({"pid": proc.info["pid"], "name": name, "cmdline": cmdline})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            logger.debug("Cannot access process pid=%s", proc.info.get("pid"))
            continue
    return java_procs


def analyze_jvm_config(proc_info: dict[str, Any]) -> JVMConfig | None:
    """Analyze JVM configuration for a Java process."""
    cmdline = proc_info.get("cmdline", [])
    pid = proc_info.get("pid", 0)
    name = proc_info.get("name", "java")
    jvm = JVMConfig(java_process=name, pid=pid)
    for arg in cmdline:
        if arg.startswith("-Xmx"):
            jvm.xmx_found = True
            match = re.match(r"-Xmx(\d+)([kmgKMG])?", arg)
            if match:
                value = int(match.group(1))
                unit = match.group(2) or "M"
                multipliers = {"K": 1/1024, "M": 1, "G": 1024}
                jvm.heap_max_mb = value * multipliers.get(unit.upper(), 1)
        elif arg.startswith("-Xms"):
            jvm.xms_found = True
            match = re.match(r"-Xms(\d+)([kmgKMG])?", arg)
            if match:
                value = int(match.group(1))
                unit = match.group(2) or "M"
                multipliers = {"K": 1/1024, "M": 1, "G": 1024}
                jvm.heap_min_mb = value * multipliers.get(unit.upper(), 1)
        elif arg.startswith("-D") and ".properties" in arg:
            jvm.properties_file = arg.split("=")[-1] if "=" in arg else None
    if not jvm.xmx_found:
        jvm.recommendations.append("No -Xmx set, JVM may use default heap size")
    if jvm.heap_max_mb and jvm.heap_max_mb < 256:
        jvm.recommendations.append(f"Small heap size ({jvm.heap_max_mb}MB) may cause performance issues")
    return jvm


def collect_security_issues(miner_names: set[str] | None = None, fast: bool = False) -> list[SecurityIssue]:
    """Collect security issues including crypto miners and suspicious processes."""
    if miner_names is None:
        miner_names = CRYPTO_MINER_NAMES
    cpu_interval = None if fast else 0.1
    issues = []

    # Single pass: check for crypto miners + high CPU processes
    known_benign = {"python3", "python", "node", "java", "chrome", "firefox"}
    for proc in psutil.process_iter(["pid", "name", "cmdline", "cpu_percent"]):
        try:
            name = proc.info.get("name", "")
            cmdline = proc.info.get("cmdline") or []
            cmdline_str = " ".join(cmdline).lower()

            # Check for crypto miners
            is_miner = False
            for miner_name in miner_names:
                if miner_name in name.lower() or miner_name in cmdline_str:
                    issues.append(SecurityIssue(
                        issue_type="crypto_miner",
                        severity=Severity.CRITICAL,
                        description=f"Crypto miner detected: {name} (PID: {proc.info['pid']})",
                        details={"pid": proc.info["pid"], "name": name, "cmdline": cmdline},
                        remediation="Kill the process and investigate how it was installed. Check for unauthorized access.",
                    ))
                    is_miner = True
                    break

            # If not a miner, check for high CPU
            if not is_miner:
                cpu = proc.cpu_percent(interval=cpu_interval)
                if cpu > 80 and name.lower() not in miner_names and name not in known_benign:
                    issues.append(SecurityIssue(
                        issue_type="high_cpu_process",
                        severity=Severity.MEDIUM,
                        description=f"High CPU process: {name} (PID: {proc.info['pid']}) using {cpu:.1f}% CPU",
                        details={"pid": proc.info["pid"], "name": name, "cpu_percent": cpu},
                        remediation="Investigate the process to determine if it is legitimate.",
                    ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            logger.debug("Cannot access process for security check pid=%s", proc.info.get("pid"))
            continue

    # Check for suspicious cron jobs
    crontab_paths = [
        "/var/spool/cron/crontabs",
        "/etc/crontab",
        "/etc/cron.d",
    ]

    suspicious_patterns = [
        re.compile(r"(curl|wget)\s+.*\|\s*(bash|sh|python|perl)"),
        re.compile(r"base64\s+-d"),
        re.compile(r"(curl|wget)\s+.*https?://"),
        re.compile(r"/dev/tcp/"),
    ]

    for crontab_path in crontab_paths:
        path = Path(crontab_path)
        if path.is_file():
            try:
                content = path.read_text()
                for line in content.split("\n"):
                    for pattern in suspicious_patterns:
                        if pattern.search(line):
                            issues.append(SecurityIssue(
                                issue_type="suspicious_cron",
                                severity=Severity.HIGH,
                                description=f"Suspicious cron entry in {crontab_path}",
                                details={"file": str(crontab_path), "line": line[:200]},
                                remediation="Review and remove suspicious cron entries. Check for unauthorized access.",
                            ))
                            break
            except PermissionError:
                logger.debug("Permission denied reading cron path %s", crontab_path)
                issues.append(SecurityIssue(
                    issue_type="cron_permission",
                    severity=Severity.INFO,
                    description=f"Permission denied reading {path}",
                    details={"file": str(path)},
                    remediation="Run as root for full cron scan.",
                ))
            except Exception:
                logger.exception("Error reading cron path %s", crontab_path)
                continue
        elif path.is_dir():
            for file in path.iterdir():
                if file.is_file():
                    try:
                        content = file.read_text()
                        for line in content.split("\n"):
                            for pattern in suspicious_patterns:
                                if pattern.search(line):
                                    issues.append(SecurityIssue(
                                        issue_type="suspicious_cron",
                                        severity=Severity.HIGH,
                                        description=f"Suspicious cron entry in {file}",
                                        details={"file": str(file), "line": line[:200]},
                                        remediation="Review and remove suspicious cron entries. Check for unauthorized access.",
                                    ))
                                    break
                    except PermissionError:
                        logger.debug("Permission denied reading cron file %s", file)
                        issues.append(SecurityIssue(
                            issue_type="cron_permission",
                            severity=Severity.INFO,
                            description=f"Permission denied reading {file}",
                            details={"file": str(file)},
                            remediation="Run as root for full cron scan.",
                        ))
                    except Exception:
                        logger.exception("Error reading cron file %s", file)
                        continue

    return issues
