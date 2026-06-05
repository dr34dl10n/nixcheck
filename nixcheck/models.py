"""
Pydantic models for nixcheck state and results.
"""

import logging
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

__all__ = [
    "JVMConfig",
    "LogError",
    "NixCheckState",
    "ResourceUsage",
    "SecurityIssue",
    "ServiceInfo",
    "Severity",
]


class Severity(str, Enum):
    """Issue severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ServiceInfo(BaseModel):
    """Information about a running service."""
    name: str
    status: str
    enabled: bool = False
    pid: int | None = None
    memory_mb: float | None = None
    cpu_percent: float | None = None
    since: str | None = None
    is_container: bool = False
    container_id: str | None = None


class LogError(BaseModel):
    """A detected error from logs."""
    source: str
    message: str
    timestamp: str | None = None
    severity: Severity = Severity.MEDIUM
    count: int = 1
    raw_line: str | None = None


class ResourceUsage(BaseModel):
    """System resource usage snapshot."""
    cpu_percent: float
    cpu_cores: int
    memory_percent: float
    memory_total_gb: float
    memory_used_gb: float
    memory_available_gb: float
    disk_percent: float
    disk_total_gb: float
    disk_used_gb: float
    disk_available_gb: float
    load_average: tuple[float, float, float]
    swap_percent: float | None = None


class JVMConfig(BaseModel):
    """JVM configuration analysis."""
    java_process: str
    pid: int
    heap_max_mb: float | None = None
    heap_min_mb: float | None = None
    properties_file: str | None = None
    xmx_found: bool = False
    xms_found: bool = False
    recommendations: list[str] = Field(default_factory=list)


class SecurityIssue(BaseModel):
    """Detected security issue."""
    issue_type: str
    severity: Severity
    description: str
    details: dict[str, Any] = Field(default_factory=dict)
    remediation: str | None = None


class NixCheckState(BaseModel):
    """Main state for the LangGraph workflow."""
    # Inputs
    hostname: str = "localhost"
    check_containers: bool = True
    check_security: bool = True
    miner_list_path: str | None = None
    fast_mode: bool = False
    log_lines_limit: int = 1000
    resource_warning_threshold: float = 80.0

    # Collected data
    services: list[ServiceInfo] = Field(default_factory=list)
    containers: list[ServiceInfo] = Field(default_factory=list)
    resource_usage: ResourceUsage | None = None
    log_errors: list[LogError] = Field(default_factory=list)
    jvm_configs: list[JVMConfig] = Field(default_factory=list)
    security_issues: list[SecurityIssue] = Field(default_factory=list)

    # Internal: Java process details (passed between nodes, excluded from serialization)
    java_procs_data: list[dict[str, Any]] = Field(default_factory=list, exclude=True)

    # Workflow control
    java_detected: bool = False
    errors_found: bool = False
    security_concerns: bool = False

    # Final report
    report: str | None = None
    summary: dict[str, Any] = Field(default_factory=dict)
