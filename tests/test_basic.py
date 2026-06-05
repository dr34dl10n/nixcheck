"""Tests for nixcheck."""

from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).parent.parent))

from nixcheck.models import (
    ServiceInfo, LogError, ResourceUsage, JVMConfig,
    SecurityIssue, Severity, NixCheckState
)


class TestModels:
    """Test Pydantic models."""

    def test_service_info_defaults(self):
        """Test ServiceInfo default values."""
        svc = ServiceInfo(name="test.service", status="running")
        assert svc.name == "test.service"
        assert svc.status == "running"
        assert svc.enabled is False
        assert svc.pid is None
        assert svc.is_container is False

    def test_log_error_severity(self):
        """Test LogError model."""
        err = LogError(source="test", message="error message")
        assert err.source == "test"
        assert err.severity == Severity.MEDIUM

    def test_resource_usage(self):
        """Test ResourceUsage model."""
        usage = ResourceUsage(
            cpu_percent=50.0, cpu_cores=4, memory_percent=60.0,
            memory_total_gb=16.0, memory_used_gb=9.6, memory_available_gb=6.4,
            disk_percent=40.0, disk_total_gb=500.0, disk_used_gb=200.0,
            disk_available_gb=300.0, load_average=(1.0, 1.5, 2.0), swap_percent=10.0
        )
        assert usage.cpu_percent == 50.0
        assert usage.cpu_cores == 4

    def test_jvm_config(self):
        """Test JVMConfig model."""
        jvm = JVMConfig(java_process="java", pid=1234, heap_max_mb=1024, xmx_found=True)
        assert jvm.heap_max_mb == 1024
        assert jvm.xmx_found is True

    def test_security_issue(self):
        """Test SecurityIssue model."""
        issue = SecurityIssue(
            issue_type="crypto_miner", severity=Severity.CRITICAL,
            description="Potential miner", details={"pid": 1234}
        )
        assert issue.issue_type == "crypto_miner"
        assert issue.severity == Severity.CRITICAL

    def test_nixcheck_state(self):
        """Test NixCheckState model."""
        state = NixCheckState(hostname="testhost")
        assert state.hostname == "testhost"
        assert state.check_containers is True
        assert len(state.services) == 0
