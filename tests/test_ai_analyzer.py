"""Tests for the AI analyzer module."""

from unittest.mock import MagicMock, patch

import pytest

from nixcheck.ai_analyzer import AIAnalyzerError, analyze_with_ai, _serialize_state
from nixcheck.models import (
    JVMConfig,
    LogError,
    NixCheckState,
    ResourceUsage,
    SecurityIssue,
    ServiceInfo,
    Severity,
)


@pytest.fixture
def healthy_state():
    """A state with no issues."""
    return NixCheckState(
        hostname="test-server",
        resource_usage=ResourceUsage(
            cpu_percent=12.5,
            cpu_cores=4,
            memory_percent=45.0,
            memory_total_gb=16.0,
            memory_used_gb=7.2,
            memory_available_gb=8.8,
            disk_percent=55.0,
            disk_total_gb=100.0,
            disk_used_gb=55.0,
            disk_available_gb=45.0,
            load_average=(0.5, 0.4, 0.3),
            swap_percent=0.0,
        ),
        services=[
            ServiceInfo(name="sshd", status="running", enabled=True, pid=1234, memory_mb=5.2),
        ],
    )


@pytest.fixture
def unhealthy_state():
    """A state with multiple issues."""
    return NixCheckState(
        hostname="prod-server",
        resource_usage=ResourceUsage(
            cpu_percent=92.0,
            cpu_cores=8,
            memory_percent=88.5,
            memory_total_gb=32.0,
            memory_used_gb=28.3,
            memory_available_gb=3.7,
            disk_percent=95.0,
            disk_total_gb=200.0,
            disk_used_gb=190.0,
            disk_available_gb=10.0,
            load_average=(8.5, 7.2, 5.1),
            swap_percent=45.0,
        ),
        log_errors=[
            LogError(
                source="systemd",
                message="Failed to start nginx.service",
                severity=Severity.CRITICAL,
            ),
            LogError(
                source="kernel",
                message="Out of memory: Kill process 1234 (java)",
                severity=Severity.HIGH,
            ),
        ],
        security_issues=[
            SecurityIssue(
                issue_type="crypto_miner",
                severity=Severity.CRITICAL,
                description="xmrig process detected (PID 5678)",
                remediation="Kill the process and investigate how it was installed.",
            ),
        ],
        java_detected=True,
        jvm_configs=[
            JVMConfig(
                java_process="elasticsearch",
                pid=1234,
                heap_max_mb=2048,
                xmx_found=True,
                xms_found=False,
                recommendations=["Consider setting -Xms equal to -Xmx for production"],
            ),
        ],
    )


class TestSerializeState:
    def test_serializes_to_dict(self, healthy_state):
        data = _serialize_state(healthy_state)
        assert data["hostname"] == "test-server"
        assert data["resource_usage"]["cpu_percent"] == 12.5
        assert isinstance(data["services"], list)

    def test_trims_log_errors(self, unhealthy_state):
        # Add many errors to test trimming
        unhealthy_state.log_errors = [
            LogError(source=f"src{i}", message=f"error {i}", severity=Severity.LOW)
            for i in range(100)
        ]
        data = _serialize_state(unhealthy_state)
        assert len(data["log_errors"]) <= 50

    def test_sorts_errors_by_severity(self, unhealthy_state):
        # Mix of severities
        unhealthy_state.log_errors = [
            LogError(source="low", message="low issue", severity=Severity.LOW),
            LogError(source="crit", message="critical issue", severity=Severity.CRITICAL),
            LogError(source="high", message="high issue", severity=Severity.HIGH),
        ]
        data = _serialize_state(unhealthy_state)
        assert data["log_errors"][0]["severity"] == "critical"
        assert data["log_errors"][1]["severity"] == "high"
        assert data["log_errors"][2]["severity"] == "low"


class TestAnalyzeWithAI:
    def test_returns_diagnosis(self, unhealthy_state):
        """Mock the OpenAI client and verify the call chain."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "### Overall Health\nServer is in critical state."

        with patch("openai.OpenAI") as mock_openai:
            mock_client = MagicMock()
            mock_client.chat.completions.create.return_value = mock_response
            mock_openai.return_value = mock_client

            result = analyze_with_ai(unhealthy_state, model="test-model")

        assert "Overall Health" in result
        mock_client.chat.completions.create.assert_called_once()
        call_kwargs = mock_client.chat.completions.create.call_args
        assert call_kwargs.kwargs["model"] == "test-model"
        assert call_kwargs.kwargs["temperature"] == 0.3

    def test_passes_base_url_and_api_key(self, healthy_state):
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "All good."

        with patch("openai.OpenAI") as mock_openai:
            mock_client = MagicMock()
            mock_client.chat.completions.create.return_value = mock_response
            mock_openai.return_value = mock_client

            analyze_with_ai(
                healthy_state,
                model="local-model",
                base_url="http://localhost:11434/v1",
                api_key="test-key",
            )

        mock_openai.assert_called_once_with(
            base_url="http://localhost:11434/v1",
            api_key="test-key",
        )

    def test_raises_on_empty_response(self, healthy_state):
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = None

        with patch("openai.OpenAI") as mock_openai:
            mock_client = MagicMock()
            mock_client.chat.completions.create.return_value = mock_response
            mock_openai.return_value = mock_client

            with pytest.raises(AIAnalyzerError, match="empty response"):
                analyze_with_ai(healthy_state)

    def test_raises_when_openai_missing(self, healthy_state):
        with patch.dict("sys.modules", {"openai": None}):
            with pytest.raises(AIAnalyzerError, match="openai.*required"):
                analyze_with_ai(healthy_state)

    def test_system_prompt_included(self, unhealthy_state):
        """Verify the system prompt is sent as the first message."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Diagnosis."

        with patch("openai.OpenAI") as mock_openai:
            mock_client = MagicMock()
            mock_client.chat.completions.create.return_value = mock_response
            mock_openai.return_value = mock_client

            analyze_with_ai(unhealthy_state)

        messages = mock_client.chat.completions.create.call_args.kwargs["messages"]
        assert messages[0]["role"] == "system"
        assert "senior Linux systems administrator" in messages[0]["content"]
        assert messages[1]["role"] == "user"
        assert "json" in messages[1]["content"].lower()