"""
nixcheck - Linux system health checker.

A LangGraph-based tool that detects services, analyzes logs, checks resources,
and identifies potential security issues on Linux systems.
"""

import logging

__version__ = "0.1.0"

__all__ = ["__version__"]

logger = logging.getLogger(__name__)
