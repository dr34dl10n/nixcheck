"""
LangGraph workflow for nixcheck.
"""

import logging

from langgraph.graph import END, StateGraph

from .collectors import (
    analyze_jvm_config,
    collect_containers,
    collect_journal_errors,
    collect_resource_usage,
    collect_security_issues,
    collect_services,
    collect_var_log_errors,
    detect_java_processes,
    load_miner_names,
)
from .models import NixCheckState
from .reporter import generate_report

__all__ = [
    "build_graph",
    "run_nixcheck",
    "should_analyze_jvm",
]

logger = logging.getLogger(__name__)


def collect_services_node(state: NixCheckState) -> dict:
    """Node: Collect running services."""
    logger.debug("Collecting services")
    services = collect_services(fast=state.fast_mode)
    return {"services": services}


def collect_containers_node(state: NixCheckState) -> dict:
    """Node: Collect running containers."""
    if not state.check_containers:
        return {"containers": []}
    logger.debug("Collecting containers")
    containers = collect_containers()
    return {"containers": containers}


def collect_resources_node(state: NixCheckState) -> dict:
    """Node: Collect system resource usage."""
    logger.debug("Collecting resource usage")
    resource_usage = collect_resource_usage(fast=state.fast_mode)
    return {"resource_usage": resource_usage}


def collect_logs_node(state: NixCheckState) -> dict:
    """Node: Collect log errors."""
    logger.debug("Collecting log errors (limit=%d)", state.log_lines_limit)
    journal_errors = collect_journal_errors(state.log_lines_limit)
    var_log_errors = collect_var_log_errors()
    all_errors = journal_errors + var_log_errors
    logger.info("Found %d log errors", len(all_errors))
    return {"log_errors": all_errors, "errors_found": len(all_errors) > 0}


def detect_java_node(state: NixCheckState) -> dict:
    """Node: Detect Java processes."""
    logger.debug("Detecting Java processes")
    java_procs = detect_java_processes()
    logger.info("Java detected: %s (%d processes)", len(java_procs) > 0, len(java_procs))
    return {"java_detected": len(java_procs) > 0, "java_procs_data": java_procs}


def analyze_jvm_node(state: NixCheckState) -> dict:
    """Node: Analyze JVM configurations."""
    java_procs = state.java_procs_data
    if not java_procs:
        return {"jvm_configs": []}
    
    logger.debug("Analyzing %d JVM configurations", len(java_procs))
    jvm_configs = []
    for proc in java_procs:
        config = analyze_jvm_config(proc)
        if config:
            jvm_configs.append(config)
    return {"jvm_configs": jvm_configs}


def collect_security_node(state: NixCheckState) -> dict:
    """Node: Collect security issues."""
    if not state.check_security:
        return {"security_issues": [], "security_concerns": False}
    logger.debug("Collecting security issues")
    miner_names = load_miner_names(state.miner_list_path)
    issues = collect_security_issues(miner_names, fast=state.fast_mode)
    logger.info("Found %d security issues", len(issues))
    return {"security_issues": issues, "security_concerns": len(issues) > 0}


def report_node(state: NixCheckState) -> dict:
    """Node: Generate final report."""
    logger.debug("Generating report")
    report = generate_report(state)
    return {"report": report}


def should_analyze_jvm(state: NixCheckState) -> str:
    """Conditional edge: Should we analyze JVM?"""
    if state.java_detected:
        return "analyze_jvm"
    return "report"


def build_graph() -> StateGraph:
    """Build the LangGraph workflow."""
    graph = StateGraph(NixCheckState)
    
    # Add nodes
    graph.add_node("collect_services", collect_services_node)
    graph.add_node("collect_containers", collect_containers_node)
    graph.add_node("collect_resources", collect_resources_node)
    graph.add_node("collect_logs", collect_logs_node)
    graph.add_node("detect_java", detect_java_node)
    graph.add_node("analyze_jvm", analyze_jvm_node)
    graph.add_node("collect_security", collect_security_node)
    graph.add_node("report", report_node)
    
    # Set entry point
    graph.set_entry_point("collect_services")
    
    # Add edges
    graph.add_edge("collect_services", "collect_containers")
    graph.add_edge("collect_containers", "collect_resources")
    graph.add_edge("collect_resources", "collect_logs")
    graph.add_edge("collect_logs", "detect_java")
    graph.add_edge("detect_java", "collect_security")
    
    # Conditional edge for JVM analysis
    graph.add_conditional_edges(
        "collect_security",
        should_analyze_jvm,
        {"analyze_jvm": "analyze_jvm", "report": "report"}
    )
    
    graph.add_edge("analyze_jvm", "report")
    graph.add_edge("report", END)
    
    return graph


def run_nixcheck(
    hostname: str = "localhost",
    check_containers: bool = True,
    check_security: bool = True,
    log_lines_limit: int = 1000,
    resource_warning_threshold: float = 80.0,
    miner_list_path: str | None = None,
    fast_mode: bool = False,
) -> NixCheckState:
    """Run the full nixcheck workflow."""
    logger.info("Running nixcheck for hostname=%s", hostname)
    graph = build_graph()
    app = graph.compile()
    
    initial_state = NixCheckState(
        hostname=hostname,
        check_containers=check_containers,
        check_security=check_security,
        log_lines_limit=log_lines_limit,
        resource_warning_threshold=resource_warning_threshold,
        miner_list_path=miner_list_path,
        fast_mode=fast_mode,
    )
    
    final_state = app.invoke(initial_state)
    logger.info("nixcheck completed")
    return final_state