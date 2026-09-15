"""AEGIS Agent 1 — CLI interface.

Primary user interface for running scans. Uses Click for argument
parsing and output formatting.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import click

from agent1 import __version__
from agent1.config import build_config
from agent1.orchestrator import ScanStatus, run_scan


def _setup_logging(verbose: bool = False) -> None:
    """Configure structured logging.

    Every log event contains: timestamp, scan_id (via extra), component
    (logger name), event (message), and severity (level).
    Never logs secrets.
    """
    level = logging.DEBUG if verbose else logging.INFO
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger("aegis")
    root_logger.setLevel(level)
    root_logger.addHandler(handler)


@click.group()
@click.version_option(version=__version__, prog_name="aegis")
def main():
    """AEGIS — Runtime Security Agent for web applications and APIs."""
    pass


@main.command()
@click.argument("url")
@click.option(
    "--auth-config",
    type=click.Path(exists=True),
    help="Path to authentication configuration YAML file.",
)
@click.option(
    "--scope",
    "scope_file",
    type=click.Path(exists=True),
    help="Path to scope/configuration YAML file.",
)
@click.option(
    "--max-requests",
    type=int,
    default=None,
    help="Maximum number of HTTP requests.",
)
@click.option(
    "--rate-limit",
    type=float,
    default=None,
    help="Maximum requests per second.",
)
@click.option(
    "--timeout",
    type=float,
    default=None,
    help="Per-request timeout in seconds.",
)
@click.option(
    "--tests",
    type=str,
    default=None,
    help="Comma-separated list of tests to run (e.g., bola,ssrf,misconfig).",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(),
    default=None,
    help="Path to write JSON report.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "text"]),
    default="text",
    help="Output format.",
)
@click.option(
    "--safe/--no-safe",
    default=True,
    help="Enable/disable safe mode (default: enabled).",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose debug logging.",
)
def scan(
    url: str,
    auth_config: str | None,
    scope_file: str | None,
    max_requests: int | None,
    rate_limit: float | None,
    timeout: float | None,
    tests: str | None,
    output_path: str | None,
    output_format: str,
    safe: bool,
    verbose: bool,
):
    """Run a security scan against a target URL.

    \b
    Examples:
        aegis scan https://example.test
        aegis scan https://example.test --tests bola,ssrf --output results.json
        aegis scan https://example.test --scope scope.yaml --auth-config auth.yaml
    """
    _setup_logging(verbose)

    # Parse test list
    test_list = None
    if tests:
        test_list = [t.strip() for t in tests.split(",")]

    # Build configuration
    try:
        config = build_config(
            url=url,
            scope_file=scope_file,
            max_requests=max_requests,
            rate_limit=rate_limit,
            timeout=timeout,
            tests=test_list,
            safe_mode=safe,
        )
    except Exception as e:
        click.echo(f"Configuration error: {e}", err=True)
        sys.exit(1)

    # Print scan header
    click.echo()
    click.echo("AEGIS Runtime Security Agent")
    click.echo("=" * 40)
    click.echo(f"Target:    {url}")
    click.echo(f"Safe Mode: {'ON' if safe else 'OFF'}")
    click.echo()

    # Execute scan
    result = run_scan(config, auth_config=auth_config)
    session = result.session

    # Print results
    click.echo(f"Scan ID:   {session.scan_id}")
    click.echo(f"Status:    {session.status.value}")
    click.echo()

    if session.status == ScanStatus.COMPLETED:
        click.echo("[+] Scope validated")
        click.echo("[+] Target probed")
        click.echo(f"[+] Endpoints discovered: {session.statistics.get('endpoints_discovered', 0)}")
        if result.discovery and result.discovery.endpoints and verbose:
            for ep in result.discovery.endpoints:
                click.echo(f"    - [{ep.id}] {ep.method} {ep.path} (source: {ep.source})")
        click.echo(f"[+] Total requests: {session.statistics.get('total_requests', 0)}")
        click.echo(f"[+] Evidence collected: {session.statistics.get('evidence_count', 0)}")
        click.echo(f"[+] Findings: {session.statistics.get('findings_count', 0)}")

        if result.findings:
            click.echo()
            click.echo("Findings:")
            click.echo("-" * 40)
            for f in result.findings:
                sev = f.get("severity", "INFO")
                title = f.get("title", "")
                ep = f.get("endpoint")
                ep_str = f"{ep.get('method')} {ep.get('path')}" if ep else ""
                click.echo(f"[{sev}] {title}")
                if ep_str:
                    click.echo(f"Endpoint: {ep_str}")
                click.echo(f"Details:  {f.get('description', '')}")
                evidence_list = f.get("evidence", [])
                if evidence_list:
                    click.echo(f"Evidence: {', '.join(evidence_list)}")
                click.echo("-" * 40)
    elif session.status == ScanStatus.FAILED:
        click.echo("[!] Scan failed")
        for error in session.errors:
            click.echo(f"    - [{error.get('component', '?')}] {error.get('error', error.get('message', 'Unknown error'))}")

    click.echo()

    # Build JSON report
    report = {
        "schema_version": "1.0",
        "scan": {
            "scan_id": session.scan_id,
            "target": session.target,
            "started_at": session.started_at.isoformat() if session.started_at else None,
            "finished_at": session.finished_at.isoformat() if session.finished_at else None,
            "status": session.status.value,
        },
        "target": {
            "url": session.target,
        },
        "discovery": result.discovery.model_dump(mode="json") if result.discovery else {},
        "findings": result.findings,
        "evidence": result.evidence,
        "statistics": session.statistics,
    }

    # Write output
    if output_path:
        output_file = Path(output_path)
        output_file.write_text(
            json.dumps(report, indent=2, default=str),
            encoding="utf-8",
        )
        click.echo(f"Report written to: {output_path}")
    elif output_format == "json":
        click.echo(json.dumps(report, indent=2, default=str))

    click.echo()
    click.echo("Scan completed.")


if __name__ == "__main__":
    main()
