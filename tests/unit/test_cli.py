"""Unit tests for AEGIS Agent 1 — CLI interface."""

from click.testing import CliRunner

from agent1.cli import main


class TestCLI:
    """Tests for the aegis CLI."""

    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "aegis" in result.output
        assert "0.1.0" in result.output

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Runtime Security Agent" in result.output

    def test_scan_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--auth-config" in result.output
        assert "--scope" in result.output
        assert "--max-requests" in result.output
        assert "--rate-limit" in result.output
        assert "--timeout" in result.output
        assert "--tests" in result.output
        assert "--output" in result.output
        assert "--format" in result.output
        assert "--safe" in result.output

    def test_scan_missing_url(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan"])
        assert result.exit_code != 0
