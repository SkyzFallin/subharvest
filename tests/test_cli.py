from __future__ import annotations

from typer.testing import CliRunner

from subharvest.cli import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "subharvest" in result.stdout


def test_list_sources():
    result = runner.invoke(app, ["--list-sources"])
    assert result.exit_code == 0
    assert "crtsh" in result.stdout


def test_unknown_format_rejected():
    result = runner.invoke(app, ["example.com", "--format", "yaml"])
    assert result.exit_code == 2


def test_unknown_only_source_rejected():
    result = runner.invoke(app, ["example.com", "--only", "nonexistent"])
    assert result.exit_code == 2
