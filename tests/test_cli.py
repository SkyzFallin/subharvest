from __future__ import annotations

import os
from pathlib import Path

import httpx
import respx
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


def test_auto_saves_txt_artifact_to_output_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with respx.mock(base_url="https://crt.sh") as mock:
        mock.get("/").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {"name_value": "www.example.com", "not_before": "2024-01-01"},
                    {"name_value": "api.example.com", "not_before": "2024-02-01"},
                ],
            )
        )
        result = runner.invoke(
            app,
            ["example.com", "--only", "crtsh", "--format", "txt", "--quiet"],
        )

    assert result.exit_code == 0, result.stdout

    artifacts = list((tmp_path / "output").glob("example.com-*.txt"))
    assert len(artifacts) == 1, f"expected one artifact, got {artifacts}"
    body = artifacts[0].read_text()
    assert "www.example.com" in body
    assert "api.example.com" in body


def test_no_auto_output_disables_artifact(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with respx.mock(base_url="https://crt.sh") as mock:
        mock.get("/").mock(
            return_value=httpx.Response(
                200, json=[{"name_value": "www.example.com"}]
            )
        )
        result = runner.invoke(
            app,
            [
                "example.com",
                "--only",
                "crtsh",
                "--format",
                "txt",
                "--quiet",
                "--no-auto-output",
            ],
        )
    assert result.exit_code == 0
    assert not (tmp_path / "output").exists()


def test_unsafe_domain_chars_sanitized_in_filename(tmp_path, monkeypatch):
    """Defense-in-depth: filename must not allow path traversal even if the
    domain argument contains slashes or dots outside the leaf."""
    monkeypatch.chdir(tmp_path)
    with respx.mock(base_url="https://crt.sh") as mock:
        mock.get("/").mock(return_value=httpx.Response(200, json=[]))
        result = runner.invoke(
            app, ["..//evil", "--only", "crtsh", "--format", "txt", "--quiet"]
        )
    assert result.exit_code == 0
    output_dir = tmp_path / "output"
    artifacts = list(output_dir.iterdir())
    assert artifacts, "expected an artifact even for sanitized name"
    for a in artifacts:
        # Path separators cannot survive sanitization
        assert "/" not in a.name and "\\" not in a.name
        # Artifact must stay strictly inside output/ — no traversal escape
        assert a.resolve().is_relative_to(output_dir.resolve())
