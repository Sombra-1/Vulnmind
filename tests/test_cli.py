import json
from pathlib import Path
from types import SimpleNamespace

from click.testing import CliRunner

from vulnmind import updater
from vulnmind.cli import cli

FIXTURES = Path(__file__).resolve().parent


def _no_live_intel(findings, **kwargs):
    return findings


def test_json_output_is_valid_stable_and_deduplicated_across_files(monkeypatch):
    monkeypatch.setattr("vulnmind.cli._exploit_intel_enrich", _no_live_intel)
    runner = CliRunner()
    sample = str(FIXTURES / "sample_nmap.xml")

    result = runner.invoke(cli, ["analyze", sample, sample, "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert len(payload) == 5
    for finding in payload:
        assert finding["confidence"] in {
            "confirmed", "scanner-reported", "strong", "weak"
        }
        assert isinstance(finding["actively_exploited"], bool)
        assert isinstance(finding["exploit_available"], bool)
        assert isinstance(finding["metasploit_available"], bool)
        assert isinstance(finding["exploit_confidence"], str)
        assert isinstance(finding["exploit_references"], list)


def test_json_enrichment_requests_quiet_mode(monkeypatch):
    captured = {}
    monkeypatch.setattr("vulnmind.cli._exploit_intel_enrich", _no_live_intel)
    monkeypatch.setattr(
        "vulnmind.cli.Config.load",
        lambda: SimpleNamespace(
            groq_api_key="test-key",
            model=None,
            update_checks_enabled=False,
        ),
    )

    def fake_enrich(findings, cfg, deep, quiet):
        captured.update({"deep": deep, "quiet": quiet})
        return findings

    monkeypatch.setattr("vulnmind.ai.enrich_findings", fake_enrich)
    runner = CliRunner()

    result = runner.invoke(cli, [
        "analyze",
        str(FIXTURES / "sample_nuclei.jsonl"),
        "--enrich",
        "--format",
        "json",
    ])

    assert result.exit_code == 0, result.output
    json.loads(result.stdout)
    assert captured == {"deep": False, "quiet": True}


def test_json_parse_error_uses_stderr_only(tmp_path):
    bad_input = tmp_path / "unknown.txt"
    bad_input.write_text("not scanner output")
    runner = CliRunner()

    result = runner.invoke(cli, [
        "analyze",
        str(bad_input),
        "--format",
        "json",
    ])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "Error parsing scanner input" in result.stderr


def test_update_check_only_reports_release_without_installing(monkeypatch):
    monkeypatch.setattr(
        updater,
        "check_for_update",
        lambda force: {"latest": "v0.6.1", "newer": True, "checked_at": 1.0},
    )
    monkeypatch.setattr(
        updater,
        "perform_update",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("--check-only must not install")
        ),
    )
    runner = CliRunner()

    result = runner.invoke(cli, ["update", "--check-only"])

    assert result.exit_code == 0, result.output
    assert "v0.6.1" in result.output
    assert updater.RELEASES_URL in result.output


def test_empty_text_result_can_show_update_notice(monkeypatch, tmp_path):
    empty_scan = tmp_path / "empty.xml"
    empty_scan.write_text("<?xml version='1.0'?><nmaprun></nmaprun>")
    monkeypatch.setattr(
        "vulnmind.cli.Config.load",
        lambda: SimpleNamespace(
            groq_api_key=None,
            update_checks_enabled=True,
        ),
    )
    monkeypatch.setattr(updater, "start_check", lambda: None)
    monkeypatch.setattr(
        updater,
        "get_notice",
        lambda: "Update available: v0.6.1 — run vulnmind update",
    )

    result = CliRunner().invoke(cli, ["analyze", str(empty_scan)])

    assert result.exit_code == 0, result.output
    assert "No Findings" in result.output
    assert "Update available: v0.6.1" in result.output


def test_disabled_automatic_update_checks_do_not_start_network_thread(monkeypatch):
    monkeypatch.setattr(
        "vulnmind.cli.Config.load",
        lambda: SimpleNamespace(
            groq_api_key=None,
            update_checks_enabled=False,
        ),
    )
    monkeypatch.setattr(
        updater,
        "start_check",
        lambda: (_ for _ in ()).throw(
            AssertionError("disabled checks must not start")
        ),
    )
    monkeypatch.setattr("vulnmind.cli._exploit_intel_enrich", _no_live_intel)

    result = CliRunner().invoke(cli, [
        "analyze",
        str(FIXTURES / "sample_nuclei.jsonl"),
    ])

    assert result.exit_code == 0, result.output


def test_text_output_brackets_ipv6_target_with_port(monkeypatch, tmp_path):
    scan = tmp_path / "ipv6.jsonl"
    scan.write_text(json.dumps({
        "template-id": "ipv6-target",
        "info": {"name": "IPv6 result", "severity": "low"},
        "matched-at": "https://[2001:db8::1]:8443/",
    }))
    monkeypatch.setattr("vulnmind.cli._exploit_intel_enrich", _no_live_intel)
    monkeypatch.setattr(
        "vulnmind.cli.Config.load",
        lambda: SimpleNamespace(
            groq_api_key=None,
            update_checks_enabled=False,
        ),
    )

    result = CliRunner().invoke(cli, ["analyze", str(scan)])

    assert result.exit_code == 0, result.output
    assert "[2001:db8::1]:8443" in result.output
