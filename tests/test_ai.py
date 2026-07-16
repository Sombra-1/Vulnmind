from types import SimpleNamespace

import requests

from vulnmind import ai
from vulnmind.parsers.base import Finding


def make_finding(**overrides):
    values = {
        "id": "ai-test",
        "source_tool": "pytest",
        "source_file": "inline",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "host": "192.0.2.10",
        "port": 80,
        "protocol": "tcp",
        "service": "http",
        "title": "Finding",
        "description": "Evidence",
        "raw_evidence": "Evidence",
        "suggested_commands": ["existing-command"],
        "metasploit_modules": ["existing/module"],
    }
    values.update(overrides)
    return Finding(**values)


def test_apply_enrichment_preserves_stable_list_and_string_types():
    finding = make_finding()

    result = ai._apply_enrichment(finding, {
        "explanation": {"not": "a string"},
        "priority": ["critical"],
        "priority_reason": 123,
        "suggested_commands": "curl example.test",
        "metasploit_modules": {"module": "bad"},
        "false_positive_likelihood": None,
        "false_positive_reason": ["bad"],
        "remediation": {"bad": True},
    })

    assert result.ai_explanation is None
    assert result.priority is None
    assert result.suggested_commands == ["existing-command"]
    assert result.metasploit_modules == ["existing/module"]
    assert result.false_positive_likelihood is None
    assert result.remediation is None


def test_quiet_enrichment_never_prints_network_errors(monkeypatch, capsys):
    monkeypatch.setattr(
        ai,
        "_call_groq",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            requests.ConnectionError("offline")
        ),
    )
    monkeypatch.setattr(ai.time, "sleep", lambda delay: None)
    cfg = SimpleNamespace(groq_api_key="test-key", model=None)

    result = ai.enrich_findings(
        [make_finding(), make_finding(id="second")],
        cfg,
        quiet=True,
    )

    assert len(result) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_suggested_module_is_not_promoted_to_verified_intelligence():
    finding = make_finding(
        metasploit_modules=[],
        metasploit_available=False,
        exploit_confidence="none",
    )

    result = ai._apply_enrichment(finding, {
        "metasploit_modules": ["exploit/unverified/suggestion"],
    })

    assert result.metasploit_modules == ["exploit/unverified/suggestion"]
    assert result.metasploit_available is False
    assert result.exploit_confidence == "none"
    assert result.exploit_references == []


def test_http_error_without_response_never_escapes(monkeypatch):
    monkeypatch.setattr(
        ai,
        "_call_groq",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            requests.HTTPError("connection closed")
        ),
    )

    result = ai._enrich_one(
        make_finding(),
        api_key="test-key",
        model="test-model",
        deep=False,
    )

    assert result.id == "ai-test"
