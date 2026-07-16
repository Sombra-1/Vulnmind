from pathlib import Path

import json
import pytest

from vulnmind.parsers import detect_and_parse
from vulnmind.parsers.nuclei import NucleiParser

FIXTURES = Path(__file__).resolve().parents[1]


def test_nuclei_jsonl_fixture_parses_results_and_skips_bad_lines():
    findings = detect_and_parse(FIXTURES / "sample_nuclei.jsonl")

    assert len(findings) == 3
    assert {finding.source_tool for finding in findings} == {"nuclei"}
    assert not any(f.title == "Failed matcher row" for f in findings)


def test_nuclei_trusts_classification_cves_and_target_fields():
    findings = detect_and_parse(FIXTURES / "sample_nuclei.jsonl")
    finding = next(f for f in findings if f.title.startswith("Apache Path Traversal"))

    assert finding.host == "target.local"
    assert finding.port == 443
    assert finding.protocol == "tcp"
    assert finding.service == "http"
    assert finding.priority == "critical"
    assert finding.confidence == "scanner-reported"
    assert finding.cve_ids == ["CVE-2021-41773"]
    assert finding.cvss_score == 7.5
    assert finding.suggested_commands == [
        "curl -sk --path-as-is 'https://target.local/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd'"
    ]
    assert "classification.cve-id: CVE-2021-41773" in finding.raw_evidence
    assert "root:x:0:0" in finding.raw_evidence


def test_nuclei_does_not_invent_cves_from_template_id():
    findings = detect_and_parse(FIXTURES / "sample_nuclei.jsonl")
    finding = next(f for f in findings if f.title.startswith("Template ID Mentions"))

    assert finding.host == "192.0.2.50"
    assert finding.port == 8080
    assert finding.priority == "low"
    assert finding.cve_ids == []
    assert finding.false_positive_likelihood == "medium"


def test_nuclei_tolerates_missing_fields():
    findings = detect_and_parse(FIXTURES / "sample_nuclei.jsonl")
    finding = next(f for f in findings if f.title == "Odd DNS finding")

    assert finding.host == "example.com"
    assert finding.port is None
    assert finding.protocol == "udp"
    assert finding.service == "dns"
    assert finding.priority == "low"


def test_nuclei_can_parse_go_style_json_keys():
    content = (
        '{"TemplateID":"go-style","Info":{"Name":"Go style event",'
        '"Severity":"medium","Classification":{"CVEID":"CVE-2024-12345"}},'
        '"Matched":"https://go.example/path","CURLCommand":"curl https://go.example/path"}'
    )

    findings = NucleiParser().parse(FIXTURES / "inline.jsonl", content)

    assert len(findings) == 1
    assert findings[0].host == "go.example"
    assert findings[0].port == 443
    assert findings[0].priority == "medium"
    assert findings[0].cve_ids == ["CVE-2024-12345"]


@pytest.mark.parametrize("malformed_target", ["http://[::1", "http://[not-ip]/x"])
def test_nuclei_malformed_bracketed_targets_fall_back_without_crashing(
    malformed_target,
):
    content = (
        '{"template-id":"malformed-target","info":{"name":"Result",'
        '"severity":"low"},"matched-at":'
        f'{__import__("json").dumps(malformed_target)},'
        '"host":"fallback.example"}'
    )

    findings = NucleiParser().parse(FIXTURES / "malformed.jsonl", content)

    assert len(findings) == 1
    assert findings[0].host == "fallback.example"


@pytest.mark.parametrize("invalid_score", [True, float("nan"), float("inf"), 10**400])
def test_nuclei_rejects_non_finite_or_oversized_cvss_without_crashing(
    invalid_score,
):
    content = json.dumps({
        "template-id": "invalid-cvss",
        "info": {
            "name": "Invalid score",
            "severity": "medium",
            "classification": {"cvss-score": invalid_score},
        },
        "matched-at": "https://target.example/",
    })

    findings = NucleiParser().parse(FIXTURES / "invalid_cvss.jsonl", content)

    assert len(findings) == 1
    assert findings[0].cvss_score is None
