from vulnmind.matcher import (
    _extract_product_version,
    _find_best_match,
    _version_less_than,
    match_finding,
)
from vulnmind.parsers.base import Finding


def make_finding(**overrides):
    values = {
        "id": "test-id",
        "source_tool": "pytest",
        "source_file": "inline",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "host": "192.0.2.10",
        "port": 80,
        "protocol": "tcp",
        "service": "http",
        "title": "Open port 80/tcp - Apache httpd 2.4.49",
        "description": "Parser-built scan evidence must be preserved.",
        "raw_evidence": "service: http\nproduct: Apache httpd\nversion: 2.4.49",
        "cve_ids": [],
    }
    values.update(overrides)
    return Finding(**values)


def test_strong_match_merges_cves_and_preserves_parser_description():
    finding = make_finding(cve_ids=["CVE-2021-41773"])

    enriched = match_finding(finding)

    assert enriched.priority == "critical"
    assert set(enriched.cve_ids) == {"CVE-2021-41773", "CVE-2021-42013"}
    assert enriched.description == "Parser-built scan evidence must be preserved."
    assert enriched.suggested_commands
    assert all("192.0.2.10" in command for command in enriched.suggested_commands)
    assert enriched.false_positive_likelihood == "low"


def test_weak_service_fallback_does_not_add_kb_cves_or_commands():
    finding = make_finding(
        title="Open port 80/tcp (http)",
        description="Port 80/tcp is open on 192.0.2.10, running http.",
        raw_evidence="host: 192.0.2.10  port: 80/tcp  state: open\nservice: http",
        cve_ids=["CVE-2099-0001"],
    )

    enriched = match_finding(finding)

    assert enriched.cve_ids == ["CVE-2099-0001"]
    assert enriched.suggested_commands == []
    assert enriched.metasploit_modules == []
    assert enriched.false_positive_likelihood == "medium"


def test_product_specific_entries_are_not_selected_for_other_products():
    entries = [
        {"product": "tp-link", "priority": "high", "cves": ["CVE-2023-1389"]},
        {"product": None, "priority": "medium", "cves": ["CVE-2010-2333"]},
    ]

    match, confidence = _find_best_match(entries, product="apache", version="2.4.41")

    assert confidence == "weak"
    assert match["product"] is None


def test_version_tokens_must_have_a_dot_and_be_after_product():
    finding = make_finding(
        title="Open port 21/tcp - vsftpd",
        description="Port 21 is open. Build 7601 appears before the product.",
        raw_evidence="host: target port: 21\nproduct: vsftpd\nversion: 2.3.4",
    )

    product, version = _extract_product_version(finding)

    assert product == "vsftpd"
    assert version == "2.3.4"


def test_version_before_comparison_handles_common_service_versions():
    assert _version_less_than("7.2p2", "8.0")
    assert _version_less_than("2.4.49", "2.4.51")
    assert not _version_less_than("8.2p1", "8.0")


def test_equivalent_products_match_version_before_entries():
    entries = [
        {
            "product": "mysql",
            "version_before": "8.0",
            "priority": "medium",
            "cves": [],
        }
    ]

    match, confidence = _find_best_match(entries, product="mariadb", version="5.7.32")

    assert confidence == "strong"
    assert match["product"] == "mysql"
