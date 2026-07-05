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


def test_exact_version_match_does_not_overmatch_prefix_versions():
    entries = [
        {
            "product": "apache",
            "version_match": "2.4.49",
            "priority": "critical",
            "cves": ["CVE-2021-41773"],
        },
        {
            "product": "apache",
            "priority": "high",
            "cves": ["CVE-2011-3192"],
        },
    ]

    match, confidence = _find_best_match(entries, product="apache", version="2.4.490")

    assert confidence == "strong"
    assert match["cves"] == ["CVE-2011-3192"]


def test_http_tomcat_product_uses_tomcat_service_guidance():
    finding = make_finding(
        title="Open port 8080/tcp - Apache Tomcat 9.0.31",
        description="Port 8080/tcp is open on target.local, running http Apache Tomcat 9.0.31.",
        raw_evidence="service: http\nproduct: Apache Tomcat\nversion: 9.0.31",
        cve_ids=[],
    )

    enriched = match_finding(finding)

    assert enriched.priority == "high"
    assert "Tomcat" in enriched.priority_reason
    assert enriched.false_positive_likelihood == "medium"


def test_smb_windows_product_match_is_not_marked_weak_when_cve_is_parser_reported():
    finding = make_finding(
        service="microsoft-ds",
        port=445,
        title="smb-vuln-ms17-010 on target.local:445",
        description="NSE script 'smb-vuln-ms17-010' flagged target.local:445/tcp.",
        raw_evidence=(
            "Script: smb-vuln-ms17-010\n"
            "product: Windows 7\n"
            "Output:\nVULNERABLE: CVE:CVE-2017-0144"
        ),
        cve_ids=["CVE-2017-0144"],
    )

    enriched = match_finding(finding)

    assert enriched.priority == "high"
    assert enriched.cve_ids == ["CVE-2017-0144"]
    assert enriched.false_positive_likelihood == "low"
    assert "scanner output reported cve" in enriched.false_positive_reason.lower()


def test_nuclei_findings_do_not_merge_adjacent_kb_cves():
    finding = make_finding(
        source_tool="nuclei",
        title="Apache Path Traversal and File Disclosure",
        description="Apache HTTP Server 2.4.49 path traversal and file disclosure.",
        raw_evidence=(
            "template-id: cves/2021/CVE-2021-41773\n"
            "classification.cve-id: CVE-2021-41773"
        ),
        cve_ids=["CVE-2021-41773"],
        priority="critical",
    )

    enriched = match_finding(finding)

    assert enriched.cve_ids == ["CVE-2021-41773"]
    assert "CVE-2021-42013" not in enriched.cve_ids
    assert enriched.remediation
