from pathlib import Path

from vulnmind.matcher import _extract_product_version, match_findings
from vulnmind.parsers import load_files


def test_nmap_versions_drive_matching_without_unrelated_cves():
    findings = load_files([Path(__file__).with_name("sample_nmap.xml")])
    versions = {finding.port: _extract_product_version(finding) for finding in findings}
    matched = {finding.port: finding for finding in match_findings(findings)}

    assert versions[21] == ("vsftpd", "2.3.4")
    assert versions[80] == ("apache", "2.4.49")
    assert versions[445] == ("", "")
    assert matched[21].cve_ids == ["CVE-2011-2523"]
    assert matched[80].cve_ids == ["CVE-2021-41773", "CVE-2021-42013"]
    assert "CVE-2012-1182" not in matched[445].cve_ids
