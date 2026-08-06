from pathlib import Path

from vulnmind.parsers import detect_and_parse

FIXTURES = Path(__file__).resolve().parents[1]


def test_nikto_fixture_parses_findings_and_cves():
    findings = detect_and_parse(FIXTURES / "sample_nikto.txt")

    assert len(findings) == 8
    assert {finding.host for finding in findings} == {"192.168.1.10"}
    assert {finding.port for finding in findings} == {80}
    assert {finding.service for finding in findings} == {"http"}
    assert any(f.title.startswith("OSVDB-3092") for f in findings)
    assert any(f.cve_ids == ["CVE-2021-41773"] for f in findings)
    assert any(f.cve_ids == ["CVE-2014-6271"] for f in findings)
    assert not any("requests:" in f.title for f in findings)
