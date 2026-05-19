from pathlib import Path

from vulnmind.parsers import detect_and_parse

FIXTURES = Path(__file__).resolve().parents[1]


def test_metasploit_fixture_parses_signal_and_tracks_active_module():
    findings = detect_and_parse(FIXTURES / "sample_metasploit.txt")

    assert len(findings) == 5
    assert not any("Scanned 1 of 1 hosts" in finding.title for finding in findings)
    assert any(f.cve_ids == ["CVE-2017-0144"] for f in findings)
    assert any(
        f.priority == "critical"
        and f.metasploit_modules == ["windows/smb/ms17_010_eternalblue"]
        for f in findings
    )
    assert any(
        f.port == 22
        and f.service == "ssh"
        and f.priority == "high"
        and f.metasploit_modules == ["scanner/ssh/ssh_login"]
        for f in findings
    )
