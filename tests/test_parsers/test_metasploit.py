from pathlib import Path

from vulnmind.parsers import detect_and_parse
from vulnmind.parsers.metasploit import MetasploitParser

FIXTURES = Path(__file__).resolve().parents[1]


def test_metasploit_fixture_parses_signal_and_tracks_active_module():
    findings = detect_and_parse(FIXTURES / "sample_metasploit.txt")

    assert len(findings) == 5
    assert not any("Scanned 1 of 1 hosts" in finding.title for finding in findings)
    assert any(f.cve_ids == ["CVE-2017-0144"] for f in findings)
    assert any(
        f.priority == "critical"
        and f.confidence == "confirmed"
        and f.metasploit_modules == [
            "exploit/windows/smb/ms17_010_eternalblue"
        ]
        for f in findings
    )
    assert any(
        f.port == 22
        and f.service == "ssh"
        and f.priority == "high"
        and f.confidence == "confirmed"
        and f.metasploit_modules == ["auxiliary/scanner/ssh/ssh_login"]
        for f in findings
    )


def test_metasploit_likely_vulnerable_is_reported_not_confirmed():
    findings = detect_and_parse(FIXTURES / "sample_metasploit.txt")
    finding = next(f for f in findings if "likely VULNERABLE" in f.title)

    assert finding.confidence == "scanner-reported"


def test_metasploit_skips_explicit_negative_and_zero_result_lines():
    content = """Metasploit Framework
msf6 > use auxiliary/scanner/ssh/ssh_login
[-] 192.0.2.10:22 - Target is not vulnerable
[+] 192.0.2.10:22 - 0 credentials obtained
[+] 192.0.2.10:22 - No credentials obtained
"""

    findings = MetasploitParser().parse(
        FIXTURES / "negative_metasploit.txt",
        content,
    )

    assert findings == []


def test_metasploit_context_preserves_full_module_path_and_deduplicates_cves():
    content = """Metasploit Framework
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) > run
[+] 192.0.2.10:445 - VULNERABLE CVE-2017-0144 CVE-2017-0144
"""

    findings = MetasploitParser().parse(
        FIXTURES / "module_context.txt",
        content,
    )

    assert len(findings) == 1
    assert findings[0].metasploit_modules == [
        "exploit/windows/smb/ms17_010_eternalblue"
    ]
    assert findings[0].cve_ids == ["CVE-2017-0144"]


def test_metasploit_parses_bracketed_and_bare_ipv6_targets():
    content = """Metasploit Framework
msf6 > use auxiliary/scanner/smb/smb_ms17_010
[+] [2001:0db8::1]:445 - Host is VULNERABLE to CVE-2017-0144
[+] 2001:db8::2 - Login Successful
"""

    findings = MetasploitParser().parse(FIXTURES / "ipv6_metasploit.txt", content)

    assert [(finding.host, finding.port) for finding in findings] == [
        ("2001:db8::1", 445),
        ("2001:db8::2", None),
    ]
