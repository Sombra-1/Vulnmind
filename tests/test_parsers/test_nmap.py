from pathlib import Path

from vulnmind.parsers import detect_and_parse, load_files
from vulnmind.parsers.nmap import NmapParser

FIXTURES = Path(__file__).resolve().parents[1]


def by_port(findings, port):
    return [finding for finding in findings if finding.port == port]


def test_nmap_xml_fixture_parses_open_ports_and_script_cves():
    findings = detect_and_parse(FIXTURES / "sample_nmap.xml")

    assert len(findings) == 5
    assert {finding.port for finding in findings} == {21, 22, 80, 445, 3306}
    assert by_port(findings, 21)[0].cve_ids == ["CVE-2011-2523"]
    assert by_port(findings, 80)[0].cve_ids == ["CVE-2021-41773"]
    assert by_port(findings, 445)[0].cve_ids == ["CVE-2017-0144"]
    assert "version: 7.2p2 Ubuntu 4ubuntu2.8" in by_port(findings, 22)[0].raw_evidence
    assert by_port(findings, 3306)[0].service == "mysql"


def test_nmap_text_fixture_parses_script_and_open_port_findings():
    findings = detect_and_parse(FIXTURES / "sample_nmap.txt")

    assert len(findings) == 4
    shellshock = next(f for f in findings if f.title.startswith("http-shellshock"))
    assert shellshock.host == "192.168.1.20"
    assert shellshock.port == 80
    assert shellshock.cve_ids == ["CVE-2014-6271"]
    assert "Apache httpd 2.4.41" in shellshock.raw_evidence
    assert {finding.port for finding in findings if not finding.cve_ids} == {22, 80, 8080}


def test_nmap_xml_ignores_closed_and_filtered_ports():
    content = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.0.2.20" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
      <port protocol="tcp" portid="80"><state state="filtered"/><service name="http"/></port>
    </ports>
  </host>
</nmaprun>
"""

    findings = NmapParser().parse(FIXTURES / "inline.xml", content)

    assert findings == []


def test_load_files_deduplicates_repeated_inputs():
    findings = load_files([FIXTURES / "sample_nmap.xml", FIXTURES / "sample_nmap.xml"])

    assert len(findings) == 5
