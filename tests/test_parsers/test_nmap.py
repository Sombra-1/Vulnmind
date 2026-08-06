from pathlib import Path

from vulnmind.matcher import match_findings
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
    assert by_port(findings, 80)[0].confidence == "scanner-reported"
    assert "version: 7.2p2 Ubuntu 4ubuntu2.8" in by_port(findings, 22)[0].raw_evidence
    assert by_port(findings, 3306)[0].service == "mysql"


def test_nmap_text_fixture_parses_script_and_open_port_findings():
    findings = detect_and_parse(FIXTURES / "sample_nmap.txt")

    assert len(findings) == 4
    shellshock = next(f for f in findings if f.title.startswith("http-shellshock"))
    assert shellshock.host == "192.168.1.20"
    assert shellshock.port == 80
    assert shellshock.cve_ids == ["CVE-2014-6271"]
    assert shellshock.confidence == "scanner-reported"
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


def test_nmap_xml_does_not_promote_explicit_not_vulnerable_script():
    content = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.0.2.30" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds"/>
        <script id="smb-vuln-ms17-010" output="NOT VULNERABLE: CVE-2017-0144"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

    findings = NmapParser().parse(FIXTURES / "negative.xml", content)

    assert len(findings) == 1
    assert findings[0].cve_ids == []
    assert findings[0].title.startswith("Open port 445")


def test_nmap_text_does_not_promote_explicit_not_vulnerable_script():
    content = """Nmap scan report for 192.0.2.30
Host is up.
PORT    STATE SERVICE VERSION
445/tcp open  microsoft-ds
| smb-vuln-ms17-010:
|   NOT VULNERABLE
|_  CVE-2017-0144

Nmap done: 1 IP address (1 host up) scanned
"""

    findings = NmapParser().parse(FIXTURES / "negative.txt", content)

    assert len(findings) == 1
    assert findings[0].cve_ids == []
    assert findings[0].title.startswith("Open port 445")


def test_nmap_xml_no_vulnerabilities_found_is_not_promoted_by_matcher():
    content = """<?xml version="1.0"?>
<nmaprun><host>
  <address addr="192.0.2.31" addrtype="ipv4"/>
  <ports><port protocol="tcp" portid="80">
    <state state="open"/>
    <service name="http" product="Apache httpd" version="2.4.49"/>
    <script id="http-vuln-cve2021-41773" output="No vulnerabilities found: CVE-2021-41773"/>
  </port></ports>
</host></nmaprun>
"""

    findings = match_findings(
        NmapParser().parse(FIXTURES / "no_vulns.xml", content)
    )

    assert len(findings) == 1
    assert findings[0].cve_ids == []
    assert findings[0].priority is None
    assert "kb-vulnerability-inference: blocked" in findings[0].raw_evidence


def test_nmap_text_zero_vulnerabilities_detected_is_not_promoted_by_matcher():
    content = """Nmap scan report for 192.0.2.32
Host is up.
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.49
| http-vuln-cve2021-41773:
|_ 0 known vulnerabilities detected: CVE-2021-41773

Nmap done: 1 IP address (1 host up) scanned
"""

    findings = match_findings(
        NmapParser().parse(FIXTURES / "no_vulns.txt", content)
    )

    assert all(finding.cve_ids == [] for finding in findings)
    assert all(finding.priority is None for finding in findings)
    assert any(
        "kb-vulnerability-inference: blocked" in finding.raw_evidence
        for finding in findings
    )


def test_nmap_script_error_is_not_reported_as_scanner_confirmed():
    content = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.0.2.40" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.49"/>
        <script id="http-vuln-cve2021-41773" output="ERROR: Script execution failed; vulnerability status could not be determined"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

    findings = NmapParser().parse(FIXTURES / "inconclusive.xml", content)

    assert len(findings) == 1
    assert findings[0].title.startswith("Open port 80")
    assert findings[0].cve_ids == []
    assert findings[0].confidence == "weak"


def test_explicit_negative_nse_result_cannot_be_reversed_by_matcher():
    content = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.0.2.41" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.49"/>
        <script id="http-vuln-cve2021-41773" output="NOT VULNERABLE: CVE-2021-41773"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

    parsed = NmapParser().parse(FIXTURES / "negative_apache.xml", content)
    findings = match_findings(parsed)

    assert len(findings) == 1
    assert findings[0].cve_ids == []
    assert findings[0].priority is None
    assert findings[0].confidence == "weak"
    assert "NOT VULNERABLE" in findings[0].raw_evidence
    assert "kb-vulnerability-inference: blocked" in findings[0].raw_evidence


def test_inconclusive_nse_result_cannot_be_reversed_by_matcher():
    content = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.0.2.42" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.49"/>
        <script id="http-vuln-cve2021-41773" output="ERROR: could not determine whether target is VULNERABLE"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

    parsed = NmapParser().parse(FIXTURES / "inconclusive_apache.xml", content)
    findings = match_findings(parsed)

    assert len(findings) == 1
    assert findings[0].cve_ids == []
    assert findings[0].priority is None
    assert findings[0].confidence == "weak"


def test_negative_nse_result_blocks_kb_inference_with_positive_sibling():
    content = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.0.2.43" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.49"/>
        <script id="http-vuln-cve2021-41773" output="NOT VULNERABLE: CVE-2021-41773"/>
        <script id="http-vuln-other" output="VULNERABLE: unrelated application check"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

    parsed = NmapParser().parse(FIXTURES / "mixed_scripts.xml", content)
    findings = match_findings(parsed)

    assert len(findings) == 1
    assert findings[0].title.startswith("http-vuln-other")
    assert findings[0].cve_ids == []
    assert findings[0].priority == "medium"
    assert findings[0].confidence == "scanner-reported"
    assert "NOT VULNERABLE: CVE-2021-41773" in findings[0].raw_evidence
    assert "kb-vulnerability-inference: blocked" in findings[0].raw_evidence


def test_dedicated_negative_filters_same_cve_from_positive_sibling_only():
    content = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.0.2.44" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.49"/>
        <script id="http-vuln-cve2021-41773" output="NOT VULNERABLE: CVE-2021-41773"/>
        <script id="vulners" output="CVE-2021-41773 9.8\nCVE-2022-9999 7.5"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

    parsed = NmapParser().parse(FIXTURES / "mixed_cves.xml", content)
    findings = match_findings(parsed)

    assert len(findings) == 1
    assert findings[0].cve_ids == ["CVE-2022-9999"]
    assert "CVE-2021-41773" not in findings[0].description
    assert "CVE-2021-41773" in findings[0].raw_evidence


def test_load_files_deduplicates_matching_xml_and_text_open_ports(tmp_path):
    xml_path = tmp_path / "scan.xml"
    text_path = tmp_path / "scan.nmap"
    xml_path.write_text("""<?xml version="1.0"?>
<nmaprun><host>
  <address addr="192.0.2.50" addrtype="ipv4"/>
  <hostnames><hostname name="target.example"/></hostnames>
  <ports><port protocol="tcp" portid="8080">
    <state state="open"/>
    <service name="http" product="Apache httpd" version="2.4.58"/>
  </port></ports>
</host></nmaprun>
""")
    text_path.write_text("""Nmap scan report for target.example (192.0.2.50)
Host is up.
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache httpd 2.4.58

Nmap done: 1 IP address (1 host up) scanned
""")

    findings = load_files([xml_path, text_path])

    assert len(findings) == 1
    assert findings[0].host == "target.example"
    assert findings[0].port == 8080


def test_ipv6_xml_and_text_variants_share_a_finding_id(tmp_path):
    xml_path = tmp_path / "scan.xml"
    text_path = tmp_path / "scan.nmap"
    xml_path.write_text("""<?xml version="1.0"?>
<nmaprun><host>
  <address addr="2001:0db8::1" addrtype="ipv6"/>
  <ports><port protocol="tcp" portid="22">
    <state state="open"/>
    <service name="ssh"/>
  </port></ports>
</host></nmaprun>
""")
    text_path.write_text("""Nmap scan report for 2001:db8::1
Host is up.
PORT   STATE SERVICE
22/tcp open  ssh
""")

    findings = load_files([xml_path, text_path])

    assert len(findings) == 1
    assert findings[0].port == 22
