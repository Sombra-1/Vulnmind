from vulnmind.parsers.base import Finding
from vulnmind.report import generate_pdf


def test_pdf_renders_confidence_and_exploit_intelligence(tmp_path):
    finding = Finding(
        id="pdf-test",
        source_tool="pytest",
        source_file="inline",
        timestamp="2026-01-01T00:00:00+00:00",
        host="192.0.2.10",
        port=443,
        protocol="tcp",
        service="http",
        title="Associated CVE <test>",
        description="Evidence & context",
        raw_evidence="scanner output > result",
        cve_ids=["CVE-2024-0001"],
        priority="high",
        confidence="scanner-reported",
        actively_exploited=True,
        exploit_available=True,
        metasploit_available=True,
        exploit_confidence="cisa-kev",
        exploit_references=[
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "https://www.exploit-db.com/exploits/123",
            "metasploit:exploit/test/module",
        ],
        metasploit_modules=["exploit/test/module"],
    )
    output = tmp_path / "report.pdf"

    generate_pdf([finding], str(output))

    assert output.read_bytes().startswith(b"%PDF")
    assert output.stat().st_size > 1000
