from vulnmind.enrichers.intelligence import enrich_with_exploit_intelligence
from vulnmind.parsers.base import Finding


def make_finding(**overrides):
    values = {
        "id": "intel-test",
        "source_tool": "pytest",
        "source_file": "inline",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "host": "192.0.2.10",
        "port": 80,
        "protocol": "tcp",
        "service": "http",
        "title": "CVE finding",
        "description": "Scanner evidence",
        "raw_evidence": "CVE-2024-0001",
        "cve_ids": ["CVE-2024-0001"],
        "priority": "medium",
        "confidence": "scanner-reported",
    }
    values.update(overrides)
    return Finding(**values)


def test_batches_cves_and_applies_all_signals_without_priority_lift():
    calls = []

    def fake_kev(cves, allow_network):
        calls.append(("kev", cves, allow_network))
        return {
            "CVE-2024-0001": {
                "source_url": "https://www.cisa.gov/kev",
                "references": ["https://www.cisa.gov/kev"],
            }
        }

    def fake_exploitdb(cves, allow_network):
        calls.append(("exploitdb", cves, allow_network))
        return {
            "CVE-2024-0001": [
                {"id": "123", "url": "https://www.exploit-db.com/exploits/123"}
            ]
        }

    finding = make_finding(metasploit_modules=["exploit/test/module"])
    result = enrich_with_exploit_intelligence(
        [finding, make_finding(id="duplicate-cve")],
        allow_network=True,
        kev_lookup=fake_kev,
        exploitdb_lookup=fake_exploitdb,
    )

    assert calls == [
        ("kev", ["CVE-2024-0001"], True),
        ("exploitdb", ["CVE-2024-0001"], True),
    ]
    assert result[0].priority == "medium"
    assert result[0].actively_exploited is True
    assert result[0].exploit_available is True
    assert result[0].metasploit_available is True
    assert result[0].exploit_confidence == "cisa-kev"
    assert result[0].exploit_references == [
        "https://www.cisa.gov/kev",
        "https://www.exploit-db.com/exploits/123",
        "metasploit:exploit/test/module",
    ]


def test_offline_no_data_keeps_stable_schema_types():
    finding = make_finding(cve_ids=[], metasploit_modules=[])

    result = enrich_with_exploit_intelligence(
        [finding],
        kev_lookup=lambda *args, **kwargs: {},
        exploitdb_lookup=lambda *args, **kwargs: {},
    )[0]

    assert result.actively_exploited is False
    assert result.exploit_available is False
    assert result.metasploit_available is False
    assert result.exploit_confidence == "none"
    assert result.exploit_references == []


def test_metasploit_only_signal_is_distinct_from_public_exploit():
    finding = make_finding(cve_ids=[], metasploit_modules=["auxiliary/test/module"])

    result = enrich_with_exploit_intelligence([finding])[0]

    assert result.actively_exploited is False
    assert result.exploit_available is False
    assert result.metasploit_available is True
    assert result.exploit_confidence == "metasploit-module"


def test_lookup_failures_are_silent_and_references_are_bounded():
    finding = make_finding(
        metasploit_modules=[f"exploit/test/module_{i}" for i in range(10)]
    )

    def fail(*args, **kwargs):
        raise RuntimeError("offline")

    result = enrich_with_exploit_intelligence(
        [finding],
        kev_lookup=fail,
        exploitdb_lookup=fail,
    )[0]

    assert result.exploit_confidence == "metasploit-module"
    assert len(result.exploit_references) == 5


def test_invalid_metasploit_paths_do_not_create_verified_signal():
    finding = make_finding(
        cve_ids=[],
        metasploit_modules=["exploits/test/module", "module/without/type", ""],
    )

    result = enrich_with_exploit_intelligence([finding])[0]

    assert result.metasploit_modules == []
    assert result.metasploit_available is False
    assert result.exploit_confidence == "none"
