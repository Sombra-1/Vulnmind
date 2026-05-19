import json
import time

import requests

from vulnmind import nvd
from vulnmind.parsers.base import Finding


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


def make_finding(**overrides):
    values = {
        "id": "nvd-test",
        "source_tool": "pytest",
        "source_file": "inline",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "host": "192.0.2.10",
        "port": 80,
        "protocol": "tcp",
        "service": "http",
        "title": "CVE finding",
        "description": "Parser evidence",
        "raw_evidence": "CVE-2024-0001",
        "cve_ids": ["CVE-2024-0001"],
    }
    values.update(overrides)
    return Finding(**values)


def nvd_payload(cve_id="CVE-2024-0001", score=9.8):
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "published": "2024-01-01T00:00:00.000",
                    "descriptions": [
                        {"lang": "es", "value": "Descripcion"},
                        {"lang": "en", "value": "English description"},
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": score,
                                    "baseSeverity": "CRITICAL",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                }
                            }
                        ]
                    },
                    "references": [
                        {"url": "https://example.test/one"},
                        {"url": "https://example.test/two"},
                        {"url": "https://example.test/three"},
                        {"url": "https://example.test/four"},
                    ],
                }
            }
        ]
    }


def test_cache_round_trip_uses_configured_cache_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(nvd, "NVD_CACHE_DIR", tmp_path)
    payload = {"cve_id": "CVE-2024-0001", "found": True}

    nvd._write_cache("CVE-2024-0001", payload)

    assert nvd._read_cache("CVE-2024-0001") == payload
    cached_file = tmp_path / "CVE-2024-0001.json"
    assert json.loads(cached_file.read_text())["payload"] == payload


def test_stale_cache_is_ignored(tmp_path, monkeypatch):
    monkeypatch.setattr(nvd, "NVD_CACHE_DIR", tmp_path)
    path = tmp_path / "CVE-2024-0001.json"
    path.write_text(json.dumps({"_cached_at": 0, "payload": {"found": True}}))

    assert nvd._read_cache("CVE-2024-0001") is None


def test_fetch_cve_normalizes_nvd_response(monkeypatch):
    captured = {}

    def fake_get(url, params, headers, timeout):
        captured.update({"url": url, "params": params, "headers": headers, "timeout": timeout})
        return FakeResponse(payload=nvd_payload())

    monkeypatch.setattr(nvd.requests, "get", fake_get)

    result = nvd._fetch_cve("CVE-2024-0001")

    assert captured["url"] == nvd.NVD_API_URL
    assert captured["params"] == {"cveId": "CVE-2024-0001"}
    assert captured["headers"]["Accept"] == "application/json"
    assert "vulnmind/" in captured["headers"]["User-Agent"]
    assert captured["timeout"] == nvd.REQUEST_TIMEOUT
    assert result["found"] is True
    assert result["description"] == "English description"
    assert result["cvss_score"] == 9.8
    assert result["cvss_severity"] == "critical"
    assert result["references"] == [
        "https://example.test/one",
        "https://example.test/two",
        "https://example.test/three",
    ]


def test_fetch_cve_retries_transient_statuses(monkeypatch):
    responses = [FakeResponse(status_code=429), FakeResponse(payload=nvd_payload(score=7.5))]
    sleeps = []

    monkeypatch.setattr(nvd.requests, "get", lambda *args, **kwargs: responses.pop(0))
    monkeypatch.setattr(nvd.time, "sleep", lambda delay: sleeps.append(delay))

    result = nvd._fetch_cve("CVE-2024-0001")

    assert result["cvss_score"] == 7.5
    assert sleeps == [5.0]


def test_fetch_cve_silently_returns_none_on_request_failure(monkeypatch):
    def fail(*args, **kwargs):
        raise requests.Timeout()

    monkeypatch.setattr(nvd.requests, "get", fail)
    monkeypatch.setattr(nvd.time, "sleep", lambda delay: None)

    assert nvd._fetch_cve("CVE-2024-0001", max_retries=1) is None


def test_enrich_with_nvd_lifts_priority_using_highest_cvss(monkeypatch):
    finding = make_finding(cve_ids=["CVE-2024-LOW", "CVE-2024-CRIT"], priority="medium")
    data = {
        "CVE-2024-LOW": {"found": True, "cvss_score": 4.3},
        "CVE-2024-CRIT": {"found": True, "cvss_score": 9.1},
    }

    monkeypatch.setattr(nvd, "_read_cache", lambda cve_id: data[cve_id])

    enriched = nvd.enrich_with_nvd([finding])

    assert enriched[0].cvss_score == 9.1
    assert enriched[0].priority == "critical"
    assert "Elevated by NVD" in enriched[0].priority_reason


def test_enrich_with_nvd_rate_limits_only_network_fetches(monkeypatch):
    finding = make_finding(cve_ids=["CVE-2024-0001", "CVE-2024-0002"])
    now = [100.0, 101.0, 101.0, 107.5]
    sleeps = []
    fetched = []

    monkeypatch.setattr(nvd, "_read_cache", lambda cve_id: None)
    monkeypatch.setattr(nvd, "_write_cache", lambda cve_id, data: None)
    monkeypatch.setattr(time, "time", lambda: now.pop(0))

    def fake_sleep(delay):
        sleeps.append(delay)

    def fake_fetch(cve_id):
        fetched.append(cve_id)
        return {"found": True, "cvss_score": 5.0}

    monkeypatch.setattr(nvd.time, "sleep", fake_sleep)
    monkeypatch.setattr(nvd, "_fetch_cve", fake_fetch)

    nvd.enrich_with_nvd([finding])

    assert fetched == ["CVE-2024-0001", "CVE-2024-0002"]
    assert sleeps == [6.5]
