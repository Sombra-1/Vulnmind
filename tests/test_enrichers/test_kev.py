import json

import pytest
import requests

from vulnmind.enrichers import kev


class FakeResponse:
    def __init__(self, payload, status_code=200, headers=None):
        self._payload = payload
        self.content = json.dumps(payload).encode()
        self.status_code = status_code
        self.headers = headers or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def iter_content(self, chunk_size):
        for offset in range(0, len(self.content), chunk_size):
            yield self.content[offset:offset + chunk_size]


def kev_payload(cve_id="CVE-2024-0001", **overrides):
    record = {
        "cveID": cve_id,
        "vendorProject": "Example Vendor",
        "product": "Example Product",
        "vulnerabilityName": "Example vulnerability",
        "dateAdded": "2026-01-01",
        "dueDate": "2026-01-22",
        "requiredAction": "Apply the vendor update.",
        "knownRansomwareCampaignUse": "Known",
        "notes": "Official catalog note",
    }
    record.update(overrides)
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.01.01",
        "vulnerabilities": [record],
    }


def write_cache(path, payload, cached_at):
    path.write_text(json.dumps({"_cached_at": cached_at, "payload": payload}))


def test_parse_catalog_requires_exact_cves_and_normalizes_fields():
    payload = kev_payload(
        " cve-2024-12345 ",
        vulnerabilityName="  Example\x00   vulnerability  ",
    )
    payload["vulnerabilities"].extend(
        [
            None,
            {"cveID": "not-a-cve"},
            {"cveID": "CVE-2024-12345", "product": "duplicate"},
        ]
    )

    result = kev.parse_catalog(payload)

    assert list(result) == ["CVE-2024-12345"]
    record = result["CVE-2024-12345"]
    assert record["actively_exploited"] is True
    assert record["known_ransomware_campaign_use"] is True
    assert record["vulnerability_name"] == "Example vulnerability"
    assert record["product"] == "Example Product"
    assert record["references"] == [kev.CISA_KEV_CATALOG_URL]
    assert len(record["references"]) <= kev.MAX_REFERENCES


def test_fresh_cache_is_used_without_network(tmp_path):
    path = tmp_path / "cisa_kev.json"
    write_cache(path, kev_payload(), cached_at=10_000)

    def unexpected_request(*args, **kwargs):
        raise AssertionError("fresh cache must avoid the network")

    result = kev.lookup_cves(
        ["cve-2024-0001", "CVE-2024-9999"],
        cache_path=path,
        http_get=unexpected_request,
        now=lambda: 10_001,
    )

    assert list(result) == ["CVE-2024-0001"]


def test_stale_cache_falls_back_silently_when_refresh_fails(tmp_path):
    path = tmp_path / "cisa_kev.json"
    write_cache(path, kev_payload(), cached_at=1)
    warnings = []

    def fail(*args, **kwargs):
        raise requests.Timeout("offline")

    result = kev.load_catalog(
        allow_network=True,
        cache_path=path,
        http_get=fail,
        now=lambda: kev.CACHE_TTL_SECONDS + 10,
        warn=warnings.append,
    )

    assert "CVE-2024-0001" in result
    assert len(warnings) == 1
    assert "Could not refresh" in warnings[0]


def test_stale_cache_is_kept_when_download_is_malformed(tmp_path):
    path = tmp_path / "cisa_kev.json"
    stale_payload = kev_payload("CVE-2023-1111")
    write_cache(path, stale_payload, cached_at=1)

    result = kev.load_catalog(
        allow_network=True,
        cache_path=path,
        http_get=lambda *args, **kwargs: FakeResponse({"unexpected": []}),
        now=lambda: kev.CACHE_TTL_SECONDS + 10,
    )

    assert list(result) == ["CVE-2023-1111"]
    assert json.loads(path.read_text())["payload"] == stale_payload


def test_successful_refresh_is_normalized_and_cached(tmp_path):
    path = tmp_path / "nested" / "cisa_kev.json"
    captured = {}

    def get(url, headers, timeout, stream):
        captured.update(url=url, headers=headers, timeout=timeout, stream=stream)
        return FakeResponse(kev_payload("CVE-2025-2222"))

    result = kev.load_catalog(
        allow_network=True,
        cache_path=path,
        http_get=get,
        now=lambda: 1234.0,
    )

    assert list(result) == ["CVE-2025-2222"]
    assert captured["url"] == kev.CISA_KEV_URL
    assert captured["timeout"] == kev.REQUEST_TIMEOUT
    assert captured["stream"] is True
    assert captured["headers"]["Accept"] == "application/json"
    cached = json.loads(path.read_text())
    assert cached["_cached_at"] == 1234.0
    assert cached["payload"]["vulnerabilities"][0]["cveID"] == "CVE-2025-2222"


def test_offline_mode_accepts_raw_manually_seeded_catalog(tmp_path):
    path = tmp_path / "cisa_kev.json"
    path.write_text(json.dumps(kev_payload("CVE-2022-3333")))

    result = kev.lookup_cve(
        "CVE-2022-3333",
        allow_network=False,
        cache_path=path,
        now=lambda: 10**12,
    )

    assert result["cve_id"] == "CVE-2022-3333"


def test_invalid_inputs_do_not_trigger_network(tmp_path):
    def unexpected_request(*args, **kwargs):
        raise AssertionError("invalid input must avoid the network")

    assert kev.lookup_cves(
        [None, "CVE-24-1", "CVE-2024-12"],
        cache_path=tmp_path / "missing.json",
        http_get=unexpected_request,
    ) == {}
    assert kev.lookup_cve("not-a-cve", http_get=unexpected_request) is None


def test_network_is_opt_in_and_future_cache_timestamp_is_stale(tmp_path):
    missing = tmp_path / "missing.json"

    def unexpected_request(*args, **kwargs):
        raise AssertionError("network must be opt-in")

    assert kev.load_catalog(cache_path=missing, http_get=unexpected_request) == {}

    path = tmp_path / "future.json"
    write_cache(path, kev_payload("CVE-2024-1111"), cached_at=200)
    calls = []

    def refresh(*args, **kwargs):
        calls.append(True)
        return FakeResponse(kev_payload("CVE-2024-2222"))

    result = kev.load_catalog(
        allow_network=True,
        cache_path=path,
        http_get=refresh,
        now=lambda: 100,
    )

    assert calls == [True]
    assert list(result) == ["CVE-2024-2222"]


@pytest.mark.parametrize(
    "cached_at",
    [True, float("nan"), float("inf"), 10**400],
)
def test_malformed_cache_timestamps_are_stale_without_crashing(
    tmp_path,
    cached_at,
):
    path = tmp_path / "malformed_timestamp.json"
    write_cache(path, kev_payload(), cached_at=cached_at)

    catalog, is_fresh = kev._read_cache(path, 100.0)

    assert "CVE-2024-0001" in catalog
    assert is_fresh is False
