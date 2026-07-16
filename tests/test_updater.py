import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

from vulnmind import updater


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


@pytest.fixture(autouse=True)
def reset_background_state(monkeypatch, tmp_path):
    monkeypatch.setattr(updater, "_thread", None)
    monkeypatch.setattr(updater, "_result", None)
    monkeypatch.setattr(updater, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(updater, "CACHE_FILE", tmp_path / "update_check.json")


def test_version_comparison_handles_semver_prereleases():
    assert updater._is_newer("v0.6.0", "0.5.0") is True
    assert updater._is_newer("0.6.0-beta.2", "0.6.0-beta.1") is True
    assert updater._is_newer("0.6.0", "0.6.0-beta.2") is True
    assert updater._is_newer("0.6.0-beta.2", "0.6.0") is False
    assert updater._is_newer("0.6.0+build.2", "0.6.0+build.1") is False
    assert updater._is_newer("not-a-release", "0.5.0") is False
    assert updater._parse_version(f"{'9' * 5000}.0.0") is None


def test_cache_recomputes_newer_for_running_version(tmp_path, monkeypatch):
    cache_file = tmp_path / "update_check.json"
    cache_file.write_text(json.dumps({
        "latest": "v0.6.0",
        "newer": True,
        "checked_at": 990.0,
    }))
    monkeypatch.setattr(updater, "CACHE_FILE", cache_file)
    monkeypatch.setattr(updater, "__version__", "0.6.0")
    monkeypatch.setattr(updater.time, "time", lambda: 1000.0)

    result = updater._read_cache()

    assert result == {
        "latest": "v0.6.0",
        "newer": False,
        "checked_at": 990.0,
    }


@pytest.mark.parametrize(
    "payload",
    [
        {"latest": "v0.6.0", "checked_at": -100000},
        {"latest": "v0.6.0", "checked_at": "recent"},
        {"latest": "v0.6.0", "checked_at": float("nan")},
        {"latest": "v0.6.0", "checked_at": float("inf")},
        {"latest": "v0.6.0", "checked_at": 10**400},
        {"latest": "malformed", "checked_at": 999.0},
        ["not", "an", "object"],
    ],
)
def test_invalid_or_stale_cache_is_ignored(tmp_path, monkeypatch, payload):
    cache_file = tmp_path / "update_check.json"
    cache_file.write_text(json.dumps(payload))
    monkeypatch.setattr(updater, "CACHE_FILE", cache_file)
    monkeypatch.setattr(updater.time, "time", lambda: 1000.0)

    assert updater._read_cache() is None


def test_release_fetch_uses_short_timeout_user_agent_and_cache(tmp_path, monkeypatch):
    captured = {}

    def fake_get(url, headers, timeout):
        captured.update({"url": url, "headers": headers, "timeout": timeout})
        return FakeResponse({"tag_name": "v0.6.0"})

    monkeypatch.setattr(updater.requests, "get", fake_get)
    monkeypatch.setattr(updater, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(updater, "CACHE_FILE", tmp_path / "update_check.json")
    monkeypatch.setattr(updater, "__version__", "0.5.0")
    monkeypatch.setattr(updater.time, "time", lambda: 1234.0)

    result = updater.check_for_update(force=True)

    assert result == {
        "latest": "v0.6.0",
        "newer": True,
        "checked_at": 1234.0,
    }
    assert captured["url"] == updater.RELEASES_API
    assert captured["timeout"] == updater.CHECK_TIMEOUT
    assert captured["headers"]["Accept"] == "application/vnd.github+json"
    assert captured["headers"]["User-Agent"] == "vulnmind/0.5.0"
    assert json.loads(updater.CACHE_FILE.read_text()) == result


def test_network_failure_is_silent(monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise requests.Timeout()

    monkeypatch.setattr(updater.requests, "get", fail)

    assert updater.check_for_update(force=True) is None
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert json.loads(updater.CACHE_FILE.read_text())["failed"] is True


def test_get_notice_waits_a_bounded_time_for_active_thread(monkeypatch):
    class ActiveThread:
        alive = True

        def is_alive(self):
            return self.alive

        def join(self, timeout):
            assert timeout == updater.NOTICE_WAIT_SECONDS
            self.alive = False

    monkeypatch.setattr(updater, "_thread", ActiveThread())
    monkeypatch.setattr(
        updater,
        "_result",
        {"latest": "v0.6.0", "newer": True, "checked_at": 1.0},
    )

    assert "v0.6.0" in updater.get_notice()


def test_get_notice_backs_off_when_thread_exceeds_grace_period(monkeypatch):
    class StuckThread:
        def is_alive(self):
            return True

        def join(self, timeout):
            assert timeout == updater.NOTICE_WAIT_SECONDS

    monkeypatch.setattr(updater, "_thread", StuckThread())

    assert updater.get_notice() is None
    cached = json.loads(updater.CACHE_FILE.read_text())
    assert cached["failed"] is True


def test_get_notice_is_returned_once_after_check_finishes(monkeypatch):
    class FinishedThread:
        def is_alive(self):
            return False

    monkeypatch.setattr(updater, "_thread", FinishedThread())
    monkeypatch.setattr(
        updater,
        "_result",
        {"latest": "v0.6.0", "newer": True, "checked_at": 1.0},
    )

    notice = updater.get_notice()

    assert "v0.6.0" in notice
    assert "vulnmind update" in notice
    assert updater.get_notice() is None


def test_start_check_surfaces_fresh_cache_without_starting_thread(monkeypatch):
    monkeypatch.setattr(
        updater,
        "_read_cache",
        lambda: {"latest": "v0.6.0", "newer": True, "checked_at": 1.0},
    )
    monkeypatch.setattr(
        updater.threading,
        "Thread",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("fresh cache must not start a network thread")
        ),
    )

    updater.start_check()

    assert "v0.6.0" in updater.get_notice()


def test_start_check_records_backoff_before_daemon_runs(monkeypatch):
    class DeferredThread:
        def __init__(self, target, daemon):
            assert daemon is True

        def start(self):
            return None

        def is_alive(self):
            return False

    monkeypatch.setattr(updater, "_read_cache", lambda: None)
    monkeypatch.setattr(updater.threading, "Thread", DeferredThread)

    updater.start_check()

    cached = json.loads(updater.CACHE_FILE.read_text())
    assert cached["failed"] is True


def test_start_check_silences_thread_start_failure(monkeypatch):
    class BrokenThread:
        def __init__(self, target, daemon):
            pass

        def start(self):
            raise RuntimeError("thread limit")

    monkeypatch.setattr(updater, "_read_cache", lambda: None)
    monkeypatch.setattr(updater.threading, "Thread", BrokenThread)

    updater.start_check()

    assert updater._thread is None


def test_fresh_failure_cache_prevents_repeated_automatic_request(monkeypatch):
    updater.CACHE_FILE.write_text(json.dumps({
        "failed": True,
        "checked_at": 990.0,
    }))
    monkeypatch.setattr(updater.time, "time", lambda: 1000.0)
    monkeypatch.setattr(
        updater.requests,
        "get",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("fresh failure state must back off")
        ),
    )

    assert updater.check_for_update() is None


def test_detect_install_method_prefers_pipx_prefix(monkeypatch):
    monkeypatch.setattr(sys, "prefix", "/home/test/.local/share/pipx/venvs/vulnmind")
    monkeypatch.delenv("PIPX_HOME", raising=False)

    assert updater.detect_install_method() == updater.INSTALL_PIPX


def test_pipx_metadata_detects_custom_pipx_home(monkeypatch, tmp_path):
    custom_venv = tmp_path / "tools" / "vulnmind"
    custom_venv.mkdir(parents=True)
    (custom_venv / "pipx_metadata.json").write_text("{}")
    monkeypatch.setattr(sys, "prefix", str(custom_venv))
    monkeypatch.delenv("PIPX_HOME", raising=False)

    assert updater._looks_like_pipx_environment() is True


def test_detect_install_method_recognizes_source_checkout(monkeypatch, tmp_path):
    monkeypatch.setattr(updater, "_looks_like_pipx_environment", lambda: False)
    monkeypatch.setattr(updater, "_find_source_root", lambda: tmp_path)

    assert updater.detect_install_method() == updater.INSTALL_SOURCE


def test_find_source_root_does_not_misclassify_repo_local_venv(
    monkeypatch,
    tmp_path,
):
    source_root = tmp_path / "repo"
    source_module = source_root / "vulnmind" / "updater.py"
    installed_module = (
        source_root / ".venv" / "lib" / "python3.12" /
        "site-packages" / "vulnmind" / "updater.py"
    )
    source_module.parent.mkdir(parents=True)
    installed_module.parent.mkdir(parents=True)
    (source_root / "setup.py").write_text("# package")
    source_module.write_text("# source")
    installed_module.write_text("# installed")

    monkeypatch.setattr(updater, "__file__", str(installed_module))
    assert updater._find_source_root() is None

    monkeypatch.setattr(updater, "__file__", str(source_module))
    assert updater._find_source_root() == source_root


@pytest.mark.parametrize(
    ("installer", "expected"),
    [("pip\n", updater.INSTALL_PIP), ("apt\n", updater.INSTALL_UNKNOWN)],
)
def test_detect_install_method_uses_distribution_installer(
    monkeypatch, installer, expected
):
    class Distribution:
        def read_text(self, filename):
            assert filename == "INSTALLER"
            return installer

    monkeypatch.setattr(updater, "_looks_like_pipx_environment", lambda: False)
    monkeypatch.setattr(updater, "_find_source_root", lambda: None)
    monkeypatch.setattr(updater.metadata, "distribution", lambda name: Distribution())

    assert updater.detect_install_method() == expected


def test_pip_plan_targets_the_active_interpreter():
    plan = updater.get_update_plan(
        updater.INSTALL_PIP,
        latest_version="v0.6.0",
    )

    assert plan.can_auto_update is True
    assert plan.command == (
        sys.executable,
        "-m",
        "pip",
        "install",
        "--upgrade",
        "vulnmind @ https://github.com/Sombra-1/vulnmind/archive/refs/tags/v0.6.0.tar.gz",
    )
    assert "v0.6.0.tar.gz" in plan.instructions


def test_pip_plan_refuses_unvalidated_release_tag():
    plan = updater.get_update_plan(
        updater.INSTALL_PIP,
        latest_version="../../main",
    )

    assert plan.can_auto_update is False
    assert plan.command is None


def test_release_spec_preserves_exact_tag_without_inventing_v_prefix():
    spec = updater._release_spec("0.6.1")

    assert spec.endswith("/refs/tags/0.6.1.tar.gz")


def test_source_plan_is_actionable_but_never_automatic(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, "_find_source_root", lambda: tmp_path)

    plan = updater.get_update_plan(updater.INSTALL_SOURCE)

    assert plan.can_auto_update is False
    assert plan.command is None
    assert "git -C" in plan.instructions
    assert "pull --ff-only" in plan.instructions
    assert "pip install -e" in plan.instructions


def test_perform_update_runs_pip_without_a_shell(monkeypatch, capsys):
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(updater.subprocess, "run", fake_run)
    monkeypatch.setattr(updater, "_installed_version", lambda: "0.6.0")

    result = updater.perform_update(
        updater.INSTALL_PIP,
        latest_version="v0.6.0",
    )

    assert result.success is True
    assert captured["command"][0] == sys.executable
    assert captured["command"][1:] == (
        "-m",
        "pip",
        "install",
        "--upgrade",
        "vulnmind @ https://github.com/Sombra-1/vulnmind/archive/refs/tags/v0.6.0.tar.gz",
    )
    assert captured["kwargs"] == {
        "check": False,
        "capture_output": True,
        "text": True,
        "shell": False,
    }
    captured_output = capsys.readouterr()
    assert captured_output.out == ""
    assert captured_output.err == ""


def test_perform_update_resolves_pipx_executable(monkeypatch):
    captured = {}

    monkeypatch.setattr(updater.shutil, "which", lambda name: "/usr/bin/pipx")

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(updater.subprocess, "run", fake_run)
    monkeypatch.setattr(updater, "_installed_version", lambda: "0.6.0")

    result = updater.perform_update(
        updater.INSTALL_PIPX,
        latest_version="v0.6.0",
    )

    assert result.success is True
    assert captured["command"] == (
        "/usr/bin/pipx",
        "install",
        "--force",
        "vulnmind @ https://github.com/Sombra-1/vulnmind/archive/refs/tags/v0.6.0.tar.gz",
    )


def test_perform_update_does_not_mutate_source_checkout(monkeypatch, tmp_path):
    monkeypatch.setattr(updater, "_find_source_root", lambda: Path(tmp_path))

    def unexpected_run(*args, **kwargs):
        raise AssertionError("source updates must remain manual")

    monkeypatch.setattr(updater.subprocess, "run", unexpected_run)

    result = updater.perform_update(updater.INSTALL_SOURCE)

    assert result.success is False
    assert result.command is None
    assert "pull --ff-only" in result.message


def test_perform_update_explains_missing_pipx(monkeypatch):
    monkeypatch.setattr(updater.shutil, "which", lambda name: None)

    result = updater.perform_update(
        updater.INSTALL_PIPX,
        latest_version="v0.6.0",
    )

    assert result.success is False
    assert result.returncode is None
    assert "pipx command is not available" in result.message
    assert "pipx install --force" in result.message


@pytest.mark.parametrize("installed_version", [None, "0.5.0", "invalid"])
def test_perform_update_fails_when_installed_version_cannot_be_verified(
    monkeypatch,
    installed_version,
):
    monkeypatch.setattr(
        updater.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0),
    )
    monkeypatch.setattr(updater, "_installed_version", lambda: installed_version)

    result = updater.perform_update(
        updater.INSTALL_PIP,
        latest_version="v0.6.0",
    )

    assert result.success is False
    assert "installer exited successfully" in result.message.lower()
