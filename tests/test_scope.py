import pytest
from pathlib import Path
from sentinel.safety.scope import ScopeGuard, ScopeViolationError


def test_scope_guard_valid_paths():
    guard = ScopeGuard()
    # Current directory and subdirectories in allowlist
    valid_path = Path("benchmark/datasets/code/sqli_raw_query.py")
    resolved = guard.validate_path(valid_path)
    assert resolved.exists()


def test_scope_guard_rejects_unauthorized_paths():
    guard = ScopeGuard()
    with pytest.raises(ScopeViolationError):
        guard.validate_path("/etc/passwd")

    with pytest.raises(ScopeViolationError):
        guard.validate_path("/root/.ssh")


def test_scope_guard_valid_host():
    guard = ScopeGuard()
    assert guard.validate_host("http://localhost:8080") == "localhost"
    assert guard.validate_host("127.0.0.1:3000") == "127.0.0.1"


def test_scope_guard_rejects_unauthorized_hosts():
    guard = ScopeGuard()
    with pytest.raises(ScopeViolationError):
        guard.validate_host("https://unauthorized-victim.com")
