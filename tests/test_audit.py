import tempfile
from pathlib import Path
from sentinel.safety.audit import AuditLogger


def test_audit_logging_and_verification():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "test_audit.log"
        logger = AuditLogger(log_file)

        # Log three events
        logger.log("SCAN_STARTED", actor="test-runner", target="app.py", details={"files": 5})
        logger.log("FINDING_DETECTED", actor="juror-1", target="app.py:12", details={"sev": "HIGH"})
        logger.log("SCAN_COMPLETED", actor="sentinel", target="app.py", details={"risk": 45})

        valid, msg = logger.verify_integrity()
        assert valid is True
        assert "3 chained events intact" in msg

        entries = logger.read_entries()
        assert len(entries) == 3
        assert entries[0]["event_type"] == "SCAN_STARTED"
        assert entries[1]["prev_hash"] == entries[0]["entry_hash"]
        assert entries[2]["prev_hash"] == entries[1]["entry_hash"]


def test_audit_detects_tampering():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "tampered.log"
        logger = AuditLogger(log_file)

        logger.log("EVENT_1", actor="user", target="file1")
        logger.log("EVENT_2", actor="user", target="file2")

        # Tamper with file content
        content = log_file.read_text(encoding="utf-8")
        tampered_content = content.replace("file1", "malicious_tamper")
        log_file.write_text(tampered_content, encoding="utf-8")

        valid, msg = logger.verify_integrity()
        assert valid is False
        assert "Tampered entry detected" in msg
