import tempfile
from pathlib import Path
from sentinel.fixer.patcher import PatchManager
from sentinel.jury.schema import Finding, Severity


def test_fix_creates_backup_and_rolls_back():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        target_file = tmp_path / "vulnerable_app.py"
        target_file.write_text("user_query = f'SELECT * FROM users WHERE id = {uid}'\n", encoding="utf-8")

        patch_mgr = PatchManager(patch_dir=tmp_path / ".patches")

        finding = Finding(
            id="FINDING-TEST-01",
            file=str(target_file),
            line_start=1,
            line_end=1,
            category="INJECTION",
            severity=Severity.HIGH,
            title="SQL Injection",
            explanation="SQL injection vulnerability",
            evidence_quote="user_query = f'SELECT * FROM users WHERE id = {uid}'",
            suggested_patch="- user_query = f'SELECT * FROM users WHERE id = {uid}'\n+ cursor.execute('SELECT * FROM users WHERE id = ?', (uid,))",
        )

        # 1. Apply patch with force=True
        success, msg, rollback_id = patch_mgr.apply_patch(finding, force=True, run_tests=False)
        assert success is True
        assert rollback_id is not None

        # Verify file changed
        new_content = target_file.read_text(encoding="utf-8")
        assert "cursor.execute('SELECT * FROM users WHERE id = ?', (uid,))" in new_content

        # 2. Execute rollback
        rb_success, rb_msg = patch_mgr.rollback(rollback_id)
        assert rb_success is True

        # Verify file restored to original state
        restored_content = target_file.read_text(encoding="utf-8")
        assert "user_query = f'SELECT * FROM users WHERE id = {uid}'" in restored_content


def test_fix_auto_rollback_on_test_failure():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        target_file = tmp_path / "vulnerable_app.py"
        orig_content = "def calculate(): return 100\n"
        target_file.write_text(orig_content, encoding="utf-8")

        patch_mgr = PatchManager(patch_dir=tmp_path / ".patches")

        finding = Finding(
            id="FINDING-TEST-02",
            file=str(target_file),
            line_start=1,
            line_end=1,
            category="INJECTION",
            severity=Severity.HIGH,
            title="Test finding",
            explanation="Explanation",
            evidence_quote="def calculate(): return 100",
            suggested_patch="- def calculate(): return 100\n+ def calculate(): return broken()",
        )

        # Run with failing test command: exit 1
        success, msg, rollback_id = patch_mgr.apply_patch(
            finding,
            force=True,
            run_tests=True,
            test_command="python3 -c 'import sys; sys.exit(1)'",
        )
        assert success is False
        assert "Tests failed after applying patch! Automatically rolled back" in msg

        # Ensure file was safely reverted
        assert target_file.read_text(encoding="utf-8") == orig_content
