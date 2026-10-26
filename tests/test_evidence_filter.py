from sentinel.jury.judge import SentinelJudge
from sentinel.jury.schema import Finding, Severity


def test_evidence_filter_accepts_real_code():
    real_code = (
        "import sqlite3\n"
        "def query_user(uid):\n"
        "    cursor.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
        "    return cursor.fetchone()\n"
    )

    finding = Finding(
        id="F1",
        file="app.py",
        line_start=3,
        line_end=3,
        category="INJECTION",
        severity=Severity.HIGH,
        title="SQL Injection",
        explanation="Query formatted directly",
        evidence_quote="cursor.execute(f'SELECT * FROM users WHERE id = {uid}')",
    )

    assert SentinelJudge.verify_line_evidence(finding, real_code) is True


def test_evidence_filter_discards_hallucination():
    real_code = (
        "import sqlite3\n"
        "def query_user(uid):\n"
        "    cursor.execute('SELECT * FROM users WHERE id = ?', (uid,))\n"
        "    return cursor.fetchone()\n"
    )

    hallucinated_finding = Finding(
        id="F2",
        file="app.py",
        line_start=3,
        line_end=3,
        category="INJECTION",
        severity=Severity.HIGH,
        title="SQL Injection",
        explanation="Fabricated finding not in real code",
        evidence_quote="db.raw_query_exec_unsafe(f'DROP TABLE users')",
    )

    # Must be discarded because evidence quote does not exist in real code!
    assert SentinelJudge.verify_line_evidence(hallucinated_finding, real_code) is False
