---
name: sentinel-audit
description: Run security audits on source code repositories and dependency update diffs using Sentinel's open-weight model jury. Use when analyzing code for injection, authentication flaws, hardcoded secrets, and supply-chain tampering.
---

# Sentinel Security Audit Skill

This skill enables any autonomous agent to run static security audits, verify supply-chain updates, and inspect codebases using Sentinel's multi-model jury.

## Capabilities

1. **Source Code Audit**: Scans code directories for SQLi, Command Injection, Path Traversal, SSRF, Deserialization, Hardcoded Secrets, and Weak Cryptography.
2. **Dependency Update Audit**: Analyzes package diffs for malicious lifecycle scripts (`postinstall`), outbound network exfiltration, dynamic evaluation (`eval`/`atob`), and unauthorized file access.
3. **Audit Log Inspection**: Verifies cryptographically chained SHA-256 logs for accountability.

## When to Use

- When reviewing a PR or git commit before merge.
- When updating an npm, Python, or Go dependency.
- When running pre-deployment security checks on internal services.

## Usage Commands

### 1. Source Code Audit
```bash
sentinel scan <directory_or_file_path> [--threshold 60] [--json]
```

### 2. Dependency Update Diff Audit
```bash
sentinel diff <original_package.json> <updated_package.json>
# Or directly from git diff:
git diff origin/main | sentinel diff -
```

### 3. Review and Apply Patch
```bash
sentinel fix <FINDING_ID> --file <PATH> --approve
# To rollback:
sentinel rollback <ROLLBACK_ID>
```

### 4. Safe Staging Probe
```bash
# Probes allowed staging endpoints listed in sentinel.scope.yml
sentinel probe http://localhost:8080
```

## Security Guarantees
- **Static Analysis Only**: Sentinel never executes untrusted code or dependencies.
- **Secret Redaction**: Keys, tokens, and passwords are automatically scrubbed before prompt construction.
- **Evidence-Backed**: The Judge engine discards any finding lacking verifiable line-level evidence in the target file.
