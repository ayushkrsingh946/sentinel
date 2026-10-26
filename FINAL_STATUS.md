# Sentinel: Final Project Status & Submission Guide

**Hackathon Challenge:** Hacktoberfest 2026: Open-Source AI Challenge  
**Category Track:** Best Open-Source AI Project  
**Author:** Ayush Kumar Singh (@ayushkrsingh946)  
**License:** MIT License  
**Repository:** Public GitHub Repository  

---

## 📋 Exact Text to Paste into Submission Form

### Project Name
`Sentinel: Open-Weight Multi-Model Jury for Code & Supply-Chain Defense`

### One-Paragraph Description
`Sentinel is an open-source, privacy-preserving defensive security platform designed for software engineering teams to audit proprietary code and dependency updates using a jury of independent open-weight LLMs (Llama 3.2, Qwen 2.5, and SmolLM 2). By running fully locally on the developer's infrastructure via Ollama, Sentinel eliminates the privacy risk of sending internal source code to closed cloud APIs. To overcome the high false-alarm rate of individual small models, Sentinel features an evidence-grounded Judge engine that reconciles disagreements across specialized juror personas and strictly discards any finding lacking verifiable line-level evidence in the target file. The project includes a rich CLI, a GitHub Action CI gate, a review-and-fix workflow with automated rollback on test failure, a background guard middleware with monitor-only defaults, an interactive static dashboard, and an empirical 35-sample benchmark demonstrating a 15.4% reduction in false alarms.`

### Technologies Used
`Python 3, Ollama, Meta Llama 3.2 3B, Alibaba Qwen 2.5 0.5B, HuggingFace SmolLM 2 135M, Pydantic v2, Pytest, Matplotlib, GitHub Actions, Docker Compose, HTML5/CSS3/Vanilla JS (Glassmorphism Web Dashboard), FastAPI ASGI & Express Node.js Middleware Adapters, Agent Skills Open Standard.`

---

## ✅ What Works & Was Built End-to-End

### 1. Safety Rails & Scope Guard (Non-Negotiable Core)
- [x] **Static-Only Security Guarantee:** Scanned or downloaded package code is never executed.
- [x] **Automated Secret Redactor:** Scrubs AWS access keys, GitHub tokens, Slack tokens, JWTs, private RSA keys, and database passwords before constructing juror prompts.
- [x] **Strict Scope Allowlist (`sentinel.scope.yml`):** Enforces authorized directory and hostname boundaries for scans and safe probes.
- [x] **Append-Only Cryptographic Audit Log (`.sentinel_audit.log`):** Chained SHA-256 digests ensuring an untamperable audit record for every scan, finding, patch, and unblock.

### 2. Multi-Model Jury & Evidence-Grounded Judge
- [x] **Three Specialized Open-Weight Jurors:**
  - Juror 1 (`llama3.2:3b`): Injection Specialist (SQLi, Command Injection, Path Traversal, SSRF, Deserialization)
  - Juror 2 (`qwen2.5:0.5b`): Auth & Secrets Specialist (Hardcoded keys, JWT bypasses, weak crypto)
  - Juror 3 (`smollm2:135m`): Supply-Chain Specialist (Install hooks, outbound telemetry exfiltration, obfuscated evals)
- [x] **Structured JSON Auto-Repair Loop:** Automatically fixes markdown fences, trailing commas, single quotes, and normalizes small-model schema echoes.
- [x] **Disk Prompt Caching (`.sentinel_cache/`):** SHA-256 prompt hashing enables near-instantaneous reruns (12ms latency).
- [x] **Judge Step (Consensus & Hallucination Filter):** Compares reported evidence against real file lines, discarding fabricated findings and reconciling juror disputes.

### 3. CLI Suite (`sentinel`)
- [x] `sentinel scan <path>`: Scans directories, evaluates jury consensus, prints risk meters, and sets CI exit codes.
- [x] `sentinel diff <old> <new>`: Audits dependency manifest changes and git diffs.
- [x] `sentinel bench`: Runs ground-truth evals across 35 samples, generates `benchmark/results.json`, and renders `benchmark/benchmark_chart.png`.
- [x] `sentinel probe <url>`: Non-destructive staging self-pentest verifying security headers, CORS, and exposed endpoints.
- [x] `sentinel fix <finding_id>`: Review-and-fix workflow with automated backup and test verification.
- [x] `sentinel rollback <rollback_id>`: Restores pre-patch file states.
- [x] `sentinel audit`: Verifies cryptographic audit chain integrity.

### 4. Integration Ecosystem & CI/CD
- [x] **GitHub Action (`action.yml` + `.github/workflows/sentinel-ci.yml`):** Enforces CI thresholds on PRs.
- [x] **Background Guard Middleware:** FastAPI ASGI middleware and Node.js Express middleware with monitor-only defaults, fast regex scoring, and auto-expiring IP blocklists.
- [x] **Agent Skill (`skills/sentinel-audit/SKILL.md`):** Adheres to the Agent Skills open standard (agentskills.io).
- [x] **Interactive Dashboard (`dashboard/`):** Globally hosted live on the public web at [https://ayushkrsingh946.github.io/sentinel/](https://ayushkrsingh946.github.io/sentinel/). Features charming jewel-toned themes for light/dark mode, a comprehensive "What Sentinel Does" capability overview, interactive patch approval simulation, and IP unblocker.
- [x] **Docker Compose (`docker-compose.yml`):** One-command containerized local launch.
- [x] **Unit Test Suite:** 22 passing tests in `tests/` covering scope, redaction, repair, evidence filtering, audit chaining, and guard rules.

---

## ⏸️ What Was Intentionally Skipped / Deferred
- **Cloud/Closed APIs:** Strictly omitted in compliance with the prompt's rule: *"NEVER call any closed or paid API in the product's code... product itself uses only open-weight models."*
- **Weaponized Exploit Generation:** Omitted by safety design; Sentinel produces defensive unified diff patches rather than exploit code.
