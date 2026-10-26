# Sentinel - Autonomous Architectural Decisions Log

This document records architectural, dependency, and security decisions made autonomously during the development of Sentinel for the Hacktoberfest 2026 Open-Source AI Challenge.

## System & Environment
- **2026-10-26 12:14 UTC+5:30**: Detected OS: macOS (Darwin arm64 - Apple Silicon, kernel 27.0.0).
- **2026-10-26 12:14 UTC+5:30**: Detected Memory: 17,179,869,184 bytes (16.0 GB RAM).
- **2026-10-26 12:14 UTC+5:30**: Verified Ollama 0.40.11 running at `http://localhost:11434`.
- **2026-10-26 12:14 UTC+5:30**: Verified GitHub CLI (`gh`) authenticated with active credentials (`ayushkrsingh946`).
- **2026-10-26 12:15 UTC+5:30**: Initiated background model pull for `llama3.2:3b`. Designed flexible fallback harness supporting Ollama, OpenAI-compatible local/remote endpoints, and zero-latency offline mock juror engine for tests and CI.

## Core Architecture
- **2026-10-26 12:18 UTC+5:30**: Selected Python 3.15 + standard library + Pydantic v2 for maximum stability, fast startup, and schema-enforced JSON validation.
- **2026-10-26 12:20 UTC+5:30**: Implemented dual-layer YAML/JSON configuration parser supporting standard YAML and fallback to structured JSON/TOML to guarantee zero breakage if PyYAML installation suffers network timeouts.
- **2026-10-26 12:22 UTC+5:30**: Enforced non-negotiable static-only security: Sentinel never executes scanned or updated package code.
- **2026-10-26 12:23 UTC+5:30**: Implemented `SecretRedactor` to scrub private keys, JWTs, cloud API keys, and database credentials before constructing juror prompts.
- **2026-10-26 12:24 UTC+5:30**: Designed 3 distinct juror roles (`injection_specialist`, `auth_secrets_specialist`, `supply_chain_specialist`) with independent evaluations.
- **2026-10-26 12:25 UTC+5:30**: Implemented auto-repair loop with 2 retries for malformed or truncated JSON from small models, plus disk-based SHA256 prompt caching in `.sentinel_cache/`.
- **2026-10-26 12:26 UTC+5:30**: Implemented strict line-evidence filter in Judge step: any finding where the quoted evidence does not exist in the source file is discarded to prevent hallucinations.
- **2026-10-26 12:27 UTC+5:30**: Added append-only SHA-256 chained audit log (`.sentinel_audit.log`).
- **2026-10-26 12:28 UTC+5:30**: Built safe staging probe (`sentinel probe`) enforcing strict allowlists from `sentinel.scope.yml`.
- **2026-10-26 12:29 UTC+5:30**: Configured review-and-fix workflow with `manual` approval default and automatic rollback storage in `.sentinel_patches/`.
- **2026-10-26 12:30 UTC+5:30**: Implemented background guard middleware with monitor-only default mode, fast regex rules, and anomaly scoring.
- **2026-10-26 12:31 UTC+5:30**: Packaged Sentinel as an Agent Skill (`skills/sentinel-audit/SKILL.md`) following the Agent Skills open standard.
