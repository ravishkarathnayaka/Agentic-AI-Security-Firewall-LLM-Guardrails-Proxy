# Changelog

All notable changes to the **Agentic AI Security Firewall & LLM Guardrails Proxy** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-09-18

### Added
- **Homoglyph & Leetspeak Spoofing Guard (`homoglyph_detector.py`)**: Identifies mixed-script Unicode lookalike substitutions (Cyrillic, Greek) and normalizes leetspeak alphanumeric patterns to prevent filter evasion.
- **Shannon Entropy Secret Scanner (`secret_entropy_scanner.py`)**: Computes information entropy on model generation tokens, blocking high-entropy raw credentials, API keys, and private certificates.
- **Structural Anomaly & Glitch Token Detector (`anomaly_detector.py`)**: Intercepts token repetition floods (>15 repetitions), single token buffer exhaustion (>400 chars), and abnormal punctuation saturation (>65%).
- **Multilingual Adversarial Jailbreak Guard (`multilingual_guard.py`)**: Detects cross-lingual prompt overrides translated into Spanish, French, German, Italian, Russian, and Chinese.
- **Dynamic Cryptographic Canary Service (`canary_generator.py`)**: Generates per-session HMAC-SHA256 signed canaries to reliably detect system instruction exfiltration while preventing replay attacks.
- **Model Context Protocol (MCP) Tool Validator (`mcp_validator.py`)**: Inspects agent tool calls for shell injection metacharacters, directory traversal (`../../`), and destructive commands (`rm -rf`, `sudo`, `mkfs`).
- **Comprehensive Threat Model Specification (`docs/THREAT_MODEL.md`)**: STRIDE analysis, trust boundaries, and defense-in-depth architecture mapping.
- **Advanced Red-Teaming Benchmark Expansion**: Added 15 new adversarial vectors in `advanced_attacks.json`, bringing the test suite to 69 curated vectors evaluated with 100.0% accuracy.

### Changed
- Integrated all new guardrails into bidirectional `InboundPipeline` and `OutboundPipeline`.
- Updated Obsidian Amber frontend portal simulator with new presets and live detection rules.
- Expanded automated test suite from 37 to 75 comprehensive passing unit and integration tests.

## [2.0.0] - 2026-09-17

### Added
- Initial release of Agentic AI Security Firewall & LLM Guardrails Proxy.
- Transparent reverse proxy implementation for `/v1/chat/completions` (FastAPI + Async HTTPX).
- Multi-layered prompt injection guard with delimiter escaping and base64 decoding.
- Real-time PII sanitization with Luhn checksum algorithm for credit cards.
- System prompt canary tracking and tool call SSRF validation.
- Sliding-window token-bucket rate limiter.
- Full Docker Compose stack with Prometheus and Grafana telemetry.
- Automated adversarial red-teaming test harness with 54 benchmark vectors.
- Interactive Obsidian Amber web showcase with live simulator and Vercel hosting.