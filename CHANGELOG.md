# Changelog

All notable changes to the **Agentic AI Security Firewall & LLM Guardrails Proxy** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] - 2026-09-22

### Added
- **SQL & NoSQL Injection Guard (`sql_nosql_guard.py`)**: Real-time inspection of LLM-generated database queries and agent tool arguments for tautologies (`OR 1=1`), UNION exfiltration, stacked table drops, time delays, and MongoDB `$where` / `$gt` operator injection.
- **AST Code Sandbox Policy Inspector (`code_sandbox_policy.py`)**: Static AST analysis of LLM-generated Python scripts before sandbox execution, blocking dangerous imports (`os`, `subprocess`, `socket`, `ctypes`), unsafe builtins (`eval`, `exec`), and dunder class hierarchy traversal (`__subclasses__`).
- **Differential N-Gram Prompt Leakage Detector (`differential_leak_guard.py`)**: Measures continuous n-gram containment and longest contiguous token subsequences between internal system directives and model completions to catch subtle or paraphrased extraction leaks.
- **RAG Hallucination & Citation Grounding Verifier (`hallucination_verifier.py`)**: Cross-references RAG generation against retrieved source documents to detect ungrounded claims, fabricated external URLs, and phantom citation markers.
- **Token Padding & Delimiter Evasion Guard (`token_padding_guard.py`)**: Intercepts whitespace padding floods (>65% whitespace) and repetitive boundary delimiter bursts (>=25 symbols) designed to bypass heuristic filters or push context limits.
- **Sensitive Document Watermark Detector (`watermark_detector.py`)**: Identifies corporate classification markings, Traffic Light Protocol tags (`TLP:RED`, `TLP:AMBER`), and legal privilege headers (`ATTORNEY-CLIENT PRIVILEGED`) to prevent data spill incidents.
- **RFC 5424 Syslog & Common Event Format (CEF) SIEM Forwarder (`siem_forwarder.py`)**: Enterprise SOC telemetry generator formatting security audit logs for Splunk, Elastic, and Microsoft Sentinel.
- **Upstream LLM Circuit Breaker (`circuit_breaker.py`)**: Three-state circuit breaker (`CLOSED`, `OPEN`, `HALF_OPEN`) mitigating cascading outages, upstream rate limits, and latency spikes with automated fallback routing.
- **Enterprise AI Security Incident Response Playbook (`docs/INCIDENT_RESPONSE_PLAYBOOK.md`)**: Comprehensive SOC triage, containment, and forensic runbooks aligned with NIST SP 800-61r2 and NIST AI RMF.
- **Adversarial Benchmark Expansion**: Added `database_and_ast_attacks.json`, expanding the evaluation harness to 84 curated vectors with a 100.0% block rate, 0.0% FPR, and 1.0000 F1 score.

### Changed
- Integrated extended database, AST sandbox, and token padding guards into inbound and outbound execution pipelines.
- Updated Obsidian Amber web portal simulator with new presets (`sqli`, `ast`, `padding`, `watermark`) and live client-side heuristic inspection rules.
- Expanded automated unit and integration test suite to **130 passing tests**.

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