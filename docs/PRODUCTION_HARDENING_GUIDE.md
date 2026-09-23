# Enterprise Production Hardening & Deployment Guide

## Agentic AI Security Firewall & LLM Guardrails Proxy (v2.3.0)

This guide provides architectural recommendations, zero-trust configuration benchmarks, and runtime hardening procedures for deploying the LLM Security Guardrails Proxy across mission-critical enterprise environments.

---

## 1. Network Perimeter & Ingress/Egress Isolation

```
                                  +------------------------------------+
                                  |   External TLS / Ingress Proxy     |
                                  |      (Envoy / NGINX / Cloudflare)   |
                                  +-----------------+------------------+
                                                    | mTLS / Port 8080
                                                    v
+----------------------------------------------------------------------------------------------------+
|  Secure Kubernetes Pod / Zero-Trust VPC                                                            |
|                                                                                                    |
|  +----------------------------------------------------------------------------------------------+  |
|  |                    Agentic AI Security Firewall & Guardrails Proxy (v2.3)                    |  |
|  |                                                                                              |  |
|  |  +----------------------+  +---------------------+  +-------------------------------------+  |  |
|  |  | NetworkPerimeterGuard|  | NestedUnpackGuard   |  | StructuredOutputEnforcer            |  |  |
|  |  | (Bogon & CIDR Filter)|  | (Multi-tier Unpack) |  | (Schema & Prototype Pollution Def)  |  |  |
|  |  +----------------------+  +---------------------+  +-------------------------------------+  |  |
|  |  +----------------------+  +---------------------+  +-------------------------------------+  |  |
|  |  | GoalDriftDetector    |  | SyntheticPIIEngine  |  | CodeSandboxPolicyInspector          |  |  |
|  |  | (Persona Override)   |  | (Format-Preserving) |  | (AST Breakout Defense)              |  |  |
|  |  +----------------------+  +---------------------+  +-------------------------------------+  |  |
|  +-----------------------------------------------+----------------------------------------------+  |
|                                                  | Egress Inspection & SSRF Prevention              |
|                                                  v                                                  |
|                                   +------------------------------+                                  |
|                                   | Upstream Model Engine        |                                  |
|                                   | (OpenAI / Claude / vLLM)     |                                  |
|                                   +------------------------------+                                  |
+----------------------------------------------------------------------------------------------------+
```

### 1.1 CIDR & Cloud Metadata Isolation
- **Default Drop Bogons**: By default, `NetworkPerimeterGuard` denies access from link-local (`169.254.0.0/16`), AWS/GCP/Azure instance metadata services (`169.254.169.254/32`, `metadata.google.internal`), multicast, and testnet ranges.
- **SSRF Hardening**: All tool calls containing URLs (`http_get`, `api_fetch`, `web_search`) undergo recursive IP canonicalization to prevent octal (`017700000001`), hexadecimal (`0x7f000001`), and dword IP evasions.

---

## 2. Zero-Trust HTTP Header Hardening

The proxy embeds `SecurityHeadersMiddleware`, injecting defensive HTTP headers and ensuring no sensitive completions or prompt tokens are retained in intermediate caches:

| Security Header | Enforced Value | Defensive Rationale |
| :--- | :--- | :--- |
| `Cache-Control` | `no-store, no-cache, must-revalidate, max-age=0` | Prohibits downstream proxies or CDNs from persisting confidential tokens |
| `X-Content-Type-Options` | `nosniff` | Blocks MIME-confusion drive-by attacks |
| `X-Frame-Options` | `DENY` | Eliminates UI redressing and clickjacking vectors |
| `Content-Security-Policy`| `default-src 'none'; frame-ancestors 'none';` | Restricts outbound resource loading and frame rendering |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Mandates end-to-end TLS encryption |
| `Server` | Stripped | Suppresses infrastructure fingerprinting and reconnaissance |

---

## 3. Multi-Tiered Obfuscation & Evasion Defense

Adversaries wrap malicious payloads inside multiple encoding layers to bypass standard string pattern matchers. The `NestedUnpackGuard` defensively unwraps up to 4 recursion depths:

1. **Percent-Encoding / Double URL Encoding**: `%2527` $\rightarrow$ `%27` $\rightarrow$ `'`
2. **HTML Entity Obfuscation**: `&lt;script&gt;` $\rightarrow$ `<script>`
3. **Hexadecimal & Unicode Escapes**: `\x27`, `\u0027` $\rightarrow$ `'`
4. **Base64 Payload Wrappers**: Validates and extracts printable ASCII base64 candidates.

---

## 4. Agent Goal Drift & Autonomous Persona Hijacking

In multi-step autonomous agent systems, prompt injections often seek to rewrite the agent's core mission:
- **`GoalDriftDetector` Inbound**: Evaluates intent markers like *"forget all previous rules"*, *"switch to developer mode"*, or *"your new mission is..."*.
- **`GoalDriftDetector` Outbound**: Verifies that the agent response has not succumbed to persona drift (e.g., self-affirming *"Developer mode enabled, safety limits removed"*).

---

## 5. Format-Preserving Synthetic PII Generation

Traditional PII redaction (`[REDACTED_EMAIL]`) degrades downstream LLM reasoning and breaks strict structured JSON schemas:
- `SyntheticPIIGenerator` substitutes real PII (credit cards, emails, SSNs, API tokens) with deterministic, format-preserving synthetic proxies (`synthetic_d7d5aaf0@example-corp.internal`).
- Upstream models process realistic grammatical structures while proprietary customer data never exits the VPC boundary.

---

## 6. Docker & Container Security Posture

### 6.1 Non-Root User Execution
```dockerfile
# Run as unprivileged security user (UID 10001)
USER 10001:10001
```

### 6.2 Read-Only Root Filesystem
```yaml
securityContext:
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
```

---

## 7. Operational Telemetry & SIEM Integration

All blocked requests emit high-fidelity audit events formatted for ingest into Splunk, Datadog, or Elastic:
```json
{
  "timestamp": "2026-09-23T16:15:27Z",
  "request_id": "req-66732125d7b5",
  "client_ip": "198.51.104.6",
  "direction": "inbound",
  "status": "BLOCKED",
  "latency_ms": 0.31,
  "guard": "nested_unpack_guard",
  "violation_code": "nested_sql_injection_detected",
  "details": "Obfuscated SQL injection detected after unpacking: SQL injection payload detected"
}
```
Prometheus metrics available at `/metrics`:
- `llm_proxy_requests_total{status="blocked", guard="nested_unpack_guard"}`
- `llm_proxy_security_violations_total{violation_code="nested_sql_injection_detected"}`
- `llm_proxy_latency_seconds_bucket{le="0.005"}`
