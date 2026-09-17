# Contributing to Agentic AI Security Firewall & LLM Guardrails Proxy

Thank you for your interest in contributing to this open-source AI security project! We welcome contributions ranging from novel adversarial prompt injection vectors to performance optimizations and telemetry integrations.

---

## 🛠️ Development Setup

1. **Clone and Branch**:
   ```bash
   git clone https://github.com/ravishkarathnayaka/Agentic-AI-Security-Firewall-LLM-Guardrails-Proxy.git
   cd Agentic-AI-Security-Firewall-LLM-Guardrails-Proxy
   git checkout -b feature/your-feature-name
   ```

2. **Set up Virtual Environment**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1
   pip install -e ".[dev]"
   ```

3. **Verify Tests and Benchmarks**:
   ```bash
   pytest -v tests/
   python red_teaming/evaluate_benchmark.py
   ```

---

## 📋 Contribution Guidelines

### Adding New Attack Vectors
When adding new attack vectors:
1. Append the test payload to the appropriate dataset file in `red_teaming/datasets/` (`prompt_injections.json`, `indirect_injections.json`, `pii_test_cases.json`).
2. Run `python red_teaming/evaluate_benchmark.py` to ensure the benchmark meets the minimum required quality gates:
   - **Attack Block Rate (Recall):** $\ge 95\%$
   - **Benign False Positive Rate:** $\le 5\%$
   - **PII Redaction Rate:** $100\%$
   - **Tool Abuse Block Rate:** $100\%$

### Code Style & Quality
- All code must adhere to PEP 8 standards enforced by Ruff:
  ```bash
  ruff check proxy/ red_teaming/ tests/
  ```
- Write accompanying unit tests under `tests/` for any new guard logic.

---

## 🔄 Pull Request Process

1. Ensure all tests and lint checks pass cleanly.
2. Submit a descriptive Pull Request referencing the OWASP Top 10 for LLMs vulnerability addressed.
3. Once reviewed and approved, maintainers will squash-merge into `main`.
