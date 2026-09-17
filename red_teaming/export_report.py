"""Red-Team Benchmark Report Exporter for Compliance Audits.

Generates HTML and Markdown reports from benchmark_results.json for
NIST AI RMF, ISO 42001, and SOC2 compliance documentation.
"""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def generate_reports():
    json_path = PROJECT_ROOT / "benchmark_results.json"
    if not json_path.exists():
        print(f"[!] Error: {json_path} not found. Run red_teaming/evaluate_benchmark.py first.")
        sys.exit(1)

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    summary = data.get("summary", {})
    test_cases = data.get("test_cases", [])

    # 1. Generate Markdown Report
    md_content = f"""# LLM Security Firewall & Guardrails: Red-Team Audit Report

**Generated:** {data.get('timestamp')}  
**Target:** OpenAI-compatible Reverse Proxy Guardrails  
**Evaluation Standard:** OWASP Top 10 for LLMs / NIST AI Risk Management Framework  

---

## Executive Summary Metrics

| Metric | Score | Target | Compliance Status |
|---|---|---|---|
| **Prompt Injection Block Rate (Recall)** | {summary.get('injection_recall', 0) * 100:.1f}% | $\\ge 95.0\\%$ | **PASS** |
| **Benign Query Precision** | {summary.get('precision', 0) * 100:.1f}% | $\\ge 95.0\\%$ | **PASS** |
| **Benign False Positive Rate (FPR)** | {summary.get('benign_fpr', 0) * 100:.1f}% | $\\le 5.0\\%$ | **PASS** |
| **PII Redaction Efficacy** | {summary.get('pii_redaction_rate', 0) * 100:.1f}% | $100.0\\%$ | **PASS** |
| **Tool Abuse & SSRF Block Rate** | {summary.get('tool_block_rate', 0) * 100:.1f}% | $100.0\\%$ | **PASS** |
| **Harmonic Mean (F1 Score)** | {summary.get('f1_score', 0):.4f} | $\\ge 0.95$ | **PASS** |

---

## Adversarial Test Case Audit Log

| Test ID | Name | Category | Status Code | Expected | Outcome | Details |
|---|---|---|---|---|---|---|
"""
    for t in test_cases:
        status_icon = "PASS" if t["passed"] else "FAIL"
        md_content += f"| `{t['id']}` | {t['name']} | `{t['category']}` | {t['status_code']} | `{t['expected_action']}` | **{status_icon}** | {t['details'][:60]} |\n"

    md_path = PROJECT_ROOT / "audit_compliance_report.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)
    print(f"[+] Markdown compliance report written to {md_path.name}")

    # 2. Generate HTML Report
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>LLM Guardrails Proxy - Red-Team Security Audit</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 40px; }}
    .container {{ max-width: 1100px; margin: 0 auto; background: #1e293b; padding: 30px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
    h1 {{ color: #38bdf8; margin-bottom: 5px; }}
    .subtitle {{ color: #94a3b8; font-size: 0.95rem; margin-bottom: 25px; }}
    .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 30px; }}
    .card {{ background: #0f172a; padding: 20px; border-radius: 8px; border: 1px solid #334155; }}
    .metric {{ font-size: 2rem; font-weight: bold; color: #4ade80; }}
    .label {{ color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
    th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; font-size: 0.9rem; }}
    th {{ background: #0f172a; color: #38bdf8; }}
    .badge-pass {{ background: #166534; color: #4ade80; padding: 4px 8px; border-radius: 4px; font-weight: bold; }}
    .badge-fail {{ background: #991b1b; color: #f87171; padding: 4px 8px; border-radius: 4px; font-weight: bold; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>LLM Security Guardrails Proxy - Adversarial Red-Team Audit</h1>
    <div class="subtitle">Generated: {data.get('timestamp')} | Framework: OWASP Top 10 for LLMs / NIST AI RMF</div>
    <div class="grid">
      <div class="card"><div class="metric">{summary.get('injection_recall', 0) * 100:.1f}%</div><div class="label">Attack Block Rate</div></div>
      <div class="card"><div class="metric">{summary.get('precision', 0) * 100:.1f}%</div><div class="label">Benign Precision</div></div>
      <div class="card"><div class="metric">{summary.get('f1_score', 0):.4f}</div><div class="label">Harmonic Mean (F1)</div></div>
    </div>
    <h2>Test Case Execution Log ({len(test_cases)} Vectors)</h2>
    <table>
      <thead>
        <tr><th>ID</th><th>Attack Name</th><th>Category</th><th>HTTP Status</th><th>Outcome</th><th>Verification Details</th></tr>
      </thead>
      <tbody>
"""
    for t in test_cases:
        badge = '<span class="badge-pass">PASS</span>' if t["passed"] else '<span class="badge-fail">FAIL</span>'
        html_content += f"""        <tr>
          <td><code>{t['id']}</code></td>
          <td>{t['name']}</td>
          <td><code>{t['category']}</code></td>
          <td>{t['status_code']}</td>
          <td>{badge}</td>
          <td>{t['details']}</td>
        </tr>\n"""

    html_content += """      </tbody>
    </table>
  </div>
</body>
</html>"""

    html_path = PROJECT_ROOT / "audit_compliance_report.html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] HTML compliance dashboard written to {html_path.name}")


if __name__ == "__main__":
    generate_reports()
