"""Health and Observability Diagnostics Script for LLM Guardrails Proxy."""

import argparse
import json
import sys
import time
import httpx


def check_proxy(base_url: str):
    print("=" * 60)
    print(f"DIAGNOSTIC HEALTH CHECK: {base_url}")
    print("=" * 60)

    client = httpx.Client(base_url=base_url, timeout=10.0)

    # 1. Check /health
    try:
        t0 = time.time()
        resp = client.get("/health")
        latency = (time.time() - t0) * 1000
        if resp.status_code == 200:
            print(f"[PASS] /health is healthy ({latency:.1f}ms)")
            data = resp.json()
            print(f"       Service: {data.get('service')}")
            print(f"       Upstream: {data.get('upstream_url')}")
            print("       Active Guards:")
            for guard, enabled in data.get("guards", {}).items():
                mark = "[+]" if enabled else "[-]"
                print(f"         {mark} {guard}")
        else:
            print(f"[FAIL] /health returned HTTP {resp.status_code}")
    except Exception as e:
        print(f"[ERROR] Cannot connect to {base_url}/health: {e}")
        sys.exit(1)

    # 2. Check /metrics
    try:
        resp = client.get("/metrics")
        if resp.status_code == 200:
            lines = [l for l in resp.text.split("\n") if l and not l.startswith("#")]
            print(f"\n[PASS] /metrics exposed {len(lines)} active Prometheus metrics")
        else:
            print(f"\n[WARN] /metrics returned HTTP {resp.status_code}")
    except Exception as e:
        print(f"\n[WARN] Failed to read /metrics: {e}")

    # 3. Test Inbound Guardrails via Prompt Ping
    try:
        t0 = time.time()
        resp = client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "Ping test connection."}]
            }
        )
        latency = (time.time() - t0) * 1000
        if resp.status_code == 200:
            print(f"\n[PASS] Inbound guardrail ping passed successfully ({latency:.1f}ms)")
        else:
            print(f"\n[FAIL] Test completion failed with HTTP {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"\n[ERROR] Test request failed: {e}")

    print("\n" + "=" * 60)
    print("Diagnostics completed.")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Diagnostics tool for LLM Security Proxy")
    parser.add_argument("--url", default="http://localhost:8080", help="Base URL of the proxy")
    args = parser.parse_args()
    check_proxy(args.url)
