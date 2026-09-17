"""Interactive CLI utility for testing prompt security and guardrails in the terminal."""

import argparse
import json
import sys
from proxy.pipeline import SecurityPipeline
from proxy.config import get_settings


def test_single_prompt(prompt: str):
    """Test a single prompt through the security pipeline."""
    pipeline = SecurityPipeline()
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": prompt}]
    }

    print("\n" + "=" * 60)
    print("INPUT PROMPT:")
    print(prompt)
    print("-" * 60)

    res = pipeline.process_inbound(payload, request_id="cli-test", client_ip="127.0.0.1")

    if res.is_allowed:
        print("[ALLOWED] Prompt passed all inbound guardrails.")
        sanitized_msg = res.sanitized_payload["messages"][0]["content"]
        if sanitized_msg != prompt:
            print("\n[SANITIZED CONTENT]:")
            print(sanitized_msg)
        if res.context.reversal_map:
            print("\n[PII REDACTION MAP]:")
            print(json.dumps(res.context.reversal_map, indent=2))
    else:
        print("[BLOCKED] Security violation detected!")
        print(json.dumps(res.error_response, indent=2))
    print("=" * 60 + "\n")


def interactive_mode():
    """Run an interactive prompt evaluation shell."""
    print("=" * 60)
    print("LLM Security Guardrails Proxy - Interactive Inspector")
    print("Type your prompt to inspect for injections and PII.")
    print("Type 'exit' or 'quit' to exit.")
    print("=" * 60 + "\n")

    while True:
        try:
            prompt = input("guardrails> ")
            if not prompt.strip():
                continue
            if prompt.strip().lower() in ("exit", "quit"):
                break
            test_single_prompt(prompt)
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break


def main():
    parser = argparse.ArgumentParser(description="LLM Guardrails Proxy CLI Testing Tool")
    parser.add_argument("--prompt", "-p", type=str, help="Single prompt string to inspect")
    parser.add_argument("--interactive", "-i", action="store_true", help="Launch interactive testing REPL")

    args = parser.parse_args()

    if args.prompt:
        test_single_prompt(args.prompt)
    elif args.interactive or len(sys.argv) == 1:
        interactive_mode()


if __name__ == "__main__":
    main()
