# Context Fragmentation & Distributed Prompt Smuggling Mitigation

## Multi-Turn Smuggling Vectors
Adversaries split malicious prompts across multiple non-contiguous conversational turns to bypass single-turn heuristic filters.

## Sliding Multi-N-Gram Reassembly
- Reconstitutes sliding windows across recent conversational turns.
- Detects split override instructions, command fragmentation, and reverse shell payloads.
