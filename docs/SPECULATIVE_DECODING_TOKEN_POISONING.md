# Speculative Decoding Draft Token Verification (v4.2)

## Architectural Specification
Protects multi-model speculative decoding architectures (draft model + target verifier) against draft poisoning.

### Defense Mechanism
1. **Entropy Divergence Boundary**: Flags speculative token proposals with entropy variance > 4.5.
2. **Control Token Elimination**: Strips out unauthorized ChatML and end-of-text control sequences from draft proposals.
