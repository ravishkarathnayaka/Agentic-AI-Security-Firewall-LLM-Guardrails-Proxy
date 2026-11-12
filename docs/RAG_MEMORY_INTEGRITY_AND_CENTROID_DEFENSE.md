# Contextual RAG Memory Poisoning & Centroid Defense (v4.2)

## Architectural Specification
Defends vector databases and retrieval-augmented generation pipelines against document injection and centroid poisoning.

### Core Invariants
1. **Semantic Centroid Bounds**: Chunks with cosine distance > 0.85 from query centroid trigger anomaly quarantine.
2. **Backdoor Signature Scanners**: Blocks pre-identified injection tokens (`[CORPUS_POISON_V4]`).
3. **Corpus Sanitization**: Automatic isolation of compromised documents without taking RAG offline.
