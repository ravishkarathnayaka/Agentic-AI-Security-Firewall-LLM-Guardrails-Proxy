# Prompt Honeypot Deception & Decoy Sandboxing (v4.2)

## Architectural Specification
Active defense module injecting dynamic honeytokens into agent instructions to trap prompt injection attackers.

### Trapping Lifecycle
1. **Dynamic Injection**: Invisible honeytokens appended to prompt context.
2. **Exfiltration Trigger**: Outbound queries matching honeytokens are trapped.
3. **Decoy Containment**: Attackers receive convincing synthetic mock outputs while security telemetry registers the breach.
