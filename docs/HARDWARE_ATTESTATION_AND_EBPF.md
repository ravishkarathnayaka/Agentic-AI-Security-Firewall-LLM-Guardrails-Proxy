# Hardware Enclave Attestation & eBPF Kernel Telemetry

## Confidential Computing Root-of-Trust
- **Supported Enclaves**: AWS Nitro Enclaves, Intel SGX, AMD SEV-SNP, and TPM 2.0.
- **Platform Configuration Registers (PCR)**: Measured boot firmware verification against cryptographic golden baseline hashes.
- **Signature Integrity**: Asymmetric hardware certificate validation of enclave quotes.

## Low-Overhead eBPF Syscall Telemetry
- Real-time kernel tracing of agent process boundaries.
- Instantaneous flagging of blocked kernel primitives (`ptrace`, `pivot_root`, `kexec_load`).
