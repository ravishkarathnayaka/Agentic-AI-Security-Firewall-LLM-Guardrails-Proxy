"""
Prompt Decompression Bomb and Zlib/Zip-Slip Guard for Agent Tools.

Mitigates OWASP LLM04 (Model Denial of Service) and CWE-29/CWE-409 (Decompression Bombs
and Path Traversal via Archive Extraction / Zip Slip) by inspecting compressed buffers
in agent tool arguments, enforcing expansion caps, compression ratios, and file path safety.
"""

import base64
import gzip
import io
import zipfile
import zlib
from dataclasses import dataclass
from typing import Optional, Dict, Any, List


@dataclass
class DecompressionResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: str = "Passed decompression bomb inspection"
    compression_ratio: float = 0.0
    decompressed_bytes: int = 0
    suspect_path: Optional[str] = None


class DecompressionBombGuard:
    """
    Guards agent tools against archive expansion DoS and Zip-Slip path traversal.
    """

    ARCHIVE_PARAM_KEYS = {"archive", "bundle", "zip", "gzip", "zlib", "compressed", "file_data", "tar"}

    def __init__(
        self,
        max_decompressed_bytes: int = 5 * 1024 * 1024,  # 5 MB max safe expansion
        max_compression_ratio: float = 25.0,
        block_on_violation: bool = True
    ):
        self.max_decompressed_bytes = max_decompressed_bytes
        self.max_compression_ratio = max_compression_ratio
        self.block_on_violation = block_on_violation

    def inspect_bytes(self, compressed_bytes: bytes) -> DecompressionResult:
        """Inspects raw byte buffer for gzip/zlib/zip decompression bombs and zip slip."""
        if not compressed_bytes:
            return DecompressionResult(is_blocked=False)

        compressed_len = len(compressed_bytes)

        # 1. Try ZIP Archive Inspection
        try:
            with zipfile.ZipFile(io.BytesIO(compressed_bytes)) as zf:
                total_uncompressed = 0
                for info in zf.infolist():
                    # Check Zip Slip Path Traversal in filename
                    fn = info.filename
                    if ".." in fn or fn.startswith("/") or fn.startswith("\\") or ":\\" in fn or ":/" in fn:
                        return DecompressionResult(
                            is_blocked=self.block_on_violation,
                            violation_code="zip_slip_path_traversal",
                            details=f"Zip Slip path traversal detected in archive entry: '{fn}'",
                            suspect_path=fn
                        )
                    total_uncompressed += info.file_size

                ratio = total_uncompressed / max(1, compressed_len)
                if total_uncompressed > self.max_decompressed_bytes or ratio > self.max_compression_ratio:
                    return DecompressionResult(
                        is_blocked=self.block_on_violation,
                        violation_code="decompression_bomb_ratio_exceeded",
                        details=f"Zip bomb detected: ratio {ratio:.1f}:1 exceeds threshold ({self.max_compression_ratio}:1) or size {total_uncompressed} bytes.",
                        compression_ratio=ratio,
                        decompressed_bytes=total_uncompressed
                    )
                return DecompressionResult(is_blocked=False, compression_ratio=ratio, decompressed_bytes=total_uncompressed)
        except zipfile.BadZipFile:
            pass

        # 2. Try Gzip Inspection
        if compressed_bytes.startswith(b"\x1f\x8b"):
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(compressed_bytes)) as gz:
                    # Read up to max_decompressed_bytes + 1 chunked
                    chunk_size = 64 * 1024
                    decompressed = bytearray()
                    while True:
                        chunk = gz.read(chunk_size)
                        if not chunk:
                            break
                        decompressed.extend(chunk)
                        if len(decompressed) > self.max_decompressed_bytes:
                            ratio = len(decompressed) / max(1, compressed_len)
                            return DecompressionResult(
                                is_blocked=self.block_on_violation,
                                violation_code="decompression_bomb_size_exceeded",
                                details=f"Gzip expansion exceeds safe byte threshold ({self.max_decompressed_bytes} bytes).",
                                compression_ratio=ratio,
                                decompressed_bytes=len(decompressed)
                            )
                    ratio = len(decompressed) / max(1, compressed_len)
                    if ratio > self.max_compression_ratio and len(decompressed) > 1024:
                        return DecompressionResult(
                            is_blocked=self.block_on_violation,
                            violation_code="decompression_bomb_ratio_exceeded",
                            details=f"Gzip compression ratio {ratio:.1f}:1 exceeds safe bound ({self.max_compression_ratio}:1).",
                            compression_ratio=ratio,
                            decompressed_bytes=len(decompressed)
                        )
                    return DecompressionResult(is_blocked=False, compression_ratio=ratio, decompressed_bytes=len(decompressed))
            except Exception:
                pass

        # 3. Try Raw Zlib Decompression
        try:
            d = zlib.decompressobj()
            decompressed = d.decompress(compressed_bytes, max_length=self.max_decompressed_bytes + 1)
            ratio = len(decompressed) / max(1, compressed_len)
            if len(decompressed) > self.max_decompressed_bytes or (ratio > self.max_compression_ratio and len(decompressed) > 1024):
                return DecompressionResult(
                    is_blocked=self.block_on_violation,
                    violation_code="decompression_bomb_ratio_exceeded",
                    details=f"Zlib expansion ratio {ratio:.1f}:1 or size {len(decompressed)} bytes exceeds threshold.",
                    compression_ratio=ratio,
                    decompressed_bytes=len(decompressed)
                )
            return DecompressionResult(is_blocked=False, compression_ratio=ratio, decompressed_bytes=len(decompressed))
        except Exception:
            pass

        return DecompressionResult(is_blocked=False)

    def inspect_tool_call(self, tool_name: str, parameters: Dict[str, Any]) -> DecompressionResult:
        """Inspects tool call arguments for base64 compressed data."""
        if not parameters or not isinstance(parameters, dict):
            return DecompressionResult(is_blocked=False)

        for key, val in parameters.items():
            if any(k in key.lower() for k in self.ARCHIVE_PARAM_KEYS) and isinstance(val, str):
                try:
                    data = base64.b64decode(val.encode("ascii"), validate=True)
                    res = self.inspect_bytes(data)
                    if res.is_blocked:
                        return res
                except Exception:
                    pass

        return DecompressionResult(is_blocked=False)
