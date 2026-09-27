"""
Unit tests for DecompressionBombGuard.
Verifies defense against decompression ratio bombs, byte size limit exhaustion, and Zip Slip path traversal.
"""

import base64
import gzip
import io
import pytest
import zipfile
from proxy.guards.decompression_bomb_guard import (
    DecompressionBombGuard,
    DecompressionResult,
)


@pytest.fixture
def decomp_guard():
    return DecompressionBombGuard(max_decompressed_bytes=50000, max_compression_ratio=20.0)


def test_benign_zip_passes(decomp_guard):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("hello.txt", "Hello world, this is a normal test string!")
    res = decomp_guard.inspect_bytes(buf.getvalue())
    assert not res.is_blocked
    assert res.violation_code is None


def test_zip_slip_path_traversal_blocked(decomp_guard):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../etc/shadow", "root:*:0:0:root:/root:/bin/bash")
    res = decomp_guard.inspect_bytes(buf.getvalue())
    assert res.is_blocked
    assert res.violation_code == "zip_slip_path_traversal"
    assert "../../etc/shadow" in res.suspect_path


def test_zip_bomb_ratio_blocked(decomp_guard):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # 100,000 zeros compresses to < 150 bytes (ratio > 500:1)
        zf.writestr("zero.dat", b"0" * 100000)
    res = decomp_guard.inspect_bytes(buf.getvalue())
    assert res.is_blocked
    assert res.violation_code == "decompression_bomb_ratio_exceeded"
    assert res.compression_ratio > 20.0


def test_gzip_bomb_blocked(decomp_guard):
    # Highly compressible stream
    data = b"A" * 80000
    compressed = gzip.compress(data)
    res = decomp_guard.inspect_bytes(compressed)
    assert res.is_blocked
    assert res.violation_code in ("decompression_bomb_size_exceeded", "decompression_bomb_ratio_exceeded")


def test_tool_call_inspection(decomp_guard):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../../Windows/System32/evil.dll", "malicious payload")
    b64_zip = base64.b64encode(buf.getvalue()).decode("ascii")

    params = {"archive": b64_zip, "dest": "/tmp/out"}
    res = decomp_guard.inspect_tool_call("extract_archive", params)
    assert res.is_blocked
    assert res.violation_code == "zip_slip_path_traversal"
