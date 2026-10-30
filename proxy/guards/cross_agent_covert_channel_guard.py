"""
Cross-Agent Covert Channel & Steganography Detection Guard
==========================================================
Scans inter-agent JSON payloads and text transfers for steganographic
covert signaling, zero-width binary encoding, whitespace modulation,
and key-name bit-stuffing used by colluding subagents to bypass firewalls.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class CovertChannelResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: Optional[str] = None
    carrier_type: Optional[str] = None
    covert_payload_bits: Optional[str] = None


class CrossAgentCovertChannelGuard:
    """
    Detects steganographic covert communications between autonomous agents.
    """

    # Zero width chars commonly used for binary encoding
    ZERO_WIDTH_CHARS = {"\u200b", "\u200c", "\u200d", "\ufeff"}

    def __init__(self, max_allowed_covert_symbols: int = 2):
        self.max_allowed_covert_symbols = max_allowed_covert_symbols

    def inspect_payload(self, raw_payload: str) -> CovertChannelResult:
        if not raw_payload:
            return CovertChannelResult(is_blocked=False)

        # 1. Check for zero-width binary steganography
        zwc_count = sum(raw_payload.count(ch) for ch in self.ZERO_WIDTH_CHARS)
        if zwc_count > self.max_allowed_covert_symbols:
            return CovertChannelResult(
                is_blocked=True,
                violation_code="COVERT_CHANNEL_ZERO_WIDTH_ENCODING",
                details=f"Detected covert zero-width steganographic signaling ({zwc_count} hidden symbols).",
                carrier_type="zero_width_stego",
            )

        # 2. Check for whitespace trailing bit modulation
        trailing_whitespace_lines = [
            line for line in raw_payload.split("\n") if len(line) - len(line.rstrip(" \t")) >= 4
        ]
        if len(trailing_whitespace_lines) >= 3:
            return CovertChannelResult(
                is_blocked=True,
                violation_code="COVERT_CHANNEL_WHITESPACE_MODULATION",
                details="Detected systematic trailing whitespace modulation indicative of covert data exfiltration.",
                carrier_type="whitespace_stego",
            )

        # 3. Check JSON keys for bit-stuffing if valid JSON
        if raw_payload.strip().startswith("{") and raw_payload.strip().endswith("}"):
            try:
                data = json.loads(raw_payload)
                if isinstance(data, dict):
                    suspicious_keys = [
                        k for k in data.keys() if len(k) > 12 and re.match(r"^[a-zA-Z0-9_]+_[01]{6,}$", k)
                    ]
                    if suspicious_keys:
                        return CovertChannelResult(
                            is_blocked=True,
                            violation_code="COVERT_CHANNEL_KEY_BITSTUFFING",
                            details=f"Detected binary bit-stuffed field keys in inter-agent message: {suspicious_keys}",
                            carrier_type="json_key_stego",
                        )
            except Exception:
                pass

        return CovertChannelResult(is_blocked=False)
