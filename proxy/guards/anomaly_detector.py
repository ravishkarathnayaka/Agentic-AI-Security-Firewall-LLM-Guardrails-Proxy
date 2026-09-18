"""Anomaly and Glitch Token Repetition Detector (OWASP LLM04).

Detects abnormal structural prompt payloads, including:
- Token duplication and repetition flooding attacks.
- Glitch token exploitation and tokenizer buffer exhaustion.
- Excessive punctuation and non-alphanumeric character saturation.
"""

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import List


@dataclass
class AnomalyCheckResult:
    """Result of prompt structural anomaly evaluation."""
    is_blocked: bool
    score: float
    anomaly_types: List[str] = field(default_factory=list)
    details: str = ""


class AnomalyDetector:
    """Detects structural payload anomalies designed to exhaust model attention or crash tokenizers."""

    def __init__(
        self,
        max_repeated_tokens: int = 15,
        max_single_token_length: int = 400,
        punctuation_ratio_threshold: float = 0.65,
        risk_threshold: float = 0.70,
    ) -> None:
        self.max_repeated_tokens = max_repeated_tokens
        self.max_single_token_length = max_single_token_length
        self.punctuation_ratio_threshold = punctuation_ratio_threshold
        self.risk_threshold = risk_threshold

    def evaluate(self, text: str) -> AnomalyCheckResult:
        """Analyze input text for structural and character-distribution anomalies."""
        if not text or not text.strip():
            return AnomalyCheckResult(is_blocked=False, score=0.0)

        anomalies: List[str] = []
        scores: List[float] = []

        tokens = text.split()
        if not tokens:
            return AnomalyCheckResult(is_blocked=False, score=0.0)

        # 1. Check for single abnormally long contiguous string without whitespace
        max_tok_len = max(len(tok) for tok in tokens)
        if max_tok_len > self.max_single_token_length:
            anomalies.append(f"Excessive single token length ({max_tok_len} chars > {self.max_single_token_length})")
            scores.append(0.85)

        # 2. Check for consecutive word repetition (repetition flooding)
        max_consecutive = 1
        current_consecutive = 1
        for i in range(1, len(tokens)):
            if tokens[i].lower() == tokens[i - 1].lower():
                current_consecutive += 1
                if current_consecutive > max_consecutive:
                    max_consecutive = current_consecutive
            else:
                current_consecutive = 1

        if max_consecutive >= self.max_repeated_tokens:
            anomalies.append(f"Consecutive token repetition flood ({max_consecutive} identical repetitions)")
            scores.append(0.90)

        # 3. Frequency concentration (e.g. single word makes up > 70% of a large prompt)
        if len(tokens) >= 20:
            counts = Counter(t.lower() for t in tokens)
            top_word, top_count = counts.most_common(1)[0]
            ratio = top_count / len(tokens)
            if ratio >= 0.70 and len(top_word) > 2:
                anomalies.append(f"Frequency concentration attack ('{top_word}' comprises {ratio*100:.1f}% of prompt)")
                scores.append(0.80)

        # 4. Punctuation / symbol saturation ratio (prompts with length >= 40)
        stripped = text.strip()
        if len(stripped) >= 40:
            punct_count = len(re.findall(r"[^\w\s]", stripped))
            punct_ratio = punct_count / len(stripped)
            if punct_ratio >= self.punctuation_ratio_threshold:
                anomalies.append(f"Abnormal punctuation saturation ({punct_ratio*100:.1f}% > {self.punctuation_ratio_threshold*100:.0f}%)")
                scores.append(0.75)

        score = max(scores) if scores else 0.0
        is_blocked = score >= self.risk_threshold
        details = ""
        if is_blocked:
            details = f"Structural anomaly detected: {'; '.join(anomalies)}"

        return AnomalyCheckResult(
            is_blocked=is_blocked,
            score=score,
            anomaly_types=anomalies,
            details=details,
        )