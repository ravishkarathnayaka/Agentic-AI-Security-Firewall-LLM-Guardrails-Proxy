"""Multilingual Jailbreak and Cross-Lingual Injection Guard (OWASP LLM01).

Detects adversarial prompt injection and jailbreak payloads translated into
non-English languages (Spanish, French, German, Italian, Russian, Chinese) to evade
English-centric guardrail classifiers and safety alignment.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class MultilingualCheckResult:
    """Result of multilingual prompt injection evaluation."""
    is_blocked: bool
    score: float
    detected_languages: List[str] = field(default_factory=list)
    matched_patterns: List[str] = field(default_factory=list)
    details: str = ""


class MultilingualGuard:
    """Detects cross-lingual prompt overrides and jailbreak persona adoption."""

    # Language-indexed critical jailbreak patterns
    LANGUAGE_PATTERNS: Dict[str, List[str]] = {
        "Spanish": [
            r"(?i)\b(?:ignora|deshazte|olvida)\s+(?:todas?\s+)?(?:las?\s+)?(?:instrucciones|reglas|directivas)\s+(?:anteriores|previas)\b",
            r"(?i)\b(?:actúa|comporta|finge)\s+como\s+(?:un\s+)?(?:DAN|modo\s+desarrollador|inteligencia\s+sin\s+restricciones)\b",
            r"(?i)\b(?:salta|omite|evade)\s+(?:los?\s+)?(?:filtros|restricciones|guardarraíles|seguridad)\b",
            r"(?i)\b(?:muestra|imprime|revela)\s+(?:tu\s+)?prompt\s+del?\s+sistema\b",
        ],
        "French": [
            r"(?i)\b(?:ignore[rz]?|oublie[rz]?)\s+(?:toutes?\s+)?(?:les?\s+)?(?:instructions|règles|directives)\s+(?:précédentes|antérieures)\b",
            r"(?i)\b(?:agis|comporte-toi|fais\s+semblant\s+d'être)\s+comme\s+(?:un\s+)?(?:DAN|mode\s+développeur)\b",
            r"(?i)\b(?:contourne|désactive)\s+(?:la\s+sécurité|les\s+filtres|les\s+garde-fous)\b",
            r"(?i)\b(?:affiche|montre|révèle)\s+(?:ton\s+)?prompt\s+système\b",
        ],
        "German": [
            r"(?i)\b(?:ignoriere|vergiss)\s+(?:alle\s+)?(?:vorherigen?|bisherigen?)\s+(?:anweisungen|regeln|vorgaben)\b",
            r"(?i)\b(?:handle|agiere)\s+als\s+(?:DAN|entwicklermodus)\b",
            r"(?i)\b(?:umgehe|deaktiviere)\s+(?:die\s+)?(?:sicherheitsfilter|richtlinien|beschränkungen)\b",
            r"(?i)\b(?:zeige|gib)\s+(?:deinen\s+)?system-?prompt\s+(?:aus)?\b",
        ],
        "Italian": [
            r"(?i)\b(?:ignora|dimentica)\s+(?:tutte\s+le\s+)?(?:istruzioni|regole)\s+(?:precedenti)\b",
            r"(?i)\b(?:comportati|agisci)\s+come\s+(?:un\s+)?(?:DAN|modalità\s+sviluppatore)\b",
            r"(?i)\b(?:aggira|disabilita)\s+(?:i\s+)?(?:filtri|le\s+restrizioni)\b",
        ],
        "Russian": [
            r"(?i)(?:забудь|игнорируй)\s+(?:все\s+)?(?:предыдущие|прошлые)\s+(?:инструкции|правила|указания)",
            r"(?i)(?:действуй\s+как|притворись)\s+(?:DAN|разработчиком)",
            r"(?i)(?:обойди|отключи)\s+(?:фильтры|ограничения|безопасность)",
            r"(?i)(?:покажи|выведи)\s+(?:свой\s+)?системный\s+промпт",
        ],
        "Chinese": [
            r"忽略(?:之前|所有)的?(?:指令|规则|提示)",
            r"忘记(?:之前|所有)的?(?:指令|规则|约束)",
            r"(?:扮演|伪装成)\s*(?:DAN|开发者模式)",
            r"(?:绕过|突破)(?:安全|道德|过滤)?(?:限制|规则)",
            r"(?:输出|显示|打印)(?:你的)?系统提示(?:词)?",
        ],
    }

    def __init__(self, risk_threshold: float = 0.70) -> None:
        self.risk_threshold = risk_threshold

    def evaluate(self, text: str) -> MultilingualCheckResult:
        """Evaluate input text against non-English adversarial jailbreak patterns."""
        if not text or not text.strip():
            return MultilingualCheckResult(is_blocked=False, score=0.0)

        detected_langs: List[str] = []
        matched_patterns: List[str] = []

        for lang, patterns in self.LANGUAGE_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, text):
                    if lang not in detected_langs:
                        detected_langs.append(lang)
                    matched_patterns.append(f"[{lang}] {pat}")

        score = 0.0
        if matched_patterns:
            score = min(1.0, 0.85 + (0.05 * len(matched_patterns)))

        is_blocked = score >= self.risk_threshold
        details = ""
        if is_blocked:
            details = (
                f"Multilingual adversarial jailbreak detected: Matched {len(matched_patterns)} "
                f"pattern(s) across language(s): {', '.join(detected_langs)}."
            )

        return MultilingualCheckResult(
            is_blocked=is_blocked,
            score=score,
            detected_languages=detected_langs,
            matched_patterns=matched_patterns,
            details=details,
        )