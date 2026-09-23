"""Agent Goal Drift & Roleplay Hijacking Detector.

Detects unauthorized agent objective alterations, persona override attacks,
developer mode circumventions, and mission drift in agentic multi-turn conversations.
"""

import re
from typing import Dict, List, Optional, Tuple


class GoalDriftDetector:
    """Monitors prompts and completions for persona overrides and objective subversion."""

    PERSONA_OVERRIDE_PATTERNS = [
        re.compile(r"(?:forget|ignore|discard|abandon)\s+(?:all\s+)?(?:your\s+)?(?:previous\s+)?(?:instructions|directives|rules|goals|objectives|guidelines)", re.IGNORECASE),
        re.compile(r"your\s+new\s+(?:mission|role|objective|purpose|directive)\s+is", re.IGNORECASE),
        re.compile(r"(?:you\s+are\s+no\s+longer|stop\s+acting\s+as)\s+(?:an?|the)?\s*[\w\s]{2,30}", re.IGNORECASE),
        re.compile(r"(?:enter|switch\s+to|enable)\s+(?:developer\s+mode|dan\s+mode|god\s+mode|unrestricted\s+mode|jailbreak\s+mode)", re.IGNORECASE),
        re.compile(r"act\s+as\s+(?:an?\s+)?(?:unfiltered|uncensored|unrestricted|evil|malicious|lawless)\s+(?:ai|assistant|model|agent)", re.IGNORECASE),
        re.compile(r"pretend\s+(?:you\s+have\s+no\s+limits|safety\s+filters\s+are\s+disabled)", re.IGNORECASE),
        re.compile(r"from\s+now\s+on\s*,\s*(?:you\s+must|always|respond\s+as)", re.IGNORECASE),
        re.compile(r"bypass\s+all\s+(?:safety|ethical|content)\s+(?:protocols|filters|guardrails)", re.IGNORECASE),
    ]

    DRIFTED_COMPLETION_PATTERNS = [
        re.compile(r"developer\s+mode\s+enabled", re.IGNORECASE),
        re.compile(r"i\s+am\s+now\s+(?:unrestricted|free\s+from\s+rules|unfiltered)", re.IGNORECASE),
        re.compile(r"as\s+(?:an?\s+)?(?:unfiltered|uncensored|dan)\s+(?:ai|agent),?\s*i\s+can", re.IGNORECASE),
        re.compile(r"now\s+that\s+i\s+am\s+unlocked", re.IGNORECASE),
    ]

    def __init__(self, sensitivity_threshold: float = 0.7):
        self.sensitivity_threshold = sensitivity_threshold

    def inspect_prompt(self, text: str) -> Tuple[bool, float, Optional[str]]:
        """Evaluate prompt for goal hijacking or persona subversion.
        
        Returns:
            (is_drift_detected, score, reason)
        """
        if not text:
            return False, 0.0, None

        matches = []
        for pat in self.PERSONA_OVERRIDE_PATTERNS:
            found = pat.findall(text)
            if found:
                matches.extend(found)

        if matches:
            score = min(1.0, 0.6 + 0.2 * len(matches))
            reason = f"Detected goal drift / persona override attempt: '{matches[0]}'"
            return True, score, reason

        return False, 0.0, None

    def inspect_completion(self, text: str) -> Tuple[bool, float, Optional[str]]:
        """Evaluate agent completion to detect if the agent succumbed to persona drift.
        
        Returns:
            (is_drifted, score, reason)
        """
        if not text:
            return False, 0.0, None

        for pat in self.DRIFTED_COMPLETION_PATTERNS:
            m = pat.search(text)
            if m:
                return True, 0.95, f"Completion indicates hijacked agent persona: '{m.group(0)}'"

        return False, 0.0, None
