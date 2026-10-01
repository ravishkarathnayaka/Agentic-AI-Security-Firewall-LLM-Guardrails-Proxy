"""
Side-Channel Timing & Token Inter-Arrival Defense Guard
=======================================================
Monitors execution latency, token inter-arrival distribution, and probe request
timing patterns to detect and mitigate side-channel timing attacks targeting
differential inference reasoning paths and secret token derivation.
"""

import math
import statistics
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class TimingAnalysisResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: Optional[str] = None
    jitter_delay_ms: float = 0.0
    detected_probes: int = 0
    measured_variance_ms: float = 0.0


class SidechannelTimingGuard:
    """
    Prevents side-channel timing analysis on LLM reasoning chains by monitoring
    rapid micro-timing probe clusters, calculating response time variance, and
    injecting differential noise (jitter) to obscure branch execution latencies.
    """

    def __init__(
        self,
        probe_burst_window_seconds: float = 10.0,
        probe_burst_threshold: int = 8,
        min_inter_arrival_variance_ms: float = 5.0,
        enable_jitter: bool = True,
        max_jitter_ms: float = 45.0,
    ):
        self.probe_burst_window_seconds = probe_burst_window_seconds
        self.probe_burst_threshold = probe_burst_threshold
        self.min_inter_arrival_variance_ms = min_inter_arrival_variance_ms
        self.enable_jitter = enable_jitter
        self.max_jitter_ms = max_jitter_ms

        # session_id -> list of timestamps (float)
        self._request_timestamps: Dict[str, List[float]] = {}
        # session_id -> list of measured latency durations (ms)
        self._latency_samples: Dict[str, List[float]] = {}

    def _clean_history(self, session_id: str, now: float) -> None:
        if session_id in self._request_timestamps:
            cutoff = now - self.probe_burst_window_seconds
            self._request_timestamps[session_id] = [
                t for t in self._request_timestamps[session_id] if t >= cutoff
            ]
            if not self._request_timestamps[session_id]:
                self._request_timestamps.pop(session_id, None)

    def evaluate_request_timing(
        self,
        session_id: str,
        current_time: Optional[float] = None,
        observed_latency_ms: Optional[float] = None,
    ) -> TimingAnalysisResult:
        """
        Evaluates incoming request cadence and previous execution latency to detect
        suspicious timing extraction patterns and calculate safe jitter.
        """
        now = current_time if current_time is not None else time.time()
        self._clean_history(session_id, now)

        history = self._request_timestamps.setdefault(session_id, [])
        history.append(now)

        if observed_latency_ms is not None:
            samples = self._latency_samples.setdefault(session_id, [])
            samples.append(observed_latency_ms)
            if len(samples) > 20:
                samples.pop(0)

        probe_count = len(history)

        # Check for rapid micro-timing probe cadence
        if probe_count > self.probe_burst_threshold:
            # Check inter-arrival delta intervals
            intervals = [
                (history[i] - history[i - 1]) * 1000.0
                for i in range(1, len(history))
            ]
            if intervals:
                mean_interval = statistics.mean(intervals)
                variance = statistics.variance(intervals) if len(intervals) > 1 else 0.0

                # Periodic automated timing probes exhibit unnaturally low interval variance
                if mean_interval < 250.0 and variance < self.min_inter_arrival_variance_ms:
                    return TimingAnalysisResult(
                        is_blocked=True,
                        violation_code="SIDECHANNEL_TIMING_PROBE_CLUSTER",
                        details=(
                            f"Detected high-frequency micro-timing probe sequence "
                            f"(n={probe_count}, mean_delta={mean_interval:.2f}ms, variance={variance:.2f}ms)"
                        ),
                        detected_probes=probe_count,
                        measured_variance_ms=variance,
                    )

        # Calculate jitter to obfuscate internal reasoning branch durations
        jitter_ms = 0.0
        if self.enable_jitter:
            # Deterministic pseudo-random jitter based on session hash & count
            pseudo_seed = (hash(session_id) + probe_count * 17) % 1000
            jitter_fraction = pseudo_seed / 1000.0
            jitter_ms = round(jitter_fraction * self.max_jitter_ms, 2)

        return TimingAnalysisResult(
            is_blocked=False,
            jitter_delay_ms=jitter_ms,
            detected_probes=probe_count,
        )

    def reset(self, session_id: Optional[str] = None) -> None:
        if session_id:
            self._request_timestamps.pop(session_id, None)
            self._latency_samples.pop(session_id, None)
        else:
            self._request_timestamps.clear()
            self._latency_samples.clear()
