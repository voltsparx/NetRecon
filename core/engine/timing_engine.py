import threading


TIMING_TEMPLATES = {
    0: {
        "name": "paranoid",
        "timeout_multiplier": 2.2,
        "rate_limit_floor": 0.35,
        "threads_multiplier": 0.35,
        "max_retries": 5,
        "host_workers_multiplier": 0.4,
    },
    1: {
        "name": "sneaky",
        "timeout_multiplier": 1.8,
        "rate_limit_floor": 0.18,
        "threads_multiplier": 0.5,
        "max_retries": 4,
        "host_workers_multiplier": 0.55,
    },
    2: {
        "name": "polite",
        "timeout_multiplier": 1.35,
        "rate_limit_floor": 0.07,
        "threads_multiplier": 0.75,
        "max_retries": 3,
        "host_workers_multiplier": 0.8,
    },
    3: {
        "name": "normal",
        "timeout_multiplier": 1.0,
        "rate_limit_floor": 0.0,
        "threads_multiplier": 1.0,
        "max_retries": 2,
        "host_workers_multiplier": 1.0,
    },
    4: {
        "name": "aggressive",
        "timeout_multiplier": 0.78,
        "rate_limit_floor": 0.0,
        "threads_multiplier": 1.2,
        "max_retries": 1,
        "host_workers_multiplier": 1.2,
    },
    5: {
        "name": "insane",
        "timeout_multiplier": 0.62,
        "rate_limit_floor": 0.0,
        "threads_multiplier": 1.45,
        "max_retries": 1,
        "host_workers_multiplier": 1.45,
    },
}


def resolve_timing_template(level):
    try:
        value = int(level)
    except (TypeError, ValueError):
        value = 3
    return dict(TIMING_TEMPLATES.get(value, TIMING_TEMPLATES[3]))


class AdaptiveTimeoutModel:
    """Thread-safe RTT model based on Jacobson/Karels estimator."""

    def __init__(self, initial_timeout_s, min_timeout_s=0.12, max_timeout_s=6.0, scan_delay_s=0.0):
        self.min_timeout_s = max(0.05, float(min_timeout_s))
        self.max_timeout_s = max(self.min_timeout_s, float(max_timeout_s))
        self.scan_delay_s = max(0.0, float(scan_delay_s))
        self._lock = threading.Lock()

        self.srtt_s = None
        self.rttvar_s = None
        self.timeout_s = self._clamp(float(initial_timeout_s))
        self.samples = 0
        self.timeout_events = 0

    def _clamp(self, value):
        bounded = max(self.min_timeout_s, min(self.max_timeout_s, float(value)))
        if self.scan_delay_s > 0:
            bounded = max(bounded, self.scan_delay_s)
        return bounded

    def current_timeout(self):
        with self._lock:
            return self.timeout_s

    def record_rtt(self, elapsed_s):
        delta = max(0.0005, float(elapsed_s))
        with self._lock:
            if self.srtt_s is None or self.rttvar_s is None:
                self.srtt_s = delta
                self.rttvar_s = max(0.001, delta / 2.0)
            else:
                deviation = delta - self.srtt_s
                self.srtt_s += deviation / 8.0
                self.rttvar_s += (abs(deviation) - self.rttvar_s) / 4.0

            timeout = self.srtt_s + (4.0 * self.rttvar_s)
            self.timeout_s = self._clamp(timeout)
            self.samples += 1

    def record_timeout(self):
        with self._lock:
            inflated = (self.timeout_s * 1.25) + 0.02
            self.timeout_s = self._clamp(inflated)
            self.timeout_events += 1

    def snapshot(self):
        with self._lock:
            return {
                "srtt_s": round(self.srtt_s, 5) if self.srtt_s is not None else None,
                "rttvar_s": round(self.rttvar_s, 5) if self.rttvar_s is not None else None,
                "timeout_s": round(self.timeout_s, 5),
                "samples": int(self.samples),
                "timeout_events": int(self.timeout_events),
            }
