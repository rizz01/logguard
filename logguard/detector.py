"""Detection rules: brute force, password spraying, success-after-failures."""
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Iterable, List

from .parser import Event

SPRAY_USERS = 5  # distinct usernames (ssh) or paths (web) from one IP that suggests spraying/scanning
MODES = {
    "ssh": ("usernames", "possible password spraying", "failures"),
    "web": ("paths", "possible scanning or forced browsing", "error responses"),
}


@dataclass
class Alert:
    ip: str
    severity: str
    failures: int
    peak_in_window: int
    distinct_users: int
    first_seen: datetime
    last_seen: datetime
    possible_compromise: bool
    users_tried: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)


def _peak_in_window(times: List[datetime], window: timedelta) -> int:
    """Largest number of failures inside any sliding window (two pointers)."""
    best, left = 0, 0
    for right, t in enumerate(times):
        while t - times[left] > window:
            left += 1
        best = max(best, right - left + 1)
    return best


def analyze(events: Iterable[Event], threshold: int = 5, window_seconds: int = 60, mode: str = "ssh") -> List[Alert]:
    if mode not in MODES:
        raise ValueError(f"unknown mode: {mode}")
    subject, spray_note, noun = MODES[mode]
    if threshold < 1 or window_seconds < 1:
        raise ValueError("threshold and window_seconds must be >= 1")
    window = timedelta(seconds=window_seconds)
    fails: Dict[str, List[Event]] = defaultdict(list)
    successes: Dict[str, List[Event]] = defaultdict(list)
    for e in sorted(events, key=lambda e: e.timestamp):
        (successes if e.success else fails)[e.ip].append(e)

    alerts: List[Alert] = []
    for ip, fl in fails.items():
        times = [e.timestamp for e in fl]
        peak = _peak_in_window(times, window)
        users = sorted({e.user for e in fl})
        spray = len(users) >= SPRAY_USERS
        if peak < threshold and not spray:
            continue
        # A success after the first burst means the attacker may have got in.
        burst_start = times[0]
        compromised = any(s.timestamp >= burst_start for s in successes.get(ip, []))
        reasons = []
        if peak >= threshold:
            reasons.append(f"{peak} {noun} within {window_seconds}s (threshold {threshold})")
        if spray:
            reasons.append(f"{len(users)} different {subject} tried ({spray_note})")
        if compromised:
            reasons.append("successful login after failed attempts: investigate this account")
        severity = "HIGH" if compromised or peak >= 3 * threshold else "MEDIUM"
        alerts.append(Alert(ip, severity, len(fl), peak, len(users), times[0], times[-1],
                            compromised, users, reasons))
    order = {"HIGH": 0, "MEDIUM": 1}
    return sorted(alerts, key=lambda a: (order[a.severity], -a.failures))
