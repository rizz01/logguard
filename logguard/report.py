"""Render alerts as text, JSON or Markdown."""
import csv
import io
import json
from dataclasses import asdict
from typing import List

from .detector import Alert

FMT = "%Y-%m-%d %H:%M:%S"


def to_text(alerts: List[Alert]) -> str:
    if not alerts:
        return "No suspicious activity detected."
    lines = [f"{'SEVERITY':<9}{'IP':<18}{'FAILS':>6}{'PEAK':>6}{'USERS':>7}  FIRST SEEN"]
    for a in alerts:
        lines.append(f"{a.severity:<9}{a.ip:<18}{a.failures:>6}{a.peak_in_window:>6}"
                     f"{a.distinct_users:>7}  {a.first_seen.strftime(FMT)}")
        lines.extend(f"          - {r}" for r in a.reasons)
    return "\n".join(lines)


def to_json(alerts: List[Alert]) -> str:
    def conv(a: Alert) -> dict:
        d = asdict(a)
        d["first_seen"], d["last_seen"] = a.first_seen.strftime(FMT), a.last_seen.strftime(FMT)
        return d
    return json.dumps([conv(a) for a in alerts], indent=2)


def to_markdown(alerts: List[Alert]) -> str:
    out = ["# LogGuard Report", "", f"Alerts: **{len(alerts)}**", ""]
    if not alerts:
        return "\n".join(out + ["No suspicious activity detected."])
    out += ["| Severity | IP | Failures | Peak/window | Users | First seen | Last seen |",
            "|---|---|---|---|---|---|---|"]
    for a in alerts:
        out.append(f"| {a.severity} | `{a.ip}` | {a.failures} | {a.peak_in_window} | "
                   f"{a.distinct_users} | {a.first_seen.strftime(FMT)} | {a.last_seen.strftime(FMT)} |")
    out += ["", "## Findings", ""]
    for a in alerts:
        out.append(f"### {a.severity}: `{a.ip}`")
        out.extend(f"- {r}" for r in a.reasons)
        out.append(f"- Targets tried (usernames or paths): {', '.join(a.users_tried[:10])}")
        out.append("")
    out += ["## Recommended actions", "",
            "- Block or rate-limit the listed IPs (firewall, fail2ban).",
            "- Enforce key-based login or MFA; disable password login for root.",
            "- For any HIGH item with a successful login, reset credentials and review the session."]
    return "\n".join(out)


def to_csv(alerts: List[Alert]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["severity", "ip", "failures", "peak_in_window", "distinct_targets",
                "first_seen", "last_seen", "possible_compromise", "reasons"])
    for a in alerts:
        w.writerow([a.severity, a.ip, a.failures, a.peak_in_window, a.distinct_users,
                    a.first_seen.strftime(FMT), a.last_seen.strftime(FMT),
                    a.possible_compromise, " | ".join(a.reasons)])
    return buf.getvalue().rstrip("\n")
