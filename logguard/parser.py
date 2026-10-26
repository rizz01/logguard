"""Parse OpenSSH entries from Linux auth logs (syslog format)."""
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator, Optional

_TS = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})")
_FAIL = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9A-Fa-f.:]+) port \d+"
)
_OK = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>[0-9A-Fa-f.:]+) port \d+"
)


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    ip: str
    user: str
    success: bool


def parse_line(line: str, year: int) -> Optional[Event]:
    """Return an Event for a login attempt line, or None if it is not one."""
    ts = _TS.match(line)
    if not ts:
        return None
    for pattern, ok in ((_FAIL, False), (_OK, True)):
        m = pattern.search(line)
        if m:
            when = datetime.strptime(
                f"{year} {ts['mon']} {int(ts['day'])} {ts['time']}", "%Y %b %d %H:%M:%S"
            )
            return Event(when, m["ip"], m["user"], ok)
    return None


def parse_lines(lines: Iterable[str], year: int) -> Iterator[Event]:
    for line in lines:
        event = parse_line(line, year)
        if event:
            yield event


# ---- web server access logs (nginx / Apache "combined" format) ----
_WEB = re.compile(
    r'^(?P<ip>[0-9A-Fa-f.:]+) \S+ \S+ \[(?P<ts>\S+)(?: [+-]\d{4})?\] '
    r'"[A-Z]+ (?P<path>\S+)[^"]*" (?P<status>\d{3})'
)
WEB_BAD_STATUS = {401, 403, 404}  # unauthorised, forbidden, not found


def parse_web_line(line: str) -> Optional[Event]:
    """Return an Event for a 401/403/404 request, or None for anything else."""
    m = _WEB.match(line)
    if not m or int(m["status"]) not in WEB_BAD_STATUS:
        return None
    try:
        when = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None
    return Event(when, m["ip"], m["path"].split("?")[0], False)


def parse_web_lines(lines: Iterable[str]) -> Iterator[Event]:
    for line in lines:
        event = parse_web_line(line)
        if event:
            yield event
