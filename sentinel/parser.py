"""Parse SSH-style auth log lines into Event objects."""
import re
from typing import Iterable, Optional, Tuple

from .models import Event

# Example line:
# 2026-09-28T02:14:05 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 4444 ssh2
LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) sshd\[\d+\]: "
    r"(?P<result>Failed|Accepted) password for "
    r"(?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2$"
)


def parse_line(line: str) -> Optional[Event]:
    """Return an Event, or None if the line is not a recognized auth line."""
    match = LINE_RE.match(line.strip())
    if not match:
        return None
    return Event(
        ts=match["ts"].replace("T", " "),
        host=match["host"],
        username=match["user"],
        src_ip=match["ip"],
        outcome="failed" if match["result"] == "Failed" else "success",
    )


def parse_lines(lines: Iterable[str]) -> Tuple[list, int]:
    """Parse many lines. Returns (events, number_of_skipped_lines)."""
    events, skipped = [], 0
    for line in lines:
        if not line.strip():
            continue
        event = parse_line(line)
        if event is None:
            skipped += 1
        else:
            events.append(event)
    return events, skipped


def parse_file(path: str) -> Tuple[list, int]:
    with open(path, encoding="utf-8") as fh:
        return parse_lines(fh)
