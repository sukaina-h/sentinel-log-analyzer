"""Data structures shared across the project."""
from dataclasses import dataclass, asdict


@dataclass
class Event:
    """One parsed authentication event."""
    ts: str          # 'YYYY-MM-DD HH:MM:SS' (SQLite-friendly)
    host: str
    username: str
    src_ip: str
    outcome: str     # 'failed' or 'success'


@dataclass
class Alert:
    """A detection result."""
    rule: str
    severity: str    # low | medium | high | critical
    mitre_technique: str
    src_ip: str
    username: str
    count: int
    first_seen: str
    last_seen: str
    description: str

    def to_dict(self) -> dict:
        return asdict(self)
