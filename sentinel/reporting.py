"""Write alerts to JSON or CSV, and print a readable summary."""
import csv
import json
from typing import List

from .models import Alert

FIELDS = ["rule", "severity", "mitre_technique", "src_ip", "username",
          "count", "first_seen", "last_seen", "description"]


def write_report(alerts: List[Alert], path: str) -> None:
    if path.lower().endswith(".csv"):
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(a.to_dict() for a in alerts)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump([a.to_dict() for a in alerts], fh, indent=2)


def print_summary(alerts: List[Alert]) -> None:
    if not alerts:
        print("No alerts. Nothing suspicious found.")
        return
    print(f"\n{len(alerts)} alert(s) found:\n")
    for a in alerts:
        print(f"[{a.severity.upper():8}] {a.rule:24} {a.mitre_technique:10} {a.description}")
