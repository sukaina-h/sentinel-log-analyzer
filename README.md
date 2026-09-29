# Sentinel: Mini SIEM-Style Log Analyzer

A small Python tool that ingests SSH-style authentication logs into SQLite and detects
common attack patterns with SQL-based rules. Each alert is tagged with a severity and a
MITRE ATT&CK technique ID.

## Detections

| Rule | What it looks for | MITRE ATT&CK | Severity |
|------|-------------------|--------------|----------|
| `brute_force` | 5+ failed logins from one IP in 5 min, aimed at few usernames | T1110.001 | medium / high |
| `password_spraying` | One IP failing against 4+ different usernames in 10 min | T1110.003 | high |
| `success_after_failures` | Successful login from an IP with 5+ failures in the prior 15 min | T1078 | critical |
| `off_hours_login` | Successful logins between 00:00 and 05:00 | T1078 | low |

Thresholds are parameters on each function in `sentinel/detections.py`.

## Quick start

```bash
pip install -r requirements.txt          # only needed for tests
python -m sentinel generate --out data/auth.log
python -m sentinel analyze --logfile data/auth.log --report alerts.json
pytest
```

The `generate` command creates a realistic sample log with planted attacks, so no real data is needed.
Use `--report alerts.csv` for CSV output, or `--db events.db` to keep the SQLite database.

## Example output

```
Parsed 78 events (0 unrecognized lines skipped)

5 alert(s) found:

[CRITICAL] success_after_failures   T1078      Successful login as 'dave' from 192.0.2.77 after 8 recent failures; possible account compromise
[HIGH    ] brute_force              T1110.001  25 failed logins from 203.0.113.50 within 5 minutes
[HIGH    ] password_spraying        T1110.003  198.51.100.23 failed against 8 different usernames within 10 minutes
[MEDIUM  ] brute_force              T1110.001  8 failed logins from 192.0.2.77 within 5 minutes
[LOW     ] off_hours_login          T1078      'erin' logged in 1 time(s) between 00:00 and 05:00
```

## How it works

```
auth.log --> parser.py --> Event objects --> db.py (SQLite) --> detections.py (SQL rules) --> reporting.py --> JSON / CSV
```

- `parser.py`: regex parsing, skips malformed lines and counts them
- `db.py`: schema, index on `(src_ip, ts)`, bulk insert
- `detections.py`: sliding-window SQL self-joins to count events per IP
- `cli.py`: `argparse` subcommands (`generate`, `analyze`)
- `tests/`: 12 pytest tests covering the parser and every rule, including edge cases such as below-threshold and outside-window activity

## Design decisions

- **SQL for detection logic** keeps rules readable and mirrors how SIEM queries work.
- **Spraying vs. brute force are separated** by the number of distinct usernames, and overlapping alerts are de-duplicated.
- **Timestamps stored as `YYYY-MM-DD HH:MM:SS`** so SQLite's date functions work directly.

## Limitations and next steps

- Only SSH password events are parsed. Windows Event IDs 4625/4624 would be a natural addition.
- Off-hours detection uses a fixed window rather than a per-user baseline.
- Ideas: threat-intel IP enrichment, GeoIP impossible-travel detection, a small dashboard.
