"""Detection rules. Each rule runs SQL against the events table and returns Alerts."""
import sqlite3
from typing import List

from .models import Alert

T_BRUTE = "T1110.001"   # Brute Force: Password Guessing
T_SPRAY = "T1110.003"   # Brute Force: Password Spraying
T_VALID = "T1078"       # Valid Accounts


def _first_per_ip(rows) -> list:
    """Rows are ordered best-first; keep only the best row for each IP."""
    seen, out = set(), []
    for row in rows:
        if row["src_ip"] not in seen:
            seen.add(row["src_ip"])
            out.append(row)
    return out


def detect_brute_force(conn, threshold=5, window_minutes=5, spray_min_users=4) -> List[Alert]:
    """Many failures from one IP in a short window, aimed at few usernames."""
    rows = conn.execute(
        """
        SELECT a.src_ip AS src_ip,
               a.ts AS start_ts,
               MAX(b.ts) AS end_ts,
               COUNT(*) AS attempts,
               COUNT(DISTINCT b.username) AS users,
               MIN(b.username) AS username
        FROM events a
        JOIN events b
          ON b.src_ip = a.src_ip
         AND b.outcome = 'failed'
         AND b.ts >= a.ts
         AND b.ts < datetime(a.ts, ?)
        WHERE a.outcome = 'failed'
        GROUP BY a.id
        HAVING attempts >= ? AND users < ?
        ORDER BY attempts DESC
        """,
        (f"+{window_minutes} minutes", threshold, spray_min_users),
    ).fetchall()
    return [
        Alert(
            rule="brute_force",
            severity="high" if r["attempts"] >= 20 else "medium",
            mitre_technique=T_BRUTE,
            src_ip=r["src_ip"],
            username=r["username"],
            count=r["attempts"],
            first_seen=r["start_ts"],
            last_seen=r["end_ts"],
            description=f"{r['attempts']} failed logins from {r['src_ip']} within {window_minutes} minutes",
        )
        for r in _first_per_ip(rows)
    ]


def detect_password_spraying(conn, min_users=4, window_minutes=10) -> List[Alert]:
    """One IP failing against many different usernames."""
    rows = conn.execute(
        """
        SELECT a.src_ip AS src_ip,
               a.ts AS start_ts,
               MAX(b.ts) AS end_ts,
               COUNT(*) AS attempts,
               COUNT(DISTINCT b.username) AS users
        FROM events a
        JOIN events b
          ON b.src_ip = a.src_ip
         AND b.outcome = 'failed'
         AND b.ts >= a.ts
         AND b.ts < datetime(a.ts, ?)
        WHERE a.outcome = 'failed'
        GROUP BY a.id
        HAVING users >= ?
        ORDER BY users DESC, attempts DESC
        """,
        (f"+{window_minutes} minutes", min_users),
    ).fetchall()
    return [
        Alert(
            rule="password_spraying",
            severity="high",
            mitre_technique=T_SPRAY,
            src_ip=r["src_ip"],
            username="(multiple)",
            count=r["users"],
            first_seen=r["start_ts"],
            last_seen=r["end_ts"],
            description=f"{r['src_ip']} failed against {r['users']} different usernames within {window_minutes} minutes",
        )
        for r in _first_per_ip(rows)
    ]


def detect_success_after_failures(conn, min_failures=5, lookback_minutes=15) -> List[Alert]:
    """A successful login from an IP that just racked up failures: possible compromise."""
    rows = conn.execute(
        """
        SELECT s.src_ip AS src_ip,
               s.username AS username,
               s.ts AS success_ts,
               MIN(f.ts) AS first_fail,
               COUNT(f.id) AS prior_failures
        FROM events s
        JOIN events f
          ON f.src_ip = s.src_ip
         AND f.outcome = 'failed'
         AND f.ts <= s.ts
         AND f.ts >= datetime(s.ts, ?)
        WHERE s.outcome = 'success'
        GROUP BY s.id
        HAVING prior_failures >= ?
        ORDER BY s.ts
        """,
        (f"-{lookback_minutes} minutes", min_failures),
    ).fetchall()
    return [
        Alert(
            rule="success_after_failures",
            severity="critical",
            mitre_technique=T_VALID,
            src_ip=r["src_ip"],
            username=r["username"],
            count=r["prior_failures"],
            first_seen=r["first_fail"],
            last_seen=r["success_ts"],
            description=(
                f"Successful login as '{r['username']}' from {r['src_ip']} after "
                f"{r['prior_failures']} recent failures; possible account compromise"
            ),
        )
        for r in rows
    ]


def detect_off_hours_logins(conn, start_hour=0, end_hour=5) -> List[Alert]:
    """Successful logins during unusual hours (default 00:00-04:59), grouped by user and IP."""
    rows = conn.execute(
        """
        SELECT username, src_ip, COUNT(*) AS n, MIN(ts) AS first_ts, MAX(ts) AS last_ts
        FROM events
        WHERE outcome = 'success'
          AND CAST(strftime('%H', ts) AS INTEGER) >= ?
          AND CAST(strftime('%H', ts) AS INTEGER) < ?
        GROUP BY username, src_ip
        ORDER BY n DESC
        """,
        (start_hour, end_hour),
    ).fetchall()
    return [
        Alert(
            rule="off_hours_login",
            severity="low",
            mitre_technique=T_VALID,
            src_ip=r["src_ip"],
            username=r["username"],
            count=r["n"],
            first_seen=r["first_ts"],
            last_seen=r["last_ts"],
            description=f"'{r['username']}' logged in {r['n']} time(s) between {start_hour:02d}:00 and {end_hour:02d}:00",
        )
        for r in rows
    ]


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def run_all(conn: sqlite3.Connection) -> List[Alert]:
    spraying = detect_password_spraying(conn)
    spray_ips = {a.src_ip for a in spraying}
    # A spray can look like brute force inside a short slice; don't double-report it.
    brute = [a for a in detect_brute_force(conn) if a.src_ip not in spray_ips]
    alerts = detect_success_after_failures(conn) + spraying + brute + detect_off_hours_logins(conn)
    return sorted(alerts, key=lambda a: (SEVERITY_ORDER[a.severity], a.first_seen))
