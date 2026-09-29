from datetime import datetime, timedelta

from sentinel import db, detections
from sentinel.models import Event
from sentinel.parser import parse_line, parse_lines


def make_conn(events):
    conn = db.connect(":memory:")
    db.insert_events(conn, events)
    return conn


def ev(minute_offset, user, ip, outcome, hour=12, sec=0):
    ts = datetime(2026, 9, 28, hour, 0, 0) + timedelta(minutes=minute_offset, seconds=sec)
    return Event(ts.strftime("%Y-%m-%d %H:%M:%S"), "web01", user, ip, outcome)


# ---------- parser ----------
def test_parse_failed_invalid_user():
    line = "2026-09-28T02:14:05 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 4444 ssh2"
    e = parse_line(line)
    assert e.ts == "2026-09-28 02:14:05"
    assert (e.username, e.src_ip, e.outcome) == ("admin", "203.0.113.5", "failed")


def test_parse_accepted():
    line = "2026-09-28T09:00:00 db01 sshd[9]: Accepted password for alice from 10.0.0.10 port 5000 ssh2"
    assert parse_line(line).outcome == "success"


def test_parse_skips_garbage():
    events, skipped = parse_lines(["not a log line", "", "also junk"])
    assert events == [] and skipped == 2


# ---------- brute force ----------
def test_brute_force_detected():
    events = [ev(0, "root", "1.1.1.1", "failed", sec=i * 5) for i in range(6)]
    alerts = detections.detect_brute_force(make_conn(events))
    assert len(alerts) == 1
    assert alerts[0].src_ip == "1.1.1.1" and alerts[0].count == 6


def test_brute_force_below_threshold_ignored():
    events = [ev(0, "root", "1.1.1.1", "failed", sec=i) for i in range(4)]
    assert detections.detect_brute_force(make_conn(events)) == []


def test_brute_force_outside_window_ignored():
    # 6 failures, but spread 10 minutes apart: never 5 inside a 5-minute window
    events = [ev(i * 10, "root", "1.1.1.1", "failed") for i in range(6)]
    assert detections.detect_brute_force(make_conn(events)) == []


# ---------- password spraying ----------
def test_spraying_detected_and_not_labelled_brute_force():
    names = ["a", "b", "c", "d", "e"]
    events = [ev(0, n, "2.2.2.2", "failed", sec=i * 10) for i, n in enumerate(names)]
    conn = make_conn(events)
    spray = detections.detect_password_spraying(conn)
    assert len(spray) == 1 and spray[0].count == 5
    assert detections.detect_brute_force(conn, threshold=5) == []


# ---------- success after failures ----------
def test_success_after_failures_is_critical():
    events = [ev(0, "dave", "3.3.3.3", "failed", sec=i * 5) for i in range(6)]
    events.append(ev(2, "dave", "3.3.3.3", "success"))
    alerts = detections.detect_success_after_failures(make_conn(events))
    assert len(alerts) == 1 and alerts[0].severity == "critical"


def test_normal_success_no_alert():
    events = [ev(0, "alice", "10.0.0.10", "failed"), ev(1, "alice", "10.0.0.10", "success")]
    assert detections.detect_success_after_failures(make_conn(events)) == []


# ---------- off hours ----------
def test_off_hours_login_flagged_only_at_night():
    events = [ev(0, "erin", "10.0.0.14", "success", hour=2),
              ev(0, "erin", "10.0.0.14", "success", hour=13)]
    alerts = detections.detect_off_hours_logins(make_conn(events))
    assert len(alerts) == 1 and alerts[0].count == 1 and alerts[0].severity == "low"


# ---------- end to end ----------
def test_run_all_sorts_critical_first():
    events = [ev(0, "dave", "3.3.3.3", "failed", sec=i * 5) for i in range(6)]
    events += [ev(2, "dave", "3.3.3.3", "success"), ev(0, "erin", "10.0.0.14", "success", hour=3)]
    alerts = detections.run_all(make_conn(events))
    assert alerts[0].severity == "critical" and alerts[-1].severity == "low"


def test_run_all_does_not_double_report_spraying_as_brute_force():
    names = ["a", "b", "c", "d", "e", "f"]
    events = [ev(0, n, "2.2.2.2", "failed", sec=i * 5) for i, n in enumerate(names) for _ in range(2)]
    rules = [a.rule for a in detections.run_all(make_conn(events))]
    assert rules == ["password_spraying"]
