"""Generate a realistic fake SSH auth log with planted attacks (for demos and testing)."""
import random
from datetime import datetime, timedelta

USERS = ["alice", "bob", "carol", "dave", "erin"]
INTERNAL_IPS = {u: f"10.0.0.{i + 10}" for i, u in enumerate(USERS)}
SPRAY_NAMES = ["admin", "root", "test", "oracle", "postgres", "ubuntu", "guest", "support"]


def _line(ts: datetime, host: str, ok: bool, user: str, ip: str, invalid=False) -> str:
    verb = "Accepted" if ok else "Failed"
    inv = "invalid user " if invalid else ""
    pid = random.randint(1000, 60000)
    port = random.randint(30000, 65000)
    return (f"{ts:%Y-%m-%dT%H:%M:%S} {host} sshd[{pid}]: {verb} password for "
            f"{inv}{user} from {ip} port {port} ssh2")


def generate(seed: int = 42, day: str = "2026-09-28") -> list:
    random.seed(seed)
    base = datetime.fromisoformat(day)
    events = []  # (datetime, line)

    def add(ts, *a, **k):
        events.append((ts, _line(ts, *a, **k)))

    # 1) Normal business-hours activity with occasional typos
    for user in USERS:
        for _ in range(random.randint(3, 6)):
            ts = base + timedelta(hours=random.randint(8, 17), minutes=random.randint(0, 59),
                                  seconds=random.randint(0, 59))
            if random.random() < 0.2:
                add(ts - timedelta(seconds=10), "web01", False, user, INTERNAL_IPS[user])
            add(ts, "web01", True, user, INTERNAL_IPS[user])

    # 2) Brute force: one IP hammering 'root'
    t = base + timedelta(hours=3, minutes=12)
    for i in range(25):
        add(t + timedelta(seconds=i * 6), "web01", False, "root", "203.0.113.50")

    # 3) Password spraying: one IP, many usernames, a few tries each
    t = base + timedelta(hours=10, minutes=5)
    for i, name in enumerate(SPRAY_NAMES):
        for j in range(2):
            add(t + timedelta(seconds=i * 20 + j * 5), "web01", False, name, "198.51.100.23", invalid=True)

    # 4) Compromise: brute force on 'dave' then a success from the same IP
    t = base + timedelta(hours=14, minutes=30)
    for i in range(8):
        add(t + timedelta(seconds=i * 10), "db01", False, "dave", "192.0.2.77")
    add(t + timedelta(seconds=95), "db01", True, "dave", "192.0.2.77")

    # 5) Off-hours login by a normal user from a normal IP
    add(base + timedelta(hours=2, minutes=41), "web01", True, "erin", INTERNAL_IPS["erin"])

    events.sort(key=lambda x: x[0])
    return [line for _, line in events]
