"""Command-line interface.

Examples:
  python -m sentinel generate --out data/auth.log
  python -m sentinel analyze --logfile data/auth.log --report alerts.json
"""
import argparse
import sys

from . import db, detections, generate_logs, parser, reporting


def cmd_generate(args) -> int:
    lines = generate_logs.generate(seed=args.seed)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} log lines to {args.out}")
    return 0


def cmd_analyze(args) -> int:
    try:
        events, skipped = parser.parse_file(args.logfile)
    except FileNotFoundError:
        print(f"Error: log file not found: {args.logfile}", file=sys.stderr)
        return 1
    print(f"Parsed {len(events)} events ({skipped} unrecognized lines skipped)")

    conn = db.connect(args.db)
    db.insert_events(conn, events)
    alerts = detections.run_all(conn)
    reporting.print_summary(alerts)
    if args.report:
        reporting.write_report(alerts, args.report)
        print(f"\nReport written to {args.report}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel", description="Mini SIEM-style log analyzer")
    sub = p.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", help="create a sample log with planted attacks")
    g.add_argument("--out", default="data/auth.log")
    g.add_argument("--seed", type=int, default=42)
    g.set_defaults(func=cmd_generate)

    a = sub.add_parser("analyze", help="parse a log and run detections")
    a.add_argument("--logfile", required=True)
    a.add_argument("--report", help="output file (.json or .csv)")
    a.add_argument("--db", default=":memory:", help="SQLite path (default: in-memory)")
    a.set_defaults(func=cmd_analyze)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
