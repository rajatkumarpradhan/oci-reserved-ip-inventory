"""python -m ip_inventory.cli SNAPSHOT [--as-of YYYY-MM-DD]"""

from __future__ import annotations

import argparse
import sys
from datetime import date, datetime

from .model import SnapshotError, load_snapshot
from .rules import exit_code, run_all


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reserved-ip-inventory",
        description="Audit an offline snapshot of reserved public IPs for dangling/idle/unowned addresses.",
    )
    p.add_argument("snapshot", help="path to the JSON inventory snapshot")
    p.add_argument("--as-of", default=None, help="reference date YYYY-MM-DD (default: today, UTC)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.as_of:
        try:
            as_of = datetime.strptime(args.as_of, "%Y-%m-%d").date()
        except ValueError:
            print(f"error: --as-of {args.as_of!r} is not YYYY-MM-DD", file=sys.stderr)
            return 2
    else:
        as_of = date.today()
    try:
        snapshot = load_snapshot(args.snapshot)
    except SnapshotError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    findings = run_all(snapshot, as_of)
    attached = sum(1 for i in snapshot.reserved_ips if i.is_attached())
    print(
        f"Reserved IP audit as of {as_of.isoformat()} - {len(snapshot.reserved_ips)} reserved IP(s) "
        f"({attached} attached), {len(findings)} finding(s)"
    )
    for f in findings:
        print(f"[{f.severity:6s}] {f.rule} ip={f.ip}")
        print(f"         {f.detail}")
    code = exit_code(findings)
    print({0: "RESULT: clean", 1: "RESULT: warnings only", 2: "RESULT: HIGH findings present"}[code])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
