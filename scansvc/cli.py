"""scanctl: scan a bundle and read the verdict.

With SCAN_SERVICE_URL set it talks to the scan service over HTTP (what agents and CI use; no GitHub credentials
needed). Without it, it runs the scan in-process using the GitHub settings from the environment (operators).

Exit codes: 0 pass, 1 fail, 2 error or a rejected bundle, 3 still running or the service is at capacity.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

from .bundle import BundleError, zip_directory
from .config import ConfigError
from .models import ERROR, FAIL, PASS, Busy

EXIT = {PASS: 0, FAIL: 1, ERROR: 2}


def _backend():
    url = os.environ.get("SCAN_SERVICE_URL")
    if url:
        from .backends import HttpBackend
        return HttpBackend(url, os.environ.get("SCAN_API_TOKEN"))
    from .backends import LocalBackend
    return LocalBackend()


def _read_bundle(path):
    target = Path(path)
    if target.is_dir():
        return zip_directory(target)
    return target.read_bytes()


def _print(record, as_json):
    if as_json:
        print(json.dumps(record, indent=2))
        return
    print(f"{record['status']}  scan {record['scanId']}  sha256 {record['sha256'][:12]}")
    if record.get("runUrl"):
        print(f"  run: {record['runUrl']}")
    if record.get("detail"):
        print(f"  {record['detail']}")
    for item in record.get("findings", []):
        where = item.get("file", "")
        where += f":{item['line']}" if item.get("line") else ""
        print(f"  {item['severity']:<5} {item['rule']}  {where}  {item['message']}")


def _submit(backend, data, wait, timeout):
    """Submits, waiting out 'at capacity' answers when --wait was given."""
    deadline = time.time() + timeout
    while True:
        try:
            return backend.submit(data)
        except Busy as busy:
            if not wait or time.time() + busy.retry_after > deadline:
                raise
            print(f"  ... at capacity, retrying in {busy.retry_after}s", file=sys.stderr)
            time.sleep(busy.retry_after)


def _wait(backend, record, timeout, interval, as_json):
    deadline = time.time() + timeout
    while record["status"] not in EXIT and time.time() < deadline:
        time.sleep(interval)
        record = backend.status(record["scanId"])
        if not as_json:
            print(f"  ... {record['status']}", file=sys.stderr)
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(prog="scanctl", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="submit a bundle (zip file or directory)")
    scan.add_argument("bundle")
    scan.add_argument("--wait", action="store_true", help="poll until the verdict is final")
    scan.add_argument("--timeout", type=int, default=1200)
    scan.add_argument("--interval", type=int, default=15)
    scan.add_argument("--json", action="store_true")
    status = sub.add_parser("status", help="show a scan")
    status.add_argument("scan_id")
    status.add_argument("--json", action="store_true")
    sub.add_parser("reconcile", help="advance every scan nobody is polling (in-process mode only)")
    sub.add_parser("preflight", help="check the GitHub settings without scanning (in-process mode only)")
    args = parser.parse_args(argv)

    try:
        backend = _backend()
        if args.command == "preflight":
            print(json.dumps(backend.preflight()))
            return 0
        if args.command == "reconcile":
            for record in backend.reconcile():
                print(f"{record['scanId']} {record['status']}")
            return 0
        if args.command == "status":
            record = backend.status(args.scan_id)
            if record is None:
                print("unknown scan id", file=sys.stderr)
                return 2
        else:
            record = _submit(backend, _read_bundle(args.bundle), args.wait, args.timeout)
            if args.wait:
                record = _wait(backend, record, args.timeout, args.interval, args.json)
        _print(record, args.json)
        return EXIT.get(record["status"], 3)
    except BundleError as err:
        print(f"bundle rejected: {err}", file=sys.stderr)
        return 2
    except Busy as busy:
        print(f"scan service is at capacity; retry in {busy.retry_after} seconds", file=sys.stderr)
        return 3
    except (ConfigError, OSError, RuntimeError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
