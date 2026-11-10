#!/usr/bin/env python3
"""Live end-to-end check: pushes the fixture bundles through the real scan workspace repo and compares verdicts.

Not collected by pytest (it needs GitHub and takes minutes). Run it by hand:

    SCAN_REPO=owner/name GITHUB_TOKEN=... SCAN_STORE_URL=./.scan-store python tests/e2e_live.py

--with-secret also pushes a bundle containing secret-shaped strings generated at run time, expecting push
protection to refuse it. Off by default: if push protection does not recognise the generated format, the string
lands in the scan workspace repo, which matters when that repo is public.
"""
import argparse
import secrets
import string
import sys
import time
from pathlib import Path

from scansvc.bundle import zip_directory
from scansvc.wiring import LocalBackend

BUNDLES = Path(__file__).parent / "fixtures" / "bundles"
# name -> (expected status, rule that must be present or None)
CASES = {
    "static-ok": ("PASS", None),
    "static-xss": ("FAIL", "GH-001"),
    "node-vuln-dep": ("FAIL", "GH-003"),
    "python-cmd-injection": ("FAIL", "GH-001"),
    "workflow-injection": ("PASS", None),
}
FINAL = ("PASS", "FAIL", "ERROR")


def secret_bundle(tmp):
    """Writes a bundle whose only problem is secret-shaped text. Built at run time; nothing like it is committed."""
    alphabet = string.ascii_letters + string.digits
    rand = lambda n: "".join(secrets.choice(alphabet) for _ in range(n))  # noqa: E731
    lines = ["sk" + "_live_" + rand(24), "xox" + "b-" + "-".join(["1234567890", "1234567890123", rand(24)])]
    target = Path(tmp) / "secret-bundle"
    target.mkdir(parents=True, exist_ok=True)
    (target / "config.js").write_text("".join(f"const key{i} = '{line}';\n" for i, line in enumerate(lines)))
    return target


def wait(backend, record, timeout):
    deadline = time.time() + timeout
    while record["status"] not in FINAL and time.time() < deadline:
        time.sleep(15)
        record = backend.status(record["scan_id"])
    return record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--with-secret", action="store_true")
    parser.add_argument("--only", help="run a single case by name")
    parser.add_argument("--timeout", type=int, default=1200)
    args = parser.parse_args()

    backend = LocalBackend()
    print("preflight:", backend.preflight())
    cases = {name: (BUNDLES / name, *expect) for name, expect in CASES.items()}
    if args.with_secret:
        import tempfile
        cases["generated-secret"] = (secret_bundle(tempfile.mkdtemp(prefix="e2e-")), "FAIL", "GH-005")
    if args.only:
        cases = {args.only: cases[args.only]}

    # Submit everything first so the runs overlap, then collect.
    started = {name: backend.submit(zip_directory(path)) for name, (path, _, _) in cases.items()}
    failures = 0
    for name, (_, want_status, want_rule) in cases.items():
        record = wait(backend, started[name], args.timeout)
        rules = sorted({finding["rule"] for finding in record.get("findings", [])})
        ok = record["status"] == want_status and (want_rule is None or want_rule in rules)
        failures += 0 if ok else 1
        print(f"{'ok  ' if ok else 'FAIL'} {name:<22} got {record['status']:<7} {rules} "
              f"want {want_status} {want_rule or ''}  {record.get('run_url') or record.get('detail') or ''}")
    print("all cases matched" if not failures else f"{failures} case(s) did not match")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
