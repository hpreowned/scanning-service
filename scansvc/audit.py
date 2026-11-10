"""Audit trail: one JSON line per scan transition on the `scansvc.audit` logger (stdout by default).

Each line carries every identifier needed to join the systems together: the caller's job reference, the scan id,
the bundle sha256, the commit pushed, the workflow run, and who asked. No bundle content, no credentials.
"""
import json
import logging
import sys
import time

_logger = logging.getLogger("scansvc.audit")


class _Stdout(logging.Handler):
    """Writes to whatever sys.stdout is at the time of the call, so redirection and test capture both work."""

    def emit(self, record):
        sys.stdout.write(self.format(record) + "\n")
        sys.stdout.flush()


def configure():
    """Attach a plain handler once. Safe to call more than once."""
    if not _logger.handlers:
        handler = _Stdout()
        handler.setFormatter(logging.Formatter("%(message)s"))
        _logger.addHandler(handler)
        _logger.setLevel(logging.INFO)
        _logger.propagate = False


def emit(event, record, **extra):
    entry = {
        "ts": round(time.time(), 3),
        "event": event,
        "scan_id": record.scan_id,
        "sha256": record.sha256,
        "status": record.status,
        "step": record.step,
        "commit_sha": record.commit_sha,
        "run_id": record.run_id,
        "policy_version": record.policy_version,
        "job_ref": record.job_ref,
        "caller": record.caller,
        "trace": record.trace,
        **extra,
    }
    _logger.info(json.dumps({key: value for key, value in entry.items() if value is not None}, sort_keys=True))
