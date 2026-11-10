"""A very small in-process metrics registry with Prometheus text output. No dependency, no background thread.

Counters and duration sums are per replica; the scraper adds them up. Gauges that must be exact across replicas
(scans in flight) are read from the store at scrape time.
"""
import threading

_lock = threading.Lock()
_counters = {}
_durations = {}

HELP = {
    "scansvc_submits_total": "Bundles submitted, by outcome (new, reused, resumed, rejected, busy).",
    "scansvc_verdicts_total": "Scans that reached a final status, by status.",
    "scansvc_github_errors_total": "GitHub calls that failed, by kind (transient, permanent).",
    "scansvc_scan_seconds": "Time from submit to final status, by status.",
    "scansvc_scans_in_flight": "Scans not yet final, read from the store.",
}


def _key(labels):
    return tuple(sorted(labels.items()))


def inc(name, **labels):
    with _lock:
        _counters[(name, _key(labels))] = _counters.get((name, _key(labels)), 0) + 1


def observe(name, seconds, **labels):
    with _lock:
        total, count = _durations.get((name, _key(labels)), (0.0, 0))
        _durations[(name, _key(labels))] = (total + max(0.0, seconds), count + 1)


def reset():
    """For tests."""
    with _lock:
        _counters.clear()
        _durations.clear()


def _labels(pairs):
    return "{" + ",".join(f'{key}="{value}"' for key, value in pairs) + "}" if pairs else ""


def render(gauges=None):
    lines, seen = [], set()

    def head(name, kind):
        if name not in seen:
            seen.add(name)
            lines.append(f"# HELP {name} {HELP.get(name, name)}")
            lines.append(f"# TYPE {name} {kind}")

    with _lock:
        for (name, pairs), value in sorted(_counters.items()):
            head(name, "counter")
            lines.append(f"{name}{_labels(pairs)} {value}")
        for (name, pairs), (total, count) in sorted(_durations.items()):
            head(name, "summary")
            lines.append(f"{name}_sum{_labels(pairs)} {total:.3f}")
            lines.append(f"{name}_count{_labels(pairs)} {count}")
    for name, value in sorted((gauges or {}).items()):
        head(name, "gauge")
        lines.append(f"{name} {value}")
    return "\n".join(lines) + "\n"
