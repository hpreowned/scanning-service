"""Optional pre-push secret check with gitleaks (the one approved third-party binary).

Runs only when GITLEAKS_BIN is set. A hit fails the scan before anything is pushed to GitHub. If the binary is
configured but does not run, the scan errors: a configured check that silently does nothing is worse than none.
Messages never echo the secret, only the gitleaks rule id and the location.
"""
import json
import subprocess
from pathlib import Path

from .models import finding


class PrecheckError(Exception):
    pass


def gitleaks_findings(gitleaks_bin, workdir):
    """Findings for <workdir>/artifact. Raises PrecheckError when gitleaks could not produce a report."""
    report = Path(workdir) / "gitleaks-report.json"
    command = [
        gitleaks_bin, "detect", "--no-git", "--no-banner", "--exit-code", "0",
        "--source", str(Path(workdir) / "artifact"),
        "--report-format", "json", "--report-path", str(report),
        # Look for an ignore file in the (empty) work root, never inside the bundle.
        "--gitleaks-ignore-path", str(workdir),
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as err:
        raise PrecheckError(f"gitleaks could not be run: {type(err).__name__}") from None
    try:
        hits = json.loads(report.read_text(encoding="utf-8") or "[]")
    except (OSError, ValueError):
        raise PrecheckError(f"gitleaks produced no report (exit {result.returncode})") from None
    finally:
        report.unlink(missing_ok=True)
    prefix = str(Path(workdir) / "artifact") + "/"
    return [
        finding("GH-005", "deny", f"secret detected before push (gitleaks rule {hit.get('RuleID', 'unknown')})",
                str(hit.get("File", "")).removeprefix(prefix) or None, hit.get("StartLine"))
        for hit in hits or []
    ]
