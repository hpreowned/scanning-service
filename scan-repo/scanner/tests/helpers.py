"""Test helpers: build a throwaway git repo shaped like a scan commit. Standard library only."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common import EMPTY_TREE  # noqa: E402

GIT_ENV = {
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
}


def git(repo, *args, stdin=None):
    env = {**os.environ, **GIT_ENV}
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
                          input=stdin, env=env).stdout.strip()


def make_scan_repo(files, baseline=True, modes=None):
    """Creates a repo whose HEAD holds `files` (path -> text). Returns (repo_path, head_sha)."""
    repo = Path(tempfile.mkdtemp(prefix="scan-test-"))
    git(repo, "init", "-q")
    parent = git(repo, "commit-tree", EMPTY_TREE, "-m", "baseline") if baseline else None
    for rel, text in files.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        if modes and rel in modes:
            path.chmod(modes[rel])
    git(repo, "add", "-A")
    tree = git(repo, "write-tree")
    args = ["commit-tree", tree, "-m", "bundle"] + (["-p", parent] if parent else [])
    head = git(repo, *args)
    git(repo, "update-ref", "HEAD", head)
    git(repo, "reset", "-q", "--hard", head)
    return repo, head


def sarif(results, rules):
    """Minimal CodeQL-shaped SARIF: rules is {id: security_severity or None}, results is [(id, uri, line, text)]."""
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "CodeQL"}, "extensions": [{"rules": [
                {"id": rule_id, "properties": ({"security-severity": str(score)} if score is not None else {})}
                for rule_id, score in rules.items()]}]},
            "results": [{
                "ruleId": rule_id, "message": {"text": text},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}],
            } for rule_id, uri, line, text in results],
        }],
    }
