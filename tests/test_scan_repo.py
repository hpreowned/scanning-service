"""Real git against a local bare repository: what the service commits is exactly what the workflow will accept."""
import subprocess
from pathlib import Path

import pytest
from conftest import make_zip

import prepare  # the workflow's own tree check, from scan-repo/scanner
from common import read_json
from scansvc import scan_repo
from scansvc.bundle import extract

LIMITS = dict(max_bytes=1_000_000, max_files=50, max_file_bytes=100_000)
POLICY = str(Path(__file__).resolve().parents[1] / "scan-repo" / "scanner" / "policy.json")


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def commit(tmp_path, files, name="work"):
    workdir = tmp_path / name
    workdir.mkdir()
    paths = extract(make_zip(files), workdir, **LIMITS)
    return workdir, scan_repo.build_commit(workdir, "s-test1234", paths)


def test_tree_holds_only_plain_files_under_artifact_on_an_empty_baseline(tmp_path):
    workdir, sha = commit(tmp_path, {"index.html": "<p>hi</p>", ".github/workflows/evil.yml": "on: push"})
    entries = git(workdir, "ls-tree", "-r", sha).splitlines()
    assert all(line.startswith("100644 blob") for line in entries)
    assert sorted(line.split("\t")[1] for line in entries) == ["artifact/.github/workflows/evil.yml", "artifact/index.html"]
    assert git(workdir, "rev-parse", f"{sha}^^{{tree}}") == scan_repo.EMPTY_TREE


def test_baseline_commit_is_the_same_every_time(tmp_path):
    first, sha_a = commit(tmp_path, {"a.js": "1"}, "one")
    second, sha_b = commit(tmp_path, {"b.js": "2"}, "two")
    assert git(first, "rev-parse", f"{sha_a}^") == git(second, "rev-parse", f"{sha_b}^")


def test_gitignore_in_the_bundle_cannot_hide_files(tmp_path):
    workdir, sha = commit(tmp_path, {".gitignore": "*\n", "hidden.js": "evil()"})
    names = git(workdir, "ls-tree", "-r", "--name-only", sha).splitlines()
    assert names == ["artifact/.gitignore", "artifact/hidden.js"]


def test_gitattributes_in_the_bundle_cannot_rewrite_content(tmp_path):
    body = "line one\r\nline two\r\n"
    workdir, sha = commit(tmp_path, {".gitattributes": "* text eol=lf working-tree-encoding=UTF-16\n", "a.js": body})
    assert subprocess.run(["git", "-C", str(workdir), "cat-file", "blob", f"{sha}:artifact/a.js"],
                          check=True, capture_output=True).stdout == body.encode()


def test_push_creates_the_scan_branch_and_prepare_accepts_it(tmp_path, settings):
    remote = tmp_path / "owner" / "remote.git"
    remote.mkdir(parents=True)
    git(remote, "init", "-q", "--bare")
    workdir, sha = commit(tmp_path, {"index.html": "<script>let a = 1</script>", "app.py": "print(1)"})
    scan_repo.push(workdir, settings, "not-a-real-token", "s-test1234", sha)
    assert git(remote, "rev-parse", "refs/heads/scan/s-test1234") == sha

    checkout = tmp_path / "checkout"
    git(tmp_path, "clone", "-q", "--branch", "scan/s-test1234", str(remote), str(checkout))
    out = tmp_path / "results"
    assert prepare.main(["--target", str(checkout), "--sha", sha, "--policy", POLICY, "--out", str(out)]) == 0
    inventory = read_json(out / "inventory.json")
    assert inventory["ok"] and inventory["codeql_languages"] == ["javascript-typescript", "python"]


def test_push_failure_is_reported_without_credentials(tmp_path, settings):
    workdir, sha = commit(tmp_path, {"a.js": "1"})
    with pytest.raises(scan_repo.PushError) as raised:
        scan_repo.push(workdir, settings, "not-a-real-token", "s-test1234", sha)  # no remote exists
    assert not raised.value.secret
    assert "not-a-real-token" not in str(raised.value)
