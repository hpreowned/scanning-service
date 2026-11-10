#!/usr/bin/env python3
"""Stage 1 of a scan: prove the checked-out tree is what was requested, then take inventory.

Fails closed: any tree check that does not hold writes `ok: false` and exits 1, which verdict.py turns into `error`.
"""
import argparse
import subprocess
import sys
from pathlib import Path

from common import ARTIFACT_PREFIX, EMPTY_TREE, read_json, set_output, write_json
from inventory import build_inventory


def git(target, *args):
    return subprocess.run(["git", "-C", str(target), *args], check=True, capture_output=True, text=True).stdout.strip()


def check_tree(target, sha):
    """Returns (paths, None) when the tree is acceptable, or (None, reason)."""
    head = git(target, "rev-parse", "HEAD")
    if head != sha:
        return None, f"checked-out commit {head} is not the requested {sha}"
    try:
        parent_tree = git(target, "rev-parse", "HEAD^^{tree}")
    except subprocess.CalledProcessError:
        return None, "the scan commit has no parent; expected the empty baseline commit"
    if parent_tree != EMPTY_TREE:
        return None, "the scan commit's parent is not the empty baseline commit"
    paths = []
    # -z keeps unusual file names intact: <mode> <type> <object>\t<path>\0
    for entry in git(target, "ls-tree", "-r", "-z", "HEAD").split("\0"):
        if not entry:
            continue
        meta, path = entry.split("\t", 1)
        mode = meta.split(" ", 1)[0]
        if mode != "100644":
            return None, f"`{path}` has mode {mode}; only regular non-executable files are allowed"
        if not path.startswith(ARTIFACT_PREFIX):
            return None, f"`{path}` is outside {ARTIFACT_PREFIX}"
        paths.append(path)
    if not paths:
        return None, "the scan commit contains no files"
    return paths, None


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    out = Path(args.out)

    try:
        paths, reason = check_tree(args.target, args.sha)
    except (subprocess.CalledProcessError, OSError) as err:
        paths, reason = None, f"git inspection failed: {err}"
    if reason:
        write_json(out / "inventory.json", {"ok": False, "error": reason})
        print(f"::error::{reason}")
        return 1

    policy = read_json(args.policy, {}) or {}
    unpinned = (policy.get("dependencies") or {}).get("unpinned_manifest", "deny")
    inventory = build_inventory(args.target, paths, "GH-003" if unpinned == "deny" else "GH-004")
    inventory["ok"] = True
    inventory["base_sha"] = git(args.target, "rev-parse", "HEAD^")
    inventory["head_sha"] = args.sha
    write_json(out / "inventory.json", inventory)

    set_output("codeql_languages", ",".join(inventory["codeql_languages"]))
    set_output("has_manifests", "true" if inventory["manifests"] else "false")
    print(f"files={inventory['file_count']} languages={inventory['codeql_languages']} "
          f"manifests={len(inventory['manifests'])} unscanned={len(inventory['unscanned'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
