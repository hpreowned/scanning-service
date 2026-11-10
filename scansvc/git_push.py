"""Turns an extracted bundle into one commit on scan/<id> in the scan workspace repo.

The commit's parent is a deterministic empty baseline commit and its tree holds only artifact/. The token reaches
git through environment-scoped config, never through the URL or the command line.
"""
import base64
import os
import subprocess

EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
BOT_NAME = "artifact-scan-bot"
BOT_EMAIL = "artifact-scan-bot@users.noreply.github.com"
EPOCH = "2000-01-01T00:00:00Z"
# What GitHub prints when push protection (secret scanning) or a ruleset refuses a push.
SECRET_MARKERS = ("GH013", "push protection", "secret scanning", "GITHUB PUSH PROTECTION")


class PushError(Exception):
    def __init__(self, message, secret=False):
        super().__init__(message)
        self.secret = secret


def _base_env():
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": BOT_NAME, "GIT_AUTHOR_EMAIL": BOT_EMAIL,
        "GIT_COMMITTER_NAME": BOT_NAME, "GIT_COMMITTER_EMAIL": BOT_EMAIL,
    }


def _git(workdir, *args, env=None, check=True, stdin=None):
    return subprocess.run(["git", "-C", str(workdir), *args], capture_output=True, text=True, check=check,
                          env=env or _base_env(), timeout=300, input=stdin)


def build_commit(workdir, scan_id, paths):
    """Creates the baseline and bundle commits in a fresh repo at workdir. Returns the bundle commit SHA.

    `paths` are the bundle-relative files extract() wrote. Blobs are hashed with --no-filters and placed in the
    index directly, so a .gitignore or .gitattributes shipped in the bundle cannot hide or rewrite anything:
    the committed tree is byte-for-byte the bundle, every entry a plain 100644 blob under artifact/.
    """
    env = _base_env()
    _git(workdir, "init", "-q", env=env)
    fixed = {**env, "GIT_AUTHOR_DATE": EPOCH, "GIT_COMMITTER_DATE": EPOCH}
    baseline = _git(workdir, "commit-tree", EMPTY_TREE, "-m", "scan baseline", env=fixed).stdout.strip()
    tree_paths = [f"artifact/{path}" for path in paths]
    hashed = _git(workdir, "hash-object", "-w", "--no-filters", "--stdin-paths", env=env,
                  stdin="".join(path + "\n" for path in tree_paths)).stdout.split()
    if len(hashed) != len(tree_paths):
        raise PushError("could not hash every bundle file")
    index = "".join(f"100644 {blob}\t{path}\0" for blob, path in zip(hashed, tree_paths))
    _git(workdir, "update-index", "-z", "--add", "--index-info", env=env, stdin=index)
    tree = _git(workdir, "write-tree", env=env).stdout.strip()
    # Fixed dates here too: the same bytes and scan id always give the same commit SHA, so a repeated push after
    # a crash is a no-op instead of a rejected non-fast-forward.
    return _git(workdir, "commit-tree", tree, "-p", baseline, "-m", f"scan {scan_id}", env=fixed).stdout.strip()


def push(workdir, settings, token, scan_id, commit_sha):
    """Pushes the commit to scan/<id>. Raises PushError(secret=True) when push protection refuses it."""
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    env = {
        **_base_env(),
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": f"http.{settings.server_url}/.extraheader",
        "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}",
        "GIT_CONFIG_KEY_1": "credential.helper",
        "GIT_CONFIG_VALUE_1": "",
    }
    url = f"{settings.server_url}/{settings.scan_repo}.git"
    result = _git(workdir, "push", "--quiet", url, f"{commit_sha}:refs/heads/scan/{scan_id}", env=env, check=False)
    if result.returncode == 0:
        return
    output = (result.stderr or "") + (result.stdout or "")
    if any(marker.lower() in output.lower() for marker in SECRET_MARKERS):
        raise PushError("GitHub push protection refused the bundle: it contains a secret", secret=True)
    # Keep GitHub's own explanation but never the auth header (it is not in the output; this is belt and braces).
    tail = " ".join(line.strip() for line in output.splitlines()[-4:]).replace(basic, "[redacted]")
    raise PushError(f"push to the scan workspace repo failed: {tail[:300]}")
