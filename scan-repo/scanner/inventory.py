"""Classifies the bundle's files: what CodeQL will analyse, what dependency review covers, what nothing covers.

Reads files as text only. Never imports, installs or executes anything from the bundle.
"""
import json
import re
from pathlib import Path, PurePosixPath

from common import finding, strip_prefix

JS_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"}
HTML_EXT = {".html", ".htm", ".xhtml", ".vue"}
PY_EXT = {".py"}
# Inert for these scanners: no code path, or covered elsewhere (dependency review reads manifests and lockfiles).
DATA_EXT = {
    ".css", ".json", ".md", ".txt", ".csv", ".tsv", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".map", ".yaml", ".yml", ".toml", ".lock", ".cfg", ".ini",
}
NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
PY_MANIFESTS = ("pyproject.toml", "poetry.lock", "uv.lock", "Pipfile", "Pipfile.lock")
SUPPRESSION_FILES = {
    ".gitleaksignore", ".gitleaks.toml", "gitleaks.toml", ".semgrepignore", ".trivyignore",
    "osv-scanner.toml", "codeql-config.yml", "codeql-config.yaml", ".lgtm.yml", "lgtm.yml",
}
SUPPRESSION_INLINE = re.compile(r"gitleaks:allow|nosemgrep|\blgtm\[|\bcodeql\[|(?:#|//)\s*nosec\b")
SCRIPT_TAG = re.compile(r"<script\b", re.IGNORECASE)
REQUIREMENTS = re.compile(r"^requirements[\w.-]*\.txt$", re.IGNORECASE)
NOTEBOOK_MAGIC_LANG = re.compile(r"^%(sql|scala|r|md|sh|fs|run|pip)\b", re.IGNORECASE)
MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_LISTED = 50


def read_text(path):
    """Text of a file, or None when it is binary or larger than the cap."""
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return None
    if len(raw) > MAX_TEXT_BYTES or b"\x00" in raw:
        return None
    return raw.decode("utf-8", errors="replace")


def convert_notebook(target, rel):
    """Writes the Python code cells of an .ipynb next to it as <name>.ipynb.py. Returns (converted, skipped_cells)."""
    data = json.loads((Path(target) / rel).read_text(encoding="utf-8"))
    meta = data.get("metadata", {}) if isinstance(data, dict) else {}
    language = (meta.get("kernelspec", {}).get("language") or meta.get("language_info", {}).get("name") or "python")
    if str(language).lower() != "python":
        return None, len(data.get("cells", []))
    lines, skipped = [], 0
    for index, cell in enumerate(data.get("cells", [])):
        if cell.get("cell_type") != "code":
            continue
        source = cell.get("source", "")
        source = "".join(source) if isinstance(source, list) else str(source)
        if NOTEBOOK_MAGIC_LANG.match(source.lstrip()):
            skipped += 1
            continue
        lines.append(f"# --- notebook cell {index} ---")
        for line in source.splitlines():
            # IPython magics and shell escapes are not Python; keep the line count, drop the syntax.
            lines.append("# " + line if line.lstrip().startswith(("%", "!")) else line)
    converted = rel + ".py"
    (Path(target) / converted).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return converted, skipped


def count_npm_lock(text):
    try:
        data = json.loads(text)
    except ValueError:
        return 0
    packages = data.get("packages")
    if isinstance(packages, dict):
        return max(0, len([name for name in packages if name]))
    return len(data.get("dependencies", {}) or {})


def requirement_lines(text):
    lines = [ln.split("#", 1)[0].strip() for ln in text.splitlines()]
    return [ln for ln in lines if ln and not ln.startswith("-")]


def build_inventory(target, paths, unpinned_rule):
    """`paths` are repo-relative (artifact/...). Returns the inventory dict, including prepare-stage findings."""
    findings, unscanned, manifests, notebooks = [], [], [], {}
    has_js = has_py = False
    expected_deps = 0
    by_dir = {}
    for rel in paths:
        by_dir.setdefault(str(PurePosixPath(rel).parent), set()).add(PurePosixPath(rel).name)

    for rel in paths:
        pure = PurePosixPath(rel)
        name, ext = pure.name, pure.suffix.lower()
        full = Path(target) / rel
        text = read_text(full)

        if name in SUPPRESSION_FILES:
            findings.append(finding("GH-006", f"scanner configuration or ignore file `{name}` shipped inside the bundle", rel))
        elif text is not None:
            for number, line in enumerate(text.splitlines(), start=1):
                if SUPPRESSION_INLINE.search(line):
                    findings.append(finding("GH-006", "inline scanner suppression marker", rel, number))
                    break

        if "node_modules" in pure.parts:
            unscanned.append({"file": strip_prefix(rel), "reason": "inside node_modules (CodeQL skips it)"})
        elif name.endswith((".min.js", "-min.js")):
            unscanned.append({"file": strip_prefix(rel), "reason": "minified JavaScript (CodeQL skips it)"})
        elif ext in JS_EXT:
            has_js = True
        elif ext in HTML_EXT:
            has_js = has_js or bool(text and SCRIPT_TAG.search(text))
        elif ext in PY_EXT:
            has_py = True
        elif ext == ".ipynb":
            try:
                converted, skipped = convert_notebook(target, rel)
            except (ValueError, OSError, AttributeError, TypeError):
                unscanned.append({"file": strip_prefix(rel), "reason": "notebook could not be parsed"})
            else:
                if converted:
                    has_py = True
                    notebooks[strip_prefix(converted)] = strip_prefix(rel)
                    if skipped:
                        unscanned.append({"file": strip_prefix(rel), "reason": f"{skipped} non-Python cell(s) not analysed"})
                else:
                    unscanned.append({"file": strip_prefix(rel), "reason": "notebook language is not Python"})
        elif ext == ".svg":
            if text is None or SCRIPT_TAG.search(text):
                unscanned.append({"file": strip_prefix(rel), "reason": "SVG with script content"})
        elif ext not in DATA_EXT and name not in NPM_LOCKS and name not in PY_MANIFESTS:
            unscanned.append({"file": strip_prefix(rel), "reason": f"file type `{ext or name}` is not analysed"})

        siblings = by_dir[str(pure.parent)]
        if name == "package.json":
            manifests.append(strip_prefix(rel))
            try:
                declared = len((json.loads(text or "{}").get("dependencies") or {}))
            except ValueError:
                declared = 0
            if declared and not any(lock in siblings for lock in NPM_LOCKS):
                findings.append(finding(unpinned_rule, "package.json declares dependencies but no lockfile is present; "
                                        "they cannot be checked for known vulnerabilities", rel))
        elif name in NPM_LOCKS:
            manifests.append(strip_prefix(rel))
            if name in ("package-lock.json", "npm-shrinkwrap.json") and text:
                expected_deps += count_npm_lock(text)
        elif REQUIREMENTS.match(name):
            manifests.append(strip_prefix(rel))
            reqs = requirement_lines(text or "")
            pinned = [ln for ln in reqs if "==" in ln]
            expected_deps += len(pinned)
            if len(pinned) < len(reqs):
                findings.append(finding(unpinned_rule, f"{len(reqs) - len(pinned)} requirement(s) are not pinned with `==`; "
                                        "they cannot be checked for known vulnerabilities", rel))
        elif name in PY_MANIFESTS:
            manifests.append(strip_prefix(rel))

    if unscanned:
        listed = ", ".join(item["file"] for item in unscanned[:MAX_LISTED])
        more = f" and {len(unscanned) - MAX_LISTED} more" if len(unscanned) > MAX_LISTED else ""
        findings.append(finding("GH-007", f"{len(unscanned)} file(s) are not covered by any scanner: {listed}{more}"))

    languages = [lang for lang, present in (("javascript-typescript", has_js), ("python", has_py)) if present]
    return {
        "codeql_languages": languages,
        "manifests": manifests,
        "expected_dependencies": expected_deps,
        "notebooks": notebooks,
        "unscanned": unscanned,
        "findings": findings,
        "file_count": len(paths),
    }
