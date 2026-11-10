"""Strict extraction of a submitted zip into <workdir>/artifact/. The bundle is untrusted.

Every refusal happens before anything is written. Nothing is ever executed. Files are written 0644 and nested
under artifact/, so no bundle path can become a workflow or scanner config in the scan workspace repo.
"""
import hashlib
import io
import stat
import zipfile
import zlib
from pathlib import Path, PurePosixPath

ARTIFACT_DIR = "artifact"
MAX_PATH_LENGTH = 240
FORBIDDEN_PARTS = {"node_modules": "dependencies are never shipped in a bundle", ".git": "git metadata is not allowed"}


class BundleError(Exception):
    """The upload is not an acceptable bundle. The message is safe to return to the caller."""


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _check_name(name):
    if not name or "\\" in name or name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        raise BundleError(f"unsafe path in the archive: {name!r}")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in name):
        raise BundleError(f"control character in a path: {name!r}")
    parts = PurePosixPath(name).parts
    if ".." in parts:
        raise BundleError(f"path escapes the bundle root: {name!r}")
    if len(name) > MAX_PATH_LENGTH:
        raise BundleError(f"path longer than {MAX_PATH_LENGTH} characters: {name[:60]!r}...")
    for part in parts:
        if part in FORBIDDEN_PARTS:
            raise BundleError(f"`{part}/` is present: {FORBIDDEN_PARTS[part]}")
    # Minified files are accepted: compiled bundles are legitimate. The workflow's inventory reports them as
    # not analysed (GH-007) so the caller can see what the scan could not cover.


def extract(data, workdir, max_bytes, max_files, max_file_bytes):
    """Validates and extracts. Returns the list of bundle-relative paths written."""
    if len(data) > max_bytes:
        raise BundleError(f"the zip is larger than {max_bytes} bytes")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError) as err:
        raise BundleError(f"the upload is not a readable zip archive: {err}") from None

    entries, seen, total = [], set(), 0
    for info in archive.infolist():
        if info.is_dir():
            continue
        _check_name(info.filename)
        mode = info.external_attr >> 16
        if mode and not stat.S_ISREG(mode):
            raise BundleError(f"symlink or special file in the bundle: {info.filename!r}")
        if info.flag_bits & 0x1:
            raise BundleError(f"encrypted entry in the bundle: {info.filename!r}")
        key = info.filename.lower()
        if key in seen:
            raise BundleError(f"duplicate path (case-insensitive): {info.filename!r}")
        seen.add(key)
        if info.file_size > max_file_bytes:
            raise BundleError(f"file larger than {max_file_bytes} bytes: {info.filename!r}")
        total += info.file_size
        if total > 4 * max_bytes:
            raise BundleError("the bundle inflates to more than four times the upload limit")
        entries.append(info)
    if not entries:
        raise BundleError("the bundle contains no files")
    if len(entries) > max_files:
        raise BundleError(f"more than {max_files} files in the bundle")

    root = Path(workdir) / ARTIFACT_DIR
    written = []
    for info in entries:
        target = root / info.filename
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with archive.open(info) as source:
                # Read one byte past the declared size: a lying header cannot inflate past the per-file cap.
                body = source.read(info.file_size + 1)
        except (zipfile.BadZipFile, zlib.error, OSError, RuntimeError, NotImplementedError) as err:
            raise BundleError(f"corrupt entry {info.filename!r}: {err}") from None
        if len(body) != info.file_size:
            raise BundleError(f"declared and actual size differ: {info.filename!r}")
        target.write_bytes(body)
        target.chmod(0o644)
        written.append(info.filename)
    return written


def zip_directory(directory):
    """Zips a local directory in memory (scanctl convenience). Skips nothing: validation happens in extract()."""
    buffer = io.BytesIO()
    base = Path(directory)
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(base.rglob("*")):
            if path.is_file() and not path.is_symlink():
                archive.write(path, path.relative_to(base).as_posix())
    return buffer.getvalue()
