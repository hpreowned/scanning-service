import pytest
from conftest import make_zip

from scansvc.bundle import BundleError, extract, sha256_hex, zip_directory

LIMITS = dict(max_bytes=1_000_000, max_files=5, max_file_bytes=10_000)


def test_good_bundle_lands_under_artifact_as_plain_files(tmp_path):
    paths = extract(make_zip({"index.html": "<p>hi</p>", "js/app.js": "let a = 1"}), tmp_path, **LIMITS)
    assert sorted(paths) == ["index.html", "js/app.js"]
    target = tmp_path / "artifact" / "js" / "app.js"
    assert target.read_text() == "let a = 1"
    assert oct(target.stat().st_mode & 0o777) == "0o644"


@pytest.mark.parametrize("name, fragment", [
    ("../escape.txt", "escapes the bundle root"),
    ("a/../../escape.txt", "escapes the bundle root"),
    ("/etc/passwd", "unsafe path"),
    ("C:/x.txt", "unsafe path"),
    ("a\\b.txt", "unsafe path"),
    ("line\nbreak.js", "control character"),
    ("node_modules/x/index.js", "node_modules"),
    (".git/config", ".git"),
    ("x" * 300 + ".js", "longer than"),
])
def test_unsafe_names_are_refused_before_anything_is_written(tmp_path, name, fragment):
    with pytest.raises(BundleError, match=fragment):
        extract(make_zip({"ok.js": "1", name: "x"}), tmp_path, **LIMITS)
    assert not (tmp_path / "artifact").exists()


def test_minified_files_are_accepted_and_left_to_the_inventory(tmp_path):
    assert extract(make_zip({"assets/app.min.js": "!function(){}()"}), tmp_path, **LIMITS) == ["assets/app.min.js"]


def test_symlink_is_refused(tmp_path):
    with pytest.raises(BundleError, match="symlink"):
        extract(make_zip({"link": "/etc/passwd"}, symlinks=("link",)), tmp_path, **LIMITS)


def test_case_insensitive_duplicates_are_refused(tmp_path):
    with pytest.raises(BundleError, match="duplicate"):
        extract(make_zip({"A.js": "1", "a.js": "2"}), tmp_path, **LIMITS)


def test_limits_are_enforced(tmp_path):
    with pytest.raises(BundleError, match="more than 5 files"):
        extract(make_zip({f"f{i}.js": "1" for i in range(6)}), tmp_path, **LIMITS)
    with pytest.raises(BundleError, match="file larger"):
        extract(make_zip({"big.js": "x" * 10_001}), tmp_path, **LIMITS)
    with pytest.raises(BundleError, match="zip is larger"):
        extract(b"x" * 1_000_001, tmp_path, **LIMITS)


def test_garbage_and_empty_uploads_are_refused(tmp_path):
    with pytest.raises(BundleError, match="not a readable zip"):
        extract(b"definitely not a zip", tmp_path, **LIMITS)
    with pytest.raises(BundleError, match="no files"):
        extract(make_zip({}), tmp_path, **LIMITS)


def test_zip_directory_round_trips(tmp_path):
    source = tmp_path / "src"
    (source / "sub").mkdir(parents=True)
    (source / "sub" / "a.py").write_text("print(1)")
    data = zip_directory(source)
    assert extract(data, tmp_path / "out", **LIMITS) == ["sub/a.py"]
    assert len(sha256_hex(data)) == 64
