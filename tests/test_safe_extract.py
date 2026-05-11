"""Tests for the safe tar-extraction routine used by snapshot mode.

These exercise ``privmap.cli._safe_extract_tar`` against the class of
malicious archives that CVE-2007-4559 made famous: path traversal,
absolute paths, escaping symlinks/hardlinks, special files, and
oversize archives. They are security-critical because a snapshot
tarball passed via ``--snapshot`` is always operator-controlled at the
time the analyst runs privmap, but the archive itself may originate
from an untrusted host.
"""
import io
import os
import tarfile

import pytest

from privmap.cli import (
    _MAX_SNAPSHOT_BYTES,
    _MAX_SNAPSHOT_MEMBERS,
    _safe_extract_tar,
)


def _make_tar(tmp_path, members):
    """Build a tar.gz at tmp_path/archive.tar.gz from a list of (name, kind, payload) tuples.

    kind is one of: "file", "dir", "symlink", "hardlink", "fifo".
    For files, payload is the bytes content. For links, payload is the
    link target string. For dirs and FIFOs, payload is ignored.
    """
    archive = tmp_path / "archive.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for name, kind, payload in members:
            info = tarfile.TarInfo(name=name)
            if kind == "file":
                data = payload if isinstance(payload, bytes) else payload.encode()
                info.size = len(data)
                info.mode = 0o644
                info.type = tarfile.REGTYPE
                tar.addfile(info, io.BytesIO(data))
            elif kind == "dir":
                info.mode = 0o755
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            elif kind == "symlink":
                info.mode = 0o777
                info.type = tarfile.SYMTYPE
                info.linkname = payload
                tar.addfile(info)
            elif kind == "hardlink":
                info.mode = 0o644
                info.type = tarfile.LNKTYPE
                info.linkname = payload
                tar.addfile(info)
            elif kind == "fifo":
                info.mode = 0o644
                info.type = tarfile.FIFOTYPE
                tar.addfile(info)
            else:
                raise ValueError(f"unknown member kind: {kind}")
    return archive


def _extract(tmp_path, members):
    """Build the archive and attempt extraction. Returns the dest path
    if extraction succeeded; raises whatever _safe_extract_tar raises."""
    archive = _make_tar(tmp_path, members)
    dest = tmp_path / "out"
    dest.mkdir()
    with tarfile.open(archive, "r:gz") as tar:
        _safe_extract_tar(tar, str(dest))
    return dest


class TestHappyPath:
    """A well-formed snapshot must extract cleanly."""

    def test_simple_files_and_dirs(self, tmp_path):
        dest = _extract(tmp_path, [
            ("snapshot/", "dir", None),
            ("snapshot/etc/", "dir", None),
            ("snapshot/etc/passwd", "file", b"root:x:0:0::/root:/bin/bash\n"),
            ("snapshot/etc/group", "file", b"root:x:0:\n"),
        ])
        assert (dest / "snapshot" / "etc" / "passwd").read_bytes().startswith(b"root:")
        assert (dest / "snapshot" / "etc" / "group").is_file()

    def test_relative_symlink_within_dest_is_allowed(self, tmp_path):
        dest = _extract(tmp_path, [
            ("snapshot/", "dir", None),
            ("snapshot/real.txt", "file", b"hello"),
            ("snapshot/link.txt", "symlink", "real.txt"),
        ])
        link = dest / "snapshot" / "link.txt"
        assert link.is_symlink()
        assert os.readlink(link) == "real.txt"


class TestPathTraversal:
    """Members must not escape the destination directory."""

    def test_parent_directory_traversal_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="unsafe path"):
            _extract(tmp_path, [
                ("../escape.txt", "file", b"pwned"),
            ])

    def test_deep_traversal_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="unsafe path"):
            _extract(tmp_path, [
                ("snapshot/../../etc/passwd", "file", b"pwned"),
            ])

    def test_absolute_path_member_rejected(self, tmp_path):
        # When tar contains an absolute path, the resolved target lands
        # outside ``dest`` and must be refused.
        with pytest.raises(ValueError, match="unsafe path"):
            _extract(tmp_path, [
                ("/etc/passwd", "file", b"pwned"),
            ])

    def test_traversal_to_sibling_temp_rejected(self, tmp_path):
        # The destination is tmp_path/out. A member that resolves to
        # tmp_path/sibling must still be rejected because it is not
        # under ``dest``.
        with pytest.raises(ValueError, match="unsafe path"):
            _extract(tmp_path, [
                ("../sibling/file", "file", b"pwned"),
            ])


class TestUnsafeLinks:
    """Symlinks and hardlinks must not point outside the destination."""

    def test_absolute_symlink_target_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="absolute link target"):
            _extract(tmp_path, [
                ("snapshot/", "dir", None),
                ("snapshot/evil", "symlink", "/etc/passwd"),
            ])

    def test_traversing_symlink_target_rejected(self, tmp_path):
        # link target is relative but resolves outside dest.
        with pytest.raises(ValueError, match="escapes snapshot root"):
            _extract(tmp_path, [
                ("snapshot/", "dir", None),
                ("snapshot/evil", "symlink", "../../etc/passwd"),
            ])

    def test_absolute_hardlink_target_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="absolute link target"):
            _extract(tmp_path, [
                ("snapshot/", "dir", None),
                ("snapshot/real", "file", b"x"),
                ("snapshot/evil", "hardlink", "/etc/passwd"),
            ])


class TestSpecialFiles:
    """A snapshot only ever needs regular files, dirs, and symlinks."""

    def test_fifo_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="special file"):
            _extract(tmp_path, [
                ("snapshot/pipe", "fifo", None),
            ])


class TestSizeLimits:
    """Tar bomb defenses: member count and total uncompressed size."""

    def test_member_count_limit(self, tmp_path, monkeypatch):
        # Drive _MAX_SNAPSHOT_MEMBERS down to a tractable value so we
        # do not have to actually pack 200k members into a tarball.
        monkeypatch.setattr("privmap.cli._MAX_SNAPSHOT_MEMBERS", 5)
        members = [
            (f"snapshot/file_{i}.txt", "file", b"x")
            for i in range(10)
        ]
        with pytest.raises(ValueError, match="member limit"):
            _extract(tmp_path, members)

    def test_byte_size_limit(self, tmp_path, monkeypatch):
        # Same idea: cap bytes at something small so we can trigger it
        # without writing 2 GiB.
        monkeypatch.setattr("privmap.cli._MAX_SNAPSHOT_BYTES", 100)
        with pytest.raises(ValueError, match="size limit"):
            _extract(tmp_path, [
                ("snapshot/", "dir", None),
                ("snapshot/big.bin", "file", b"x" * 200),
            ])

    def test_limits_have_reasonable_defaults(self):
        # Sanity check: the production constants should leave room for
        # a realistic whole-system snapshot.
        assert _MAX_SNAPSHOT_MEMBERS >= 100_000
        assert _MAX_SNAPSHOT_BYTES >= 1 * 1024 * 1024 * 1024


class TestExtractionAtomicity:
    """If extraction is refused, nothing should be written."""

    def test_refusal_before_writing_subsequent_members(self, tmp_path):
        archive = _make_tar(tmp_path, [
            ("snapshot/", "dir", None),
            ("snapshot/good.txt", "file", b"ok"),
            ("../escape.txt", "file", b"bad"),
            ("snapshot/after.txt", "file", b"should-not-exist"),
        ])
        dest = tmp_path / "out"
        dest.mkdir()
        with tarfile.open(archive, "r:gz") as tar:
            with pytest.raises(ValueError):
                _safe_extract_tar(tar, str(dest))
        # Members preceding the unsafe one may have been written
        # (the function is not transactional). What MUST be true:
        # nothing escaped dest, and the post-refusal member was not
        # extracted (because extraction stopped at the error).
        assert not (tmp_path / "escape.txt").exists()
        assert not (dest / "after.txt").exists()
