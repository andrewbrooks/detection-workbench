"""Evidence is verified while it is read, so a file cannot change between the check and the use."""
import hashlib
import os

import pytest

from detection_workbench.safety.paths import PathError
from detection_workbench.safety.verified import EvidenceChanged, copy_verified, read_verified

DATA = b"evidence-bytes" * 1000
SHA = hashlib.sha256(DATA).hexdigest()


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "allowed"
    r.mkdir()
    return r.resolve()


@pytest.fixture
def f(root):
    p = root / "a.pcap"
    p.write_bytes(DATA)
    return p


def test_copy_matches_and_is_private(f, root, tmp_path):
    dest = tmp_path / "run" / "input" / "capture.pcap"
    assert copy_verified(f, dest, SHA, [root], 10**6) == len(DATA)
    assert dest.read_bytes() == DATA and oct(dest.stat().st_mode & 0o777) == "0o600"


def test_read_verified_returns_the_bytes(f, root):
    assert read_verified(f, SHA, [root], 10**6) == DATA


def test_modified_file_is_rejected_and_nothing_is_left_behind(f, root, tmp_path):
    f.write_bytes(DATA + b"tampered")
    dest = tmp_path / "out" / "capture.pcap"
    with pytest.raises(EvidenceChanged, match="changed since it was registered"):
        copy_verified(f, dest, SHA, [root], 10**6)
    assert not dest.exists()
    with pytest.raises(EvidenceChanged):
        read_verified(f, SHA, [root], 10**6)


def test_same_size_substitution_is_caught(f, root, tmp_path):
    f.write_bytes(b"X" * len(DATA))
    with pytest.raises(EvidenceChanged):
        copy_verified(f, tmp_path / "o", SHA, [root], 10**6)


def test_symlink_swapped_in_after_registration_is_not_followed(f, root, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_bytes(DATA)  # even identical content must not be reached through a link
    f.unlink()
    f.symlink_to(secret)
    with pytest.raises(PathError, match="symlinks are not followed"):
        copy_verified(f, tmp_path / "o", SHA, [root], 10**6)
    with pytest.raises(PathError):
        read_verified(f, SHA, [root], 10**6)


def test_parent_directory_swapped_for_a_symlink_is_caught_by_the_roots_check(root, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a.pcap").write_bytes(DATA)
    link = root / "sub"
    link.symlink_to(outside)
    if not os.path.isdir("/proc/self/fd"):
        pytest.skip("descriptor path lookup needs /proc")
    with pytest.raises(PathError, match="outside allowed_roots"):
        copy_verified(link / "a.pcap", tmp_path / "o", SHA, [root], 10**6)


def test_non_regular_files_are_refused_without_blocking(root, tmp_path):
    fifo = root / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(PathError, match="not a regular file"):
        copy_verified(fifo, tmp_path / "o", SHA, [root], 10**6)
    with pytest.raises(PathError, match="not a regular file"):
        read_verified(root, SHA, [root], 10**6)  # a directory


def test_size_cap_and_missing_file(f, root, tmp_path):
    with pytest.raises(PathError, match="input cap"):
        copy_verified(f, tmp_path / "o", SHA, [root], 100)
    with pytest.raises(PathError, match="cannot open"):
        copy_verified(root / "nope", tmp_path / "o", SHA, [root], 10**6)


def test_destination_is_never_overwritten(f, root, tmp_path):
    dest = tmp_path / "o"
    dest.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        copy_verified(f, dest, SHA, [root], 10**6)
    assert dest.read_bytes() == b"existing"


def test_read_checked_reads_without_a_hash_and_refuses_links(f, root, tmp_path):
    from detection_workbench.safety.verified import read_checked
    assert read_checked(f, [root], 10**6) == DATA
    link = root / "ln"
    link.symlink_to(f)
    with pytest.raises(PathError, match="symlinks are not followed"):
        read_checked(link, [root], 10**6)
    with pytest.raises(PathError, match="input cap"):
        read_checked(f, [root], 10)


def test_fingerprint_hashes_one_pass_and_keeps_only_a_head(root, tmp_path):
    from detection_workbench.safety.verified import fingerprint
    big = root / "big.bin"
    data = bytes(range(256)) * 1000
    big.write_bytes(data)
    sha, size, head = fingerprint(big, [root], 10**7)
    assert sha == hashlib.sha256(data).hexdigest() and size == len(data) and head == data[:65536]
    with pytest.raises(PathError, match="input cap"):
        fingerprint(big, [root], 100)
    link = root / "ln"
    link.symlink_to(big)
    with pytest.raises(PathError, match="symlinks are not followed"):
        fingerprint(link, [root], 10**7)
