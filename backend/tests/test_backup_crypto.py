import os

import pytest

from rased.backup_crypto import BackupError, decrypt_file, encrypt_file, sha256_file
from rased.cli import main

PASS = "correct horse battery staple 2026"


def test_roundtrip_large_file(tmp_path):
    src = tmp_path / "dump.bin"
    src.write_bytes(os.urandom(3 * 1024 * 1024 + 123))  # spans several chunks
    enc, out = tmp_path / "dump.enc", tmp_path / "restored.bin"
    digest = encrypt_file(src, enc, PASS)
    assert digest == sha256_file(enc) and enc.read_bytes()[:8] == b"RASEDBK1"
    decrypt_file(enc, out, PASS)
    assert out.read_bytes() == src.read_bytes()


def test_wrong_passphrase_and_tampering_never_produce_output(tmp_path):
    src, enc, out = tmp_path / "a", tmp_path / "a.enc", tmp_path / "a.out"
    src.write_bytes(b"pg_dump content" * 1000)
    encrypt_file(src, enc, PASS)
    with pytest.raises(BackupError):
        decrypt_file(enc, out, "wrong passphrase but long enough")
    assert not out.exists()
    data = bytearray(enc.read_bytes())
    data[100] ^= 0x01
    enc.write_bytes(bytes(data))
    with pytest.raises(BackupError):
        decrypt_file(enc, out, PASS)
    assert not out.exists() and not (tmp_path / "a.out.partial").exists()


@pytest.mark.parametrize("content", [b"", b"RASEDBK1short", b"NOTRASED" + b"\x00" * 64])
def test_invalid_backup_files_rejected(tmp_path, content):
    enc = tmp_path / "bad.enc"
    enc.write_bytes(content)
    with pytest.raises(BackupError):
        decrypt_file(enc, tmp_path / "out", PASS)


def test_short_passphrase_rejected(tmp_path):
    src = tmp_path / "a"
    src.write_bytes(b"x")
    with pytest.raises(BackupError):
        encrypt_file(src, tmp_path / "a.enc", "short")


def test_cli_roundtrip_writes_checksum(tmp_path, monkeypatch):
    src = tmp_path / "dump.sql"
    src.write_text("SELECT 1;", encoding="utf-8")
    monkeypatch.setenv("RASED_BACKUP_PASSPHRASE", PASS)
    assert main(["encrypt-file", str(src), str(tmp_path / "dump.enc")]) == 0
    assert (tmp_path / "dump.enc.sha256").read_text().split()[0] == sha256_file(tmp_path / "dump.enc")
    assert main(["decrypt-file", str(tmp_path / "dump.enc"), str(tmp_path / "back.sql")]) == 0
    assert (tmp_path / "back.sql").read_text(encoding="utf-8") == "SELECT 1;"
