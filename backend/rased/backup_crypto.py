"""Streaming authenticated encryption for database backup files (AES-256-GCM, scrypt KDF).

File format (all lengths in bytes):
    magic "RASEDBK1" (8) | salt (16) | nonce (12) | ciphertext (n) | GCM tag (16)

Decryption writes to a temporary file and only moves it into place after the GCM tag has
been verified, so a corrupted or tampered backup can never be partially restored.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"RASEDBK1"
SALT_LEN, NONCE_LEN, TAG_LEN = 16, 12, 16
CHUNK = 1024 * 1024
MIN_PASSPHRASE = 16


class BackupError(Exception):
    """Arabic, user-facing message."""


def _key(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < MIN_PASSPHRASE:
        raise BackupError(f"يجب ألا تقل عبارة مرور النسخ الاحتياطي عن {MIN_PASSPHRASE} حرفاً")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode("utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def encrypt_file(src: Path, dst: Path, passphrase: str) -> str:
    salt, nonce = os.urandom(SALT_LEN), os.urandom(NONCE_LEN)
    encryptor = Cipher(algorithms.AES(_key(passphrase, salt)), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(MAGIC)
    tmp = dst.with_name(dst.name + ".partial")
    with src.open("rb") as fin, tmp.open("wb") as fout:
        fout.write(MAGIC + salt + nonce)
        for block in iter(lambda: fin.read(CHUNK), b""):
            fout.write(encryptor.update(block))
        fout.write(encryptor.finalize())
        fout.write(encryptor.tag)
    os.replace(tmp, dst)
    return sha256_file(dst)


def decrypt_file(src: Path, dst: Path, passphrase: str) -> None:
    size = src.stat().st_size
    header_len = len(MAGIC) + SALT_LEN + NONCE_LEN
    if size < header_len + TAG_LEN:
        raise BackupError("ملف النسخة الاحتياطية تالف أو غير مكتمل")
    tmp = dst.with_name(dst.name + ".partial")
    try:
        with src.open("rb") as fin:
            header = fin.read(header_len)
            if header[: len(MAGIC)] != MAGIC:
                raise BackupError("الملف ليس نسخة احتياطية مشفرة من راصد")
            salt = header[len(MAGIC) : len(MAGIC) + SALT_LEN]
            nonce = header[len(MAGIC) + SALT_LEN :]
            fin.seek(size - TAG_LEN)
            tag = fin.read(TAG_LEN)
            fin.seek(header_len)
            decryptor = Cipher(algorithms.AES(_key(passphrase, salt)), modes.GCM(nonce, tag)).decryptor()
            decryptor.authenticate_additional_data(MAGIC)
            remaining = size - header_len - TAG_LEN
            with tmp.open("wb") as fout:
                while remaining > 0:
                    block = fin.read(min(CHUNK, remaining))
                    if not block:
                        raise BackupError("ملف النسخة الاحتياطية غير مكتمل")
                    remaining -= len(block)
                    fout.write(decryptor.update(block))
                try:
                    fout.write(decryptor.finalize())
                except InvalidTag as exc:
                    raise BackupError("فشل التحقق من سلامة النسخة الاحتياطية: عبارة المرور خاطئة أو الملف معدّل") from exc
        os.replace(tmp, dst)
    finally:
        if tmp.exists():
            tmp.unlink()
