"""Command-line administration: ``python -m rasednet <command>``."""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select


def _settings():  # type: ignore[no-untyped-def]
    from rasednet.config import get_settings

    return get_settings()


def cmd_init_db(_: argparse.Namespace) -> int:
    from rasednet.db import Database
    from rasednet.migrations_util import upgrade_to_head
    from rasednet.seed import seed_reference_data

    settings = _settings()
    upgrade_to_head(settings.database_url)
    db = Database(settings.database_url)
    with db.session() as session:
        seed_reference_data(session)
    db.dispose()
    print("تم تهيئة قاعدة البيانات وتحديثها إلى أحدث إصدار.")
    return 0


def cmd_create_admin(args: argparse.Namespace) -> int:
    from rasednet.db import Database
    from rasednet.models import Role, User, utcnow
    from rasednet.security.passwords import hash_password, password_policy_errors

    settings = _settings()
    username = args.username.strip().lower()
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        password = getpass.getpass("كلمة المرور: ")
        if password != getpass.getpass("تأكيد كلمة المرور: "):
            print("كلمتا المرور غير متطابقتين.", file=sys.stderr)
            return 2
    errors = password_policy_errors(password, username, settings.password_min_length)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 2
    db = Database(settings.database_url)
    try:
        with db.session() as session:
            if session.scalar(select(User).where(User.username == username)) is not None:
                print("اسم المستخدم موجود بالفعل.", file=sys.stderr)
                return 1
            role = session.scalar(select(Role).where(Role.name == "admin"))
            if role is None:
                print("قاعدة البيانات غير مهيأة. شغّل: python -m rasednet init-db", file=sys.stderr)
                return 1
            session.add(
                User(
                    username=username, display_name=args.display_name or username,
                    password_hash=hash_password(password), role=role, is_active=True,
                    failed_login_count=0, password_changed_at=utcnow(), created_at=utcnow(),
                )
            )
    finally:
        db.dispose()
    print(f"تم إنشاء المسؤول {username}.")
    return 0


def cmd_import_oui(args: argparse.Namespace) -> int:
    from rasednet.db import Database
    from rasednet.discovery.oui import parse_ieee_oui_csv
    from rasednet.models import OuiVendor

    content = Path(args.file).read_text(encoding="utf-8", errors="replace")
    entries = dict(parse_ieee_oui_csv(content))
    if not entries:
        print("لم يتم العثور على أي سجلات صالحة في الملف.", file=sys.stderr)
        return 1
    db = Database(_settings().database_url)
    try:
        with db.session() as session:
            existing = set(session.scalars(select(OuiVendor.prefix)))
            for prefix, vendor in entries.items():
                if prefix in existing:
                    session.get(OuiVendor, prefix).vendor = vendor  # type: ignore[union-attr]
                else:
                    session.add(OuiVendor(prefix=prefix, vendor=vendor))
    finally:
        db.dispose()
    print(f"تم استيراد {len(entries)} سجلاً من قاعدة بيانات مصنعي بطاقات الشبكة.")
    return 0


def cmd_gen_cert(args: argparse.Namespace) -> int:
    """Self-signed certificate for local HTTPS (replace with an internal-CA certificate in production)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    names: list[x509.GeneralName] = [x509.DNSName("localhost")]
    for host in args.hostname:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))
    names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.hostname[0] if args.hostname else "localhost"),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RasedNet local")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=args.days))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    (out / "rasednet.key").write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    (out / "rasednet.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"تم إنشاء الشهادة في {out}. احمِ ملف المفتاح rasednet.key بصلاحيات نظام الملفات.")
    return 0


def _passphrase(args: argparse.Namespace) -> str:
    import os

    env = os.environ.get("RASEDNET_BACKUP_PASSPHRASE")
    if env:
        return env
    if args.passphrase_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    return getpass.getpass("عبارة مرور النسخ الاحتياطي: ")


def cmd_encrypt_file(args: argparse.Namespace) -> int:
    from rasednet.backup_crypto import BackupError, encrypt_file

    try:
        digest = encrypt_file(Path(args.src), Path(args.dst), _passphrase(args))
    except BackupError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    Path(args.dst + ".sha256").write_text(f"{digest}  {Path(args.dst).name}\n", encoding="ascii")
    print(f"تم التشفير. بصمة SHA-256: {digest}")
    return 0


def cmd_decrypt_file(args: argparse.Namespace) -> int:
    from rasednet.backup_crypto import BackupError, decrypt_file

    try:
        decrypt_file(Path(args.src), Path(args.dst), _passphrase(args))
    except BackupError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print("تم فك التشفير والتحقق من سلامة الملف.")
    return 0


def cmd_gen_secret_key(_: argparse.Namespace) -> int:
    from cryptography.fernet import Fernet

    print(Fernet.generate_key().decode("ascii"))
    return 0


def cmd_forward(args: argparse.Namespace) -> int:
    """Forward this (collector) instance's inventory to a central RasedNet over HTTPS."""
    import json
    import ssl
    import urllib.request

    from rasednet.collectors import build_forward_payload
    from rasednet.db import Database

    db = Database(_settings().database_url)
    with db.session_factory() as session:
        payload = build_forward_payload(session)
    data = json.dumps(payload).encode("utf-8")
    url = args.server.rstrip("/") + "/api/collectors/report"
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json", "X-Agent-Token": args.token})
    ctx = ssl.create_default_context()
    if args.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:  # nosec B310 - operator-provided https URL
        print(resp.read().decode("utf-8", "replace"))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from rasednet.app import create_app

    ssl_kwargs = {}
    if args.cert and args.key:
        ssl_kwargs = {"ssl_certfile": args.cert, "ssl_keyfile": args.key}
    elif _settings().cookie_secure:
        print("تحذير: RASEDNET_COOKIE_SECURE=true يتطلب HTTPS. مرّر --cert و --key.", file=sys.stderr)
    # A single worker process: scan jobs and rate limiters live in this process.
    uvicorn.run(create_app(), host=args.host, port=args.port, workers=1, proxy_headers=False,
                server_header=False, log_config=None, timeout_keep_alive=30,
                timeout_graceful_shutdown=20, **ssl_kwargs)
    return 0


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    parser = argparse.ArgumentParser(prog="rasednet", description="RasedNet administration")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="apply migrations and seed reference data").set_defaults(func=cmd_init_db)

    p = sub.add_parser("create-admin", help="create an administrator account")
    p.add_argument("--username", required=True)
    p.add_argument("--display-name")
    p.add_argument("--password-stdin", action="store_true", help="read the password from standard input")
    p.set_defaults(func=cmd_create_admin)

    p = sub.add_parser("import-oui", help="import the IEEE MA-L registry CSV (oui.csv)")
    p.add_argument("file")
    p.set_defaults(func=cmd_import_oui)

    p = sub.add_parser("gen-cert", help="generate a self-signed TLS certificate")
    p.add_argument("--out-dir", default="certs")
    p.add_argument("--hostname", action="append", default=[])
    p.add_argument("--days", type=int, default=825)
    p.set_defaults(func=cmd_gen_cert)

    for name, func, help_text in (
        ("encrypt-file", cmd_encrypt_file, "encrypt a backup file (AES-256-GCM)"),
        ("decrypt-file", cmd_decrypt_file, "decrypt and verify a backup file"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("src")
        p.add_argument("dst")
        p.add_argument("--passphrase-stdin", action="store_true")
        p.set_defaults(func=func)

    sub.add_parser("gen-secret-key", help="print a new key for RASEDNET_SECRET_KEY (credential vault)").set_defaults(func=cmd_gen_secret_key)

    p = sub.add_parser("forward", help="forward this collector's inventory to a central RasedNet")
    p.add_argument("--server", required=True, help="central RasedNet base URL, e.g. https://rasednet.corp:8765")
    p.add_argument("--token", required=True, help="collector enrollment token (from the central server)")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    p.set_defaults(func=cmd_forward)

    p = sub.add_parser("serve", help="run the web server")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--cert")
    p.add_argument("--key")
    p.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    return int(args.func(args))
