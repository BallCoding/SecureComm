"""Argument parser definitions for securecomm CLI."""

from __future__ import annotations

import argparse

from securecomm.constants import VERSION


def build_parser() -> argparse.ArgumentParser:
    """Build top-level argparse parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="securecomm",
        description="Secure communication toolkit for text/files",
    )
    parser.add_argument("--version", action="version", version=f"securecomm {VERSION}")

    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="generate key pair for user")
    keygen.add_argument("--user", required=True, help="user id")
    keygen.add_argument("--overwrite", action="store_true", help="overwrite existing keys")

    users = sub.add_parser("users", help="list known users")
    users.add_argument("--json", action="store_true", help="output JSON")

    exp = sub.add_parser("export-public", help="export public keys")
    exp.add_argument("--user", required=True, help="user id")
    exp.add_argument("--output", help="output json file")

    imp = sub.add_parser("import-public", help="import public keys")
    imp.add_argument("--input", required=True, help="public bundle json path")

    et = sub.add_parser("encrypt-text", help="encrypt text message")
    et.add_argument("--sender", required=True, help="sender user id")
    et.add_argument("--recipient", required=True, help="recipient user id")
    et.add_argument("--text", required=True, help="plaintext message")
    et.add_argument("--aad", default="", help="optional additional authenticated data")
    et.add_argument("--output", help="output envelope path")

    dt = sub.add_parser("decrypt-text", help="decrypt text message")
    dt.add_argument("--recipient", required=True, help="recipient user id")
    dt.add_argument("--sender", required=True, help="sender user id")
    dt.add_argument("--input", required=True, help="encrypted envelope path")

    ef = sub.add_parser("encrypt-file", help="encrypt file")
    ef.add_argument("--sender", required=True, help="sender user id")
    ef.add_argument("--recipient", required=True, help="recipient user id")
    ef.add_argument("--input", required=True, help="input file path")
    ef.add_argument("--output", help="output encrypted envelope path")
    ef.add_argument("--chunk-size", type=int, default=64 * 1024, help="chunk size in bytes")

    df = sub.add_parser("decrypt-file", help="decrypt file")
    df.add_argument("--recipient", required=True, help="recipient user id")
    df.add_argument("--sender", required=True, help="sender user id")
    df.add_argument("--input", required=True, help="encrypted envelope path")
    df.add_argument("--output", required=True, help="output plaintext file path")

    sf = sub.add_parser("sign-file", help="create detached file signature")
    sf.add_argument("--signer", required=True, help="signer user id")
    sf.add_argument("--input", required=True, help="file to sign")
    sf.add_argument("--output", help="output signature file path")

    vf = sub.add_parser("verify-file", help="verify detached file signature")
    vf.add_argument("--signer", required=True, help="signer user id")
    vf.add_argument("--input", required=True, help="file path")
    vf.add_argument("--signature", required=True, help="signature envelope path")

    ve = sub.add_parser("vault-encrypt", help="password encrypt text")
    ve.add_argument("--text", required=True, help="text to encrypt")
    ve.add_argument("--password", required=True, help="encryption password")
    ve.add_argument("--output", help="vault output path")
    ve.add_argument("--pbkdf2", action="store_true", help="use PBKDF2 instead of Argon2id")

    vd = sub.add_parser("vault-decrypt", help="password decrypt text")
    vd.add_argument("--password", required=True, help="decryption password")
    vd.add_argument("--input", required=True, help="vault file path")

    vr = sub.add_parser("vault-rotate", help="rotate vault password")
    vr.add_argument("--old-password", required=True, help="old password")
    vr.add_argument("--new-password", required=True, help="new password")
    vr.add_argument("--input", required=True, help="existing vault file")
    vr.add_argument("--output", required=True, help="new vault file")
    vr.add_argument("--pbkdf2", action="store_true", help="use PBKDF2 instead of Argon2id")

    audit = sub.add_parser("audit", help="audit log operations")
    audit.add_argument("--limit", type=int, default=20, help="latest entry count")
    audit.add_argument("--summary", action="store_true", help="show summary only")
    audit.add_argument("--json", action="store_true", help="output JSON")

    return parser