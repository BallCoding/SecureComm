"""Command handlers for securecomm CLI."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from securecomm.cli.formatter import print_error, print_json, print_ok, print_table
from securecomm.crypto.randoms import now_epoch
from securecomm.errors import SecureCommError
from securecomm.services.audit_service import AuditService
from securecomm.services.file_service import FileService
from securecomm.services.key_service import KeyService
from securecomm.services.message_service import MessageService
from securecomm.services.vault_service import VaultService


class CommandContext:
    """Reusable service instances for command execution."""

    def __init__(self, key_root: Path | None = None) -> None:
        self.keys = KeyService(key_root=key_root)
        self.msg = MessageService(key_root=key_root)
        self.files = FileService(key_root=key_root)
        self.vault = VaultService()
        self.audit = AuditService()


class CommandRunner:
    """Dispatch parsed CLI args to concrete handlers."""

    def __init__(self, ctx: CommandContext | None = None) -> None:
        self.ctx = ctx or CommandContext()

    def run(self, args: argparse.Namespace) -> int:
        """Execute selected command and map exceptions to return code."""
        try:
            command = args.command
            if command == "keygen":
                return self.cmd_keygen(args)
            if command == "users":
                return self.cmd_users(args)
            if command == "export-public":
                return self.cmd_export_public(args)
            if command == "import-public":
                return self.cmd_import_public(args)
            if command == "encrypt-text":
                return self.cmd_encrypt_text(args)
            if command == "decrypt-text":
                return self.cmd_decrypt_text(args)
            if command == "encrypt-file":
                return self.cmd_encrypt_file(args)
            if command == "decrypt-file":
                return self.cmd_decrypt_file(args)
            if command == "sign-file":
                return self.cmd_sign_file(args)
            if command == "verify-file":
                return self.cmd_verify_file(args)
            if command == "vault-encrypt":
                return self.cmd_vault_encrypt(args)
            if command == "vault-decrypt":
                return self.cmd_vault_decrypt(args)
            if command == "vault-rotate":
                return self.cmd_vault_rotate(args)
            if command == "audit":
                return self.cmd_audit(args)
            print_error("unknown command")
            return 2
        except SecureCommError as exc:
            print_error(str(exc))
            return 1

    def cmd_keygen(self, args: argparse.Namespace) -> int:
        """Handle key generation."""
        result = self.ctx.keys.create_user(args.user, overwrite=args.overwrite)
        print_ok(f"generated keys for user '{args.user}'")
        print_json(result)
        self._audit(action="keygen", actor=args.user, status="ok", details={"overwrite": args.overwrite})
        return 0

    def cmd_users(self, args: argparse.Namespace) -> int:
        """Handle user listing."""
        users = self.ctx.keys.list_users()
        if args.json:
            print_json({"users": users, "count": len(users)})
        else:
            rows = [{"user": u} for u in users]
            print_table(rows, ["user"])
        return 0

    def cmd_export_public(self, args: argparse.Namespace) -> int:
        """Handle public key export."""
        output = Path(args.output) if args.output else None
        result = self.ctx.keys.export_public_keys(user_id=args.user, output_path=output)
        print_ok(f"exported public bundle for '{args.user}'")
        print_json(result)
        self._audit(action="export_public", actor=args.user, status="ok", details={"output": args.output or "stdout"})
        return 0

    def cmd_import_public(self, args: argparse.Namespace) -> int:
        """Handle public key import."""
        path = Path(args.input)
        payload = self.ctx.keys.load_public_bundle(path)
        result = self.ctx.keys.import_public_keys(payload)
        print_ok(f"imported public keys for '{result['user_id']}'")
        print_json(result)
        self._audit(action="import_public", actor=result["user_id"], status="ok", details={"input": str(path)})
        return 0

    def cmd_encrypt_text(self, args: argparse.Namespace) -> int:
        """Handle text encryption."""
        output = Path(args.output) if args.output else None
        result = self.ctx.msg.encrypt_text(
            sender_id=args.sender,
            recipient_id=args.recipient,
            text=args.text,
            output_path=output,
            aad_text=args.aad,
        )
        print_ok("text encrypted")
        print_json(result)
        self._audit(
            action="encrypt_text",
            actor=args.sender,
            status="ok",
            details={"recipient": args.recipient, "output": args.output or "stdout"},
        )
        return 0

    def cmd_decrypt_text(self, args: argparse.Namespace) -> int:
        """Handle text decryption."""
        result = self.ctx.msg.decrypt_from_file(
            recipient_id=args.recipient,
            sender_id=args.sender,
            input_path=Path(args.input),
        )
        print_ok("text decrypted")
        print_json(result)
        self._audit(
            action="decrypt_text",
            actor=args.recipient,
            status="ok",
            details={"sender": args.sender, "input": args.input},
        )
        return 0

    def cmd_encrypt_file(self, args: argparse.Namespace) -> int:
        """Handle file encryption."""
        output = Path(args.output) if args.output else None
        result = self.ctx.files.encrypt_file(
            sender_id=args.sender,
            recipient_id=args.recipient,
            input_path=Path(args.input),
            output_path=output,
            chunk_size=args.chunk_size,
        )
        print_ok("file encrypted")
        print_json(result)
        self._audit(
            action="encrypt_file",
            actor=args.sender,
            status="ok",
            details={"recipient": args.recipient, "input": args.input, "output": args.output or "stdout"},
        )
        return 0

    def cmd_decrypt_file(self, args: argparse.Namespace) -> int:
        """Handle file decryption."""
        result = self.ctx.files.decrypt_file(
            recipient_id=args.recipient,
            sender_id=args.sender,
            envelope_input=Path(args.input),
            output_path=Path(args.output),
        )
        print_ok("file decrypted")
        print_json(result)
        self._audit(
            action="decrypt_file",
            actor=args.recipient,
            status="ok",
            details={"sender": args.sender, "input": args.input, "output": args.output},
        )
        return 0

    def cmd_sign_file(self, args: argparse.Namespace) -> int:
        """Handle detached signing."""
        output = Path(args.output) if args.output else None
        result = self.ctx.files.sign_file(signer_id=args.signer, input_path=Path(args.input), output_path=output)
        print_ok("file signed")
        print_json(result)
        self._audit(
            action="sign_file",
            actor=args.signer,
            status="ok",
            details={"input": args.input, "output": args.output or "stdout"},
        )
        return 0

    def cmd_verify_file(self, args: argparse.Namespace) -> int:
        """Handle detached signature verification."""
        result = self.ctx.files.verify_file_signature(
            signer_id=args.signer,
            input_path=Path(args.input),
            signature_input=Path(args.signature),
        )
        if result["verified"]:
            print_ok("signature verified")
            code = 0
            status = "ok"
        else:
            print_error("signature invalid")
            code = 1
            status = "fail"
        print_json(result)
        self._audit(
            action="verify_file",
            actor=args.signer,
            status=status,
            details={"input": args.input, "signature": args.signature},
        )
        return code

    def cmd_vault_encrypt(self, args: argparse.Namespace) -> int:
        """Handle password-based vault encryption."""
        output = Path(args.output) if args.output else None
        result = self.ctx.vault.encrypt_text(
            text=args.text,
            password=args.password,
            output_path=output,
            prefer_argon2=not args.pbkdf2,
        )
        print_ok("vault text encrypted")
        print_json(result)
        self._audit(action="vault_encrypt", actor="local", status="ok", details={"output": args.output or "stdout"})
        return 0

    def cmd_vault_decrypt(self, args: argparse.Namespace) -> int:
        """Handle vault decryption."""
        result = self.ctx.vault.decrypt_text(password=args.password, envelope_input=Path(args.input))
        print_ok("vault text decrypted")
        print_json(result)
        self._audit(action="vault_decrypt", actor="local", status="ok", details={"input": args.input})
        return 0

    def cmd_vault_rotate(self, args: argparse.Namespace) -> int:
        """Handle vault password rotation."""
        output = Path(args.output) if args.output else None
        result = self.ctx.vault.rotate_password(
            old_password=args.old_password,
            new_password=args.new_password,
            envelope_input=Path(args.input),
            output_path=output,
            prefer_argon2=not args.pbkdf2,
        )
        print_ok("vault password rotated")
        print_json(result)
        self._audit(action="vault_rotate", actor="local", status="ok", details={"input": args.input, "output": args.output})
        return 0

    def cmd_audit(self, args: argparse.Namespace) -> int:
        """Handle audit queries and summaries."""
        if args.summary:
            summary = self.ctx.audit.summarize()
            print_json(summary)
            return 0

        entries = self.ctx.audit.latest(limit=args.limit)
        rows: list[dict[str, Any]] = []
        for e in entries:
            rows.append(
                {
                    "timestamp": e.timestamp,
                    "action": e.action,
                    "actor": e.actor,
                    "status": e.status,
                }
            )
        if args.json:
            print_json({"entries": [e.to_dict() for e in entries]})
        else:
            print_table(rows, ["timestamp", "action", "actor", "status"])
        return 0

    def _audit(self, action: str, actor: str, status: str, details: dict[str, Any]) -> None:
        """Internal helper for consistent audit event writes."""
        self.ctx.audit.record(
            timestamp=now_epoch(),
            action=action,
            actor=actor,
            status=status,
            details=details,
        )