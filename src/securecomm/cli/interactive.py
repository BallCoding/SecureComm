"""Interactive menu mode for users who prefer guided CLI."""

from __future__ import annotations

from pathlib import Path

from securecomm.cli.commands import CommandContext
from securecomm.cli.formatter import ask, ask_non_empty, divider, print_error, print_json, print_ok, print_title
from securecomm.errors import SecureCommError


class InteractiveShell:
    """Simple text-based interactive interface."""

    def __init__(self, ctx: CommandContext | None = None) -> None:
        self.ctx = ctx or CommandContext()
        self.running = True

    def run(self) -> int:
        """Start interactive shell loop."""
        print_title("SecureComm Interactive")
        self._print_help()
        while self.running:
            try:
                divider()
                cmd = ask("menu> ").strip().lower()
                if not cmd:
                    continue
                if cmd in {"quit", "exit", "q"}:
                    self.running = False
                    continue
                if cmd in {"help", "h", "?"}:
                    self._print_help()
                    continue
                self._dispatch(cmd)
            except KeyboardInterrupt:
                print()
                self.running = False
            except SecureCommError as exc:
                print_error(str(exc))
            except Exception as exc:
                print_error(f"unexpected error: {exc}")
        print_ok("interactive session ended")
        return 0

    def _dispatch(self, cmd: str) -> None:
        """Dispatch menu command to action handler."""
        actions = {
            "1": self.action_keygen,
            "2": self.action_encrypt_text,
            "3": self.action_decrypt_text,
            "4": self.action_encrypt_file,
            "5": self.action_decrypt_file,
            "6": self.action_sign_file,
            "7": self.action_verify_file,
            "8": self.action_vault_encrypt,
            "9": self.action_vault_decrypt,
            "10": self.action_list_users,
            "11": self.action_audit_summary,
        }
        action = actions.get(cmd)
        if action is None:
            print_error("unknown menu command; use help")
            return
        action()

    def _print_help(self) -> None:
        """Print menu options."""
        print("1  - Generate user key pair")
        print("2  - Encrypt text")
        print("3  - Decrypt text")
        print("4  - Encrypt file")
        print("5  - Decrypt file")
        print("6  - Sign file")
        print("7  - Verify file signature")
        print("8  - Vault encrypt text")
        print("9  - Vault decrypt text")
        print("10 - List users")
        print("11 - Audit summary")
        print("help, h, ? - Show this help")
        print("quit, exit, q - Exit")

    def action_keygen(self) -> None:
        """Interactive key generation."""
        user = ask_non_empty("user id: ")
        overwrite = ask("overwrite existing keys? (y/N): ").lower().startswith("y")
        result = self.ctx.keys.create_user(user, overwrite=overwrite)
        print_ok("keys generated")
        print_json(result)

    def action_encrypt_text(self) -> None:
        """Interactive text encryption."""
        sender = ask_non_empty("sender: ")
        recipient = ask_non_empty("recipient: ")
        text = ask_non_empty("plaintext: ")
        out = ask("output file (optional): ").strip()
        result = self.ctx.msg.encrypt_text(sender_id=sender, recipient_id=recipient, text=text, output_path=Path(out) if out else None)
        print_ok("text encrypted")
        print_json(result)

    def action_decrypt_text(self) -> None:
        """Interactive text decryption."""
        recipient = ask_non_empty("recipient: ")
        sender = ask_non_empty("sender: ")
        path = ask_non_empty("input envelope file: ")
        result = self.ctx.msg.decrypt_from_file(recipient_id=recipient, sender_id=sender, input_path=Path(path))
        print_ok("text decrypted")
        print_json(result)

    def action_encrypt_file(self) -> None:
        """Interactive file encryption."""
        sender = ask_non_empty("sender: ")
        recipient = ask_non_empty("recipient: ")
        src = ask_non_empty("input file: ")
        out = ask("output envelope (optional): ").strip()
        chunk = ask("chunk size bytes (default 65536): ").strip()
        chunk_size = int(chunk) if chunk else 64 * 1024
        result = self.ctx.files.encrypt_file(
            sender_id=sender,
            recipient_id=recipient,
            input_path=Path(src),
            output_path=Path(out) if out else None,
            chunk_size=chunk_size,
        )
        print_ok("file encrypted")
        print_json(result)

    def action_decrypt_file(self) -> None:
        """Interactive file decryption."""
        recipient = ask_non_empty("recipient: ")
        sender = ask_non_empty("sender: ")
        src = ask_non_empty("input envelope: ")
        dst = ask_non_empty("output file: ")
        result = self.ctx.files.decrypt_file(
            recipient_id=recipient,
            sender_id=sender,
            envelope_input=Path(src),
            output_path=Path(dst),
        )
        print_ok("file decrypted")
        print_json(result)

    def action_sign_file(self) -> None:
        """Interactive file signing."""
        signer = ask_non_empty("signer: ")
        src = ask_non_empty("input file: ")
        out = ask("signature output (optional): ").strip()
        result = self.ctx.files.sign_file(signer_id=signer, input_path=Path(src), output_path=Path(out) if out else None)
        print_ok("file signed")
        print_json(result)

    def action_verify_file(self) -> None:
        """Interactive signature verification."""
        signer = ask_non_empty("signer: ")
        src = ask_non_empty("input file: ")
        sig = ask_non_empty("signature file: ")
        result = self.ctx.files.verify_file_signature(signer_id=signer, input_path=Path(src), signature_input=Path(sig))
        if result["verified"]:
            print_ok("signature verified")
        else:
            print_error("signature invalid")
        print_json(result)

    def action_vault_encrypt(self) -> None:
        """Interactive vault encryption."""
        text = ask_non_empty("text: ")
        password = ask_non_empty("password: ")
        out = ask("vault output file (optional): ").strip()
        result = self.ctx.vault.encrypt_text(text=text, password=password, output_path=Path(out) if out else None)
        print_ok("vault encrypted")
        print_json(result)

    def action_vault_decrypt(self) -> None:
        """Interactive vault decryption."""
        password = ask_non_empty("password: ")
        inp = ask_non_empty("vault input file: ")
        result = self.ctx.vault.decrypt_text(password=password, envelope_input=Path(inp))
        print_ok("vault decrypted")
        print_json(result)

    def action_list_users(self) -> None:
        """Interactive list users."""
        users = self.ctx.keys.list_users()
        print_json({"users": users, "count": len(users)})

    def action_audit_summary(self) -> None:
        """Interactive audit summary."""
        print_json(self.ctx.audit.summarize())