"""Integration tests for securecomm major workflows."""

from __future__ import annotations

import os
import shutil
import sys
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
VENDOR = ROOT / "vendor"
if str(VENDOR) not in sys.path and VENDOR.exists():
    sys.path.insert(0, str(VENDOR))
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from securecomm.services.file_service import FileService
from securecomm.services.key_service import KeyService
from securecomm.services.message_service import MessageService
from securecomm.services.vault_service import VaultService


class SecureCommWorkflowTests(unittest.TestCase):
    """End-to-end tests over text/file/vault/signature functions."""

    def setUp(self) -> None:
        tmp_root = ROOT / "tests" / ".tmp"
        tmp_root.mkdir(parents=True, exist_ok=True)
        self.base = tmp_root / f"run-{uuid.uuid4().hex}"
        self.base.mkdir(parents=True, exist_ok=True)

        self.key_root = self.base / "keys"
        self.out = self.base / "out"
        self.out.mkdir(parents=True, exist_ok=True)

        self.keys = KeyService(key_root=self.key_root)
        self.msg = MessageService(key_root=self.key_root)
        self.files = FileService(key_root=self.key_root)
        self.vault = VaultService()

        self.keys.create_user("alice")
        self.keys.create_user("bob")

    def tearDown(self) -> None:
        shutil.rmtree(self.base, ignore_errors=True)

    def test_text_encrypt_decrypt(self) -> None:
        """Alice encrypts text to Bob; Bob decrypts with sender verification."""
        envelope_path = self.out / "hello.smsg"
        enc = self.msg.encrypt_text(
            sender_id="alice",
            recipient_id="bob",
            text="secret text message 123",
            output_path=envelope_path,
            aad_text="course-project",
        )
        self.assertEqual(enc["sender"], "alice")
        self.assertTrue(Path(enc["output_path"]).exists())

        dec = self.msg.decrypt_from_file(recipient_id="bob", sender_id="alice", input_path=envelope_path)
        self.assertEqual(dec["text"], "secret text message 123")

    def test_file_encrypt_decrypt(self) -> None:
        """Encrypt and decrypt random binary file."""
        plain = self.out / "sample.bin"
        plain.write_bytes(os.urandom(200_000))

        env_path = self.out / "sample.sfile"
        recovered = self.out / "sample-recovered.bin"

        enc = self.files.encrypt_file(
            sender_id="alice",
            recipient_id="bob",
            input_path=plain,
            output_path=env_path,
            chunk_size=32 * 1024,
        )
        self.assertTrue(Path(enc["output_path"]).exists())

        dec = self.files.decrypt_file(
            recipient_id="bob",
            sender_id="alice",
            envelope_input=env_path,
            output_path=recovered,
        )
        self.assertEqual(dec["sha256"], enc["source_sha256"])
        self.assertEqual(plain.read_bytes(), recovered.read_bytes())

    def test_sign_and_verify(self) -> None:
        """Create detached signature and verify it."""
        target = self.out / "doc.txt"
        target.write_text("confidential report", encoding="utf-8")

        sig_path = self.out / "doc.ssig"
        signed = self.files.sign_file(signer_id="alice", input_path=target, output_path=sig_path)
        self.assertTrue(Path(signed["output_path"]).exists())

        verify = self.files.verify_file_signature(
            signer_id="alice",
            input_path=target,
            signature_input=sig_path,
        )
        self.assertTrue(verify["verified"])

    def test_vault_encrypt_decrypt(self) -> None:
        """Encrypt/decrypt text in password vault."""
        vault_path = self.out / "note.svault"
        password = "GoodPassword2026"
        enc = self.vault.encrypt_text(text="vault-secret", password=password, output_path=vault_path)
        self.assertTrue(Path(enc["output_path"]).exists())

        dec = self.vault.decrypt_text(password=password, envelope_input=vault_path)
        self.assertEqual(dec["text"], "vault-secret")

    def test_vault_rotate_password(self) -> None:
        """Rotate vault encryption password and validate new password works."""
        old_pwd = "StrongPwd2026A"
        new_pwd = "BetterPwd2026B"

        src = self.out / "before.svault"
        dst = self.out / "after.svault"
        self.vault.encrypt_text(text="rotation data", password=old_pwd, output_path=src)

        rotated = self.vault.rotate_password(
            old_password=old_pwd,
            new_password=new_pwd,
            envelope_input=src,
            output_path=dst,
        )
        self.assertTrue(rotated["rotated"])

        dec = self.vault.decrypt_text(password=new_pwd, envelope_input=dst)
        self.assertEqual(dec["text"], "rotation data")


if __name__ == "__main__":
    unittest.main()
