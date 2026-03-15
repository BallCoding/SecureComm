# Architecture

## Layers

1. Crypto layer (`src/securecomm/crypto`)
- Primitive wrappers (AES-GCM, X25519, Ed25519)
- KDF support (HKDF, Argon2id, PBKDF2)
- Envelope models for text/file/signature/vault

2. Service layer (`src/securecomm/services`)
- Key lifecycle management
- Text encryption/decryption orchestration
- File encryption/decryption orchestration
- Detached signature workflows
- Vault workflows
- Audit logging

3. Interface layer (`src/securecomm/cli`)
- `argparse` command surface
- Interactive guided menu
- JSON/table output formatters

## Text Workflow

1. Sender loads local private signing key and recipient public encryption key.
2. Sender generates ephemeral X25519 keypair.
3. Sender derives session key via ECDH + HKDF.
4. Sender encrypts plaintext using AES-256-GCM.
5. Sender signs canonical JSON envelope with Ed25519.
6. Recipient verifies signature and decrypts payload.

## File Workflow

1. Split file into chunks.
2. Encrypt each chunk with AES-256-GCM using deterministic per-chunk nonce derived from random seed.
3. Sign full envelope metadata + encrypted chunks.
4. Recipient verifies signature and each chunk nonce relation, then decrypts and reconstructs file.

## Vault Workflow

1. Derive key from password (Argon2id default).
2. Encrypt JSON payload with AES-256-GCM.
3. Store KDF parameters and salt in envelope metadata.
4. Re-derive key for decryption.

## Extension Points

- Replace local key storage with KMS/HSM provider.
- Add certificate-backed identity mapping.
- Add network transport layer (HTTP/gRPC/WebSocket) over envelope payloads.
