# Security Notes

## Implemented Controls

- Authenticated encryption: AES-256-GCM
- Forward secrecy pattern for messages/files: ephemeral-static X25519
- Session key derivation isolation: HKDF-SHA256 with random salt
- Sender authenticity and envelope integrity: Ed25519 signatures
- Password hardening: Argon2id (default), PBKDF2 fallback

## Threat Model Coverage (Basic)

Covered:
- Passive eavesdropping on ciphertext
- Basic active tampering with ciphertext/envelope fields
- Sender spoofing without private signing key

Not fully covered:
- Endpoint compromise
- Traffic analysis / metadata privacy
- Advanced side-channel attacks
- Secure private-key-at-rest lifecycle with hardware binding

## Operational Recommendations

- Use strong user passwords for vault mode.
- Protect key directory with strict OS permissions.
- Rotate keys periodically and after suspected compromise.
- Add secure key escrow policy only if compliance requires it.
- For high-value systems, move private keys to HSM/KMS.

## Safe Usage Rules

- Never reuse private keys across untrusted test and production contexts.
- Never send private key files to peers.
- Verify sender identity mapping before trusting any public key.
