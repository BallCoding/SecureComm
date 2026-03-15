# Usage Guide

## 1. Initialize users

```bash
python main.py keygen --user alice
python main.py keygen --user bob
```

## 2. Export/import public keys

```bash
python main.py export-public --user alice --output output/alice_public.json
python main.py import-public --input output/alice_public.json
```

## 3. Text encryption

```bash
python main.py encrypt-text --sender alice --recipient bob --text "meeting at 10" --output output/meeting.smsg
python main.py decrypt-text --recipient bob --sender alice --input output/meeting.smsg
```

## 4. File encryption

```bash
python main.py encrypt-file --sender alice --recipient bob --input contract.pdf --output output/contract.sfile
python main.py decrypt-file --recipient bob --sender alice --input output/contract.sfile --output output/contract.decrypted.pdf
```

## 5. Signature verification

```bash
python main.py sign-file --signer alice --input contract.pdf --output output/contract.ssig
python main.py verify-file --signer alice --input contract.pdf --signature output/contract.ssig
```

## 6. Vault operations

```bash
python main.py vault-encrypt --text "backup token" --password "GoodPassword2026" --output output/token.svault
python main.py vault-decrypt --password "GoodPassword2026" --input output/token.svault
python main.py vault-rotate --old-password "GoodPassword2026" --new-password "BetterPwd2026" --input output/token.svault --output output/token2.svault
```

## 7. Audit log

```bash
python main.py audit --summary
python main.py audit --limit 50
```

## 8. Interactive menu

```bash
python main.py
```

Then enter menu number like `1`, `2`, `3`.
