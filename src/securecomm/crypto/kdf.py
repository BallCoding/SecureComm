"""Key derivation functions and password-hardening helpers."""

from __future__ import annotations

from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from securecomm.constants import (
    DEFAULT_ARGON2_HASH_BYTES,
    DEFAULT_ARGON2_MEMORY_COST,
    DEFAULT_ARGON2_PARALLELISM,
    DEFAULT_ARGON2_SALT_BYTES,
    DEFAULT_ARGON2_TIME_COST,
    DEFAULT_PBKDF2_ITERATIONS,
    DEFAULT_PBKDF2_SALT_BYTES,
)
from securecomm.crypto.randoms import random_bytes


@dataclass(slots=True)
class Argon2Config:
    """Configuration for Argon2id password KDF."""

    time_cost: int = DEFAULT_ARGON2_TIME_COST
    memory_cost: int = DEFAULT_ARGON2_MEMORY_COST
    parallelism: int = DEFAULT_ARGON2_PARALLELISM
    hash_len: int = DEFAULT_ARGON2_HASH_BYTES
    salt_len: int = DEFAULT_ARGON2_SALT_BYTES


@dataclass(slots=True)
class PBKDF2Config:
    """Configuration for PBKDF2 fallback."""

    iterations: int = DEFAULT_PBKDF2_ITERATIONS
    salt_len: int = DEFAULT_PBKDF2_SALT_BYTES


def hkdf_sha256(key_material: bytes, length: int, salt: bytes, info: bytes) -> bytes:
    """Derive fixed-length key from key material using HKDF-SHA256."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(key_material)


def argon2id_derive(password: str, salt: bytes, config: Argon2Config | None = None) -> bytes:
    """Derive key from password using Argon2id."""
    cfg = config or Argon2Config()
    secret = password.encode("utf-8")
    return hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=cfg.time_cost,
        memory_cost=cfg.memory_cost,
        parallelism=cfg.parallelism,
        hash_len=cfg.hash_len,
        type=Type.ID,
    )


def pbkdf2_derive(password: str, salt: bytes, length: int = 32, config: PBKDF2Config | None = None) -> bytes:
    """Derive key from password using PBKDF2-HMAC-SHA256."""
    cfg = config or PBKDF2Config()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=cfg.iterations)
    return kdf.derive(password.encode("utf-8"))


def derive_password_key(password: str, prefer_argon2: bool = True, length: int = 32) -> tuple[str, bytes, bytes, dict[str, int]]:
    """Derive password key with metadata and algorithm tag.

    Returns:
        (algorithm, salt, key, params)
    """
    if prefer_argon2:
        cfg = Argon2Config(hash_len=length)
        salt = random_bytes(cfg.salt_len)
        key = argon2id_derive(password=password, salt=salt, config=cfg)
        params = {
            "time_cost": cfg.time_cost,
            "memory_cost": cfg.memory_cost,
            "parallelism": cfg.parallelism,
            "hash_len": cfg.hash_len,
            "salt_len": cfg.salt_len,
        }
        return "argon2id", salt, key, params

    cfg_pbkdf2 = PBKDF2Config()
    salt_pbkdf2 = random_bytes(cfg_pbkdf2.salt_len)
    key_pbkdf2 = pbkdf2_derive(password=password, salt=salt_pbkdf2, length=length, config=cfg_pbkdf2)
    params_pbkdf2 = {"iterations": cfg_pbkdf2.iterations, "salt_len": cfg_pbkdf2.salt_len, "length": length}
    return "pbkdf2", salt_pbkdf2, key_pbkdf2, params_pbkdf2


def restore_password_key(password: str, algorithm: str, salt: bytes, params: dict[str, int], length: int = 32) -> bytes:
    """Re-derive password key from stored metadata."""
    if algorithm == "argon2id":
        cfg = Argon2Config(
            time_cost=int(params.get("time_cost", DEFAULT_ARGON2_TIME_COST)),
            memory_cost=int(params.get("memory_cost", DEFAULT_ARGON2_MEMORY_COST)),
            parallelism=int(params.get("parallelism", DEFAULT_ARGON2_PARALLELISM)),
            hash_len=int(params.get("hash_len", length)),
            salt_len=int(params.get("salt_len", len(salt))),
        )
        return argon2id_derive(password=password, salt=salt, config=cfg)

    iterations = int(params.get("iterations", DEFAULT_PBKDF2_ITERATIONS))
    cfg_pbkdf2 = PBKDF2Config(iterations=iterations, salt_len=int(params.get("salt_len", len(salt))))
    out_len = int(params.get("length", length))
    return pbkdf2_derive(password=password, salt=salt, length=out_len, config=cfg_pbkdf2)