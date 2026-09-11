"""Environment and secret-file configuration. Secrets are read from files, never from env values."""
from __future__ import annotations

import os
import pathlib


def env_str(name: str, default: str) -> str:
    v = os.environ.get(name, "").strip()
    return v or default


def required(name: str) -> str:
    v = os.environ.get(name, "").strip()
    if not v:
        raise RuntimeError(f"missing required environment variable {name}")
    return v


def env_int(name: str, default: int) -> int:
    v = os.environ.get(name, "").strip()
    return int(v) if v else default


def env_float(name: str, default: float) -> float:
    v = os.environ.get(name, "").strip()
    return float(v) if v else default


def env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name, "").strip().lower()
    return default if not v else v in ("1", "true", "yes", "on")


def secret_file(env_name: str) -> bytes:
    """Reads the secret file named by `env_name`; surrounding whitespace is stripped."""
    path = pathlib.Path(required(env_name))
    try:
        data = path.read_bytes().strip()
    except OSError as e:
        raise RuntimeError(f"cannot read secret file {path}: {e}") from e
    if not data:
        raise RuntimeError(f"secret file {path} is empty")
    return data


def secret_text(env_name: str) -> str:
    return secret_file(env_name).decode("utf-8")


def atomic_write(path: pathlib.Path, data: bytes) -> None:
    """Write temp file, fsync, rename over target, fsync directory."""
    path = pathlib.Path(path)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    try:
        dfd = os.open(path.parent, os.O_RDONLY)
    except OSError:
        return  # directories cannot be opened on some platforms
    try:
        os.fsync(dfd)
    except OSError:
        pass
    finally:
        os.close(dfd)
