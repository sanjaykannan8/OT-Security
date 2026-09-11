"""Local accounts, server-side sessions, role checks, login throttling and an append-only audit log.

Passwords come from provisioned secret files (never committed) and are hashed with argon2id at startup;
only hashes stay in memory. Session tokens are random, stored hashed, HttpOnly + SameSite=Strict.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import secrets
import threading
import time
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

from sih_common import env, timeutil

ROLES = ("analyst", "admin")
COOKIE = "sih_session"


@dataclass
class Session:
    user: str
    role: str
    created: float
    last_seen: float


class AuthStore:
    def __init__(self, users: dict[str, tuple[str, str]], audit_path: pathlib.Path,
                 idle_s: int = 1800, max_age_s: int = 8 * 3600, max_sessions: int = 1000):
        """users: username -> (role, plaintext password); hashed immediately."""
        self._ph = PasswordHasher()
        self._users = {u: (role, self._ph.hash(pw)) for u, (role, pw) in users.items()}
        self._dummy = self._ph.hash(secrets.token_hex(16))
        self._sessions: dict[str, Session] = {}
        self._failures: dict[str, tuple[int, float]] = {}
        self._lock = threading.Lock()
        self.idle_s, self.max_age_s, self.max_sessions = idle_s, max_age_s, max_sessions
        self.audit_path = audit_path
        audit_path.parent.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_env(cls) -> "AuthStore":
        users = {
            env.env_str("API_ADMIN_USER", "admin"): ("admin", env.secret_text("API_ADMIN_PASSWORD_FILE")),
            env.env_str("API_ANALYST_USER", "analyst"): ("analyst", env.secret_text("API_ANALYST_PASSWORD_FILE")),
        }
        return cls(users, pathlib.Path(env.env_str("API_AUDIT_LOG", "/data/api/audit.jsonl")))

    def audit(self, event: str, user: str | None, **fields) -> None:
        rec = {"ts": timeutil.format_us(timeutil.now_us()), "event": event, "user": user, **fields}
        with self._lock, open(self.audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=True) + "\n")

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def login(self, username: str, password: str, client: str) -> tuple[str, Session] | None:
        now = time.time()
        with self._lock:
            count, until = self._failures.get(username, (0, 0.0))
        if until > now:
            self.audit("login_locked", username, client=client)
            return None
        role, hashed = self._users.get(username, (None, self._dummy))
        try:
            self._ph.verify(hashed, password)
            ok = role is not None
        except VerificationError:
            ok = False
        if not ok:
            count += 1
            with self._lock:
                self._failures[username] = (count, now + 60 if count >= 5 else 0.0)
            self.audit("login_failed", username, client=client)
            return None
        token = secrets.token_urlsafe(32)
        s = Session(username, role, now, now)
        with self._lock:
            self._failures.pop(username, None)
            if len(self._sessions) >= self.max_sessions:
                oldest = min(self._sessions, key=lambda k: self._sessions[k].last_seen)
                del self._sessions[oldest]
            self._sessions[self._key(token)] = s
        self.audit("login", username, client=client, role=role)
        return token, s

    def session(self, token: str | None) -> Session | None:
        if not token:
            return None
        now = time.time()
        k = self._key(token)
        with self._lock:
            s = self._sessions.get(k)
            if s is None:
                return None
            if now - s.last_seen > self.idle_s or now - s.created > self.max_age_s:
                del self._sessions[k]
                return None
            s.last_seen = now
            return s

    def logout(self, token: str | None) -> None:
        if token:
            with self._lock:
                s = self._sessions.pop(self._key(token), None)
            if s:
                self.audit("logout", s.user)
