"""Minimal ClickHouse HTTP client (httpx). Queries use server-side parameter binding ({name:Type})."""
from __future__ import annotations

import json
import re
from typing import Iterable, Iterator

import httpx

# Server error codes that mean "this data will never be accepted"; everything else is retried.
PERMANENT_CODES = {6, 26, 27, 38, 41, 53, 62, 69, 70, 72, 117, 130, 131, 344, 386, 473}


class ClickHouseError(Exception):
    def __init__(self, message: str, code: int | None, permanent: bool):
        super().__init__(message)
        self.code = code
        self.permanent = permanent


class ClickHouseHTTP:
    def __init__(self, url: str, user: str, password: str, database: str = "sih", timeout: float = 30.0):
        self.database = database
        self._http = httpx.Client(base_url=url.rstrip("/"), auth=(user, password), timeout=timeout)

    def _post(self, params: dict, body: bytes | str, stream: bool = False):
        params = {"database": self.database, **params}
        try:
            if stream:
                return self._http.stream("POST", "/", params=params, content=body)
            r = self._http.post("/", params=params, content=body)
        except httpx.HTTPError as e:
            raise ClickHouseError(f"clickhouse unavailable: {e}", None, False) from e
        self._raise(r)
        return r

    @staticmethod
    def _raise(r: httpx.Response) -> None:
        if r.status_code < 400:
            return
        text = r.text[:1000]
        m = re.search(r"Code: (\d+)", text)
        code = int(m.group(1)) if m else None
        permanent = code in PERMANENT_CODES or (r.status_code in (400, 404) and code is not None and code != 159)
        raise ClickHouseError(f"clickhouse HTTP {r.status_code}: {text}", code, permanent)

    def query(self, sql: str, params: dict | None = None) -> list[dict]:
        p = {f"param_{k}": v for k, v in (params or {}).items()}
        p.update({"output_format_json_quote_64bit_integers": "0", "date_time_output_format": "iso"})
        r = self._post(p, sql + " FORMAT JSONEachRow")
        return [json.loads(line) for line in r.text.splitlines() if line]

    def command(self, sql: str, params: dict | None = None) -> str:
        p = {f"param_{k}": v for k, v in (params or {}).items()}
        return self._post(p, sql).text

    def insert_json(self, table: str, rows: Iterable[dict]) -> int:
        lines = [json.dumps(r, separators=(",", ":"), ensure_ascii=False, allow_nan=False) for r in rows]
        if not lines:
            return 0
        self._post({"query": f"INSERT INTO {table} FORMAT JSONEachRow", "date_time_input_format": "best_effort",
                    "input_format_skip_unknown_fields": "0"}, ("\n".join(lines) + "\n").encode("utf-8"))
        return len(lines)

    def insert_raw(self, table: str, ndjson: bytes) -> None:
        self._post({"query": f"INSERT INTO {table} FORMAT JSONEachRow", "date_time_input_format": "best_effort"}, ndjson)

    def stream(self, sql: str) -> Iterator[bytes]:
        with self._post({}, sql, stream=True) as r:
            if r.status_code >= 400:
                r.read()
                self._raise(r)
            yield from r.iter_bytes()

    def ping(self) -> bool:
        try:
            return self._http.get("/ping", timeout=3).status_code == 200
        except httpx.HTTPError:
            return False

    def close(self) -> None:
        self._http.close()
