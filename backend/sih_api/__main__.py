"""API entrypoint: `python -m sih_api`. Metrics are served on a separate internal port."""
from __future__ import annotations

import uvicorn
from prometheus_client import start_http_server

from sih_api.app import create_app
from sih_common import env, log as jlog


def main() -> None:
    jlog.setup("api")
    start_http_server(env.env_int("API_METRICS_PORT", 9105))
    uvicorn.run(create_app(), host="0.0.0.0", port=env.env_int("API_PORT", 8080), log_level="warning",
                proxy_headers=False, access_log=False)


if __name__ == "__main__":
    main()
