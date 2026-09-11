"""Idempotent job supervisor for the Flink session cluster.

Every few seconds: if no sih-detection job is active, submit it, restoring from the newest complete
retained checkpoint in MinIO (a checkpoint is complete once its _metadata object exists). This covers
worker loss (Flink restarts tasks itself), JobManager restarts and full Compose restarts without anyone
pasting checkpoint paths. Old job checkpoint directories beyond the newest few are pruned.
"""
from __future__ import annotations

import json
import logging
import os
import pathlib
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request

from prometheus_client import Counter, Gauge, start_http_server

from sih_common import env, log as jlog

log = logging.getLogger("supervisor")
JOB_NAME = "sih-detection"
ACTIVE = {"CREATED", "RUNNING", "RESTARTING", "INITIALIZING", "RECONCILING", "FAILING", "CANCELLING", "SUSPENDED"}
CHK = re.compile(r"^checkpoints/([0-9a-f]{32})/chk-(\d+)/_metadata$")

RUNNING = Gauge("sih_supervisor_job_running", "1 when the detection job is active")
SUBMITS = Counter("sih_supervisor_submissions_total", "Job submissions", ["mode"])
FAILED_SUBMITS = Counter("sih_supervisor_submission_failures_total", "Failed job submissions")


def rest_jobs(base: str) -> list[dict] | None:
    try:
        with urllib.request.urlopen(f"{base}/jobs/overview", timeout=5) as r:
            return json.load(r).get("jobs", [])
    except (urllib.error.URLError, OSError, ValueError):
        return None


def s3():
    from minio import Minio
    return Minio(env.env_str("MINIO_ENDPOINT", "minio:9000"), access_key=env.env_str("MINIO_FLINK_USER", "flink"),
                 secret_key=env.secret_text("MINIO_FLINK_SECRET_FILE"), secure=False)


def latest_checkpoint(client, bucket: str = "flink-checkpoints") -> tuple[str | None, list[str]]:
    """Newest complete checkpoint path and job directories ordered newest first."""
    best, by_job = None, {}
    for obj in client.list_objects(bucket, prefix="checkpoints/", recursive=True):
        m = CHK.match(obj.object_name)
        if not m:
            continue
        stamp = obj.last_modified.timestamp() if obj.last_modified else 0
        by_job[m.group(1)] = max(by_job.get(m.group(1), 0), stamp)
        if best is None or stamp > best[0]:
            best = (stamp, f"s3://{bucket}/checkpoints/{m.group(1)}/chk-{m.group(2)}")
    jobs = sorted(by_job, key=by_job.get, reverse=True)
    return (best[1] if best else None), jobs


def prune(client, jobs: list[str], keep: int, bucket: str = "flink-checkpoints") -> None:
    for jid in jobs[keep:]:
        for obj in client.list_objects(bucket, prefix=f"checkpoints/{jid}/", recursive=True):
            client.remove_object(bucket, obj.object_name)
        log.info("pruned checkpoints of old job %s", jid)


def client_conf() -> str:
    """A private copy of the Flink conf with rest.address and FLINK_PROPERTIES applied for `flink run`."""
    src = pathlib.Path(os.environ.get("FLINK_HOME", "/opt/flink")) / "conf"
    dst = pathlib.Path("/tmp/sih-flink-conf")
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst)
    extra = os.environ.get("FLINK_PROPERTIES", "")
    with open(dst / "config.yaml", "a", encoding="utf-8") as f:
        f.write("\n" + extra + "\n")
    return str(dst)


def submit(savepoint: str | None, conf_dir: str) -> bool:
    cmd = ["flink", "run", "-d", "-py", env.env_str("SIH_JOB_PY", "/opt/sih/flink/sih_detect/job.py"),
           "-pyfs", env.env_str("SIH_PYFILES", "/opt/sih/lib,/opt/sih/flink")]
    if savepoint:
        cmd[2:2] = ["-s", savepoint, "--allowNonRestoredState"] if env.env_bool("SIH_ALLOW_NON_RESTORED", False) else ["-s", savepoint]
    log.info("submitting detection job: %s", " ".join(cmd))
    try:
        r = subprocess.run(cmd, env={**os.environ, "FLINK_CONF_DIR": conf_dir}, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        FAILED_SUBMITS.inc()
        log.error("flink run timed out")
        return False
    if r.returncode != 0:
        FAILED_SUBMITS.inc()
        out = r.stdout + r.stderr
        # Keep the Python traceback (the useful part), not the Java wrapper stack that follows it.
        start = out.find("Traceback (most recent call last)")
        log.error("flink run failed (%d): %s", r.returncode, (out[start:start + 2500] if start >= 0 else out[-2500:]))
        return False
    SUBMITS.labels("restore" if savepoint else "fresh").inc()
    log.info("job submitted: %s", r.stdout.strip()[-500:])
    return True


def main() -> None:
    jlog.setup("job-supervisor")
    start_http_server(env.env_int("SUPERVISOR_METRICS_PORT", 9106))
    base = env.env_str("FLINK_REST", "http://flink-jobmanager:8081")
    keep = env.env_int("SIH_KEEP_CHECKPOINT_JOBS", 3)
    conf_dir = client_conf()
    client = None
    failures = 0
    while True:
        jobs = rest_jobs(base)
        if jobs is None:
            RUNNING.set(0)
            time.sleep(3)
            continue
        active = [j for j in jobs if j.get("name") == JOB_NAME and j.get("state") in ACTIVE]
        RUNNING.set(1 if any(j.get("state") == "RUNNING" for j in active) else 0)
        if active:
            time.sleep(5)
            continue
        try:
            client = client or s3()
            path, job_dirs = latest_checkpoint(client)
        except Exception as e:  # checkpoint storage unreachable: do not start from scratch silently
            log.error("cannot list checkpoints (%s); retrying before any fresh start", e)
            client = None
            time.sleep(5)
            continue
        if submit(path, conf_dir):
            failures = 0
            try:
                prune(client, job_dirs, keep)
            except Exception as e:
                log.warning("checkpoint pruning failed: %s", e)
            time.sleep(15)  # let the job reach CREATED/RUNNING before re-checking
        else:
            failures += 1
            delay = min(120, 10 * 2 ** min(failures - 1, 4))  # 10, 20, 40, 80, 120 s
            log.info("retrying submission in %ds (consecutive failures: %d)", delay, failures)
            time.sleep(delay)


if __name__ == "__main__":
    main()
