"""GhostOps end-to-end demo: start everything, run both demos, report verdicts.

    python scripts\\demo.py            start MiniStack + API + dashboard, run demos, keep serving (Ctrl+C stops)
    python scripts\\demo.py --exit     same, but stop what it started once the demos finish
    python scripts\\demo.py --no-groq  template explanations instead of Groq

Standard library only (run it with any Python 3.11+). It uses the repo's .venv for
the backend and npm for the dashboard, reuses anything already running on its
port, and only stops processes it started itself. Logs go to logs/.
Exit code 0 when demo/bad is BLOCKED and demo/good is AUTO_APPROVED, else 1.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENV_PY = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
LOGS = ROOT / "logs"
MINISTACK = "http://localhost:4566/_ministack/health"
API = "http://127.0.0.1:8000"
DASHBOARD = "http://localhost:3000"
EXPECTED = {"bad": "BLOCKED_PENDING_REVIEW", "good": "AUTO_APPROVED"}

started: list[subprocess.Popen] = []


def say(msg: str) -> None:
    print(f"[ghostops] {msg}", flush=True)


def http_ok(url: str, timeout: float = 3) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status < 500
    except (urllib.error.URLError, OSError):
        return False


def wait_for(url: str, what: str, seconds: int) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if http_ok(url):
            say(f"{what} is up ({url})")
            return
        time.sleep(1)
    raise SystemExit(f"[ghostops] {what} did not come up within {seconds}s; see {LOGS}")


def on_path(tool: str) -> bool:
    if shutil.which(tool):
        return True
    # a shell opened before the tool was installed has a stale PATH (stdlib-only helper)
    sys.path.insert(0, str(ROOT / "backend"))
    from app.tools import registry_path

    fresh = registry_path()
    return bool(fresh and shutil.which(tool, path=fresh))


def preflight() -> None:
    problems = []
    for tool in ("docker", "terraform", "opa", "npm"):
        if not on_path(tool):
            problems.append(f"'{tool}' is not installed or not on PATH (see README: Prerequisites)")
    if not VENV_PY.is_file():
        problems.append(f"backend venv missing: {VENV_PY} (see README: Setup)")
    if not (ROOT / "dashboard" / "node_modules").is_dir():
        problems.append("dashboard dependencies missing: run  npm --prefix dashboard install")
    if not (ROOT / ".env").is_file():
        problems.append(".env missing: copy .env.example to .env and fill it in")
    if problems:
        raise SystemExit("[ghostops] cannot start:\n  - " + "\n  - ".join(problems))
    infracost_token = Path(os.environ.get("APPDATA", Path.home())) / "infracost" / "token.json"
    if os.name == "nt" and not infracost_token.is_file():
        say("note: Infracost is not logged in, so cost_delta will be null (run: infracost auth login)")


def start(name: str, cmd: list[str], cwd: Path) -> None:
    LOGS.mkdir(exist_ok=True)
    log = open(LOGS / f"{name}.log", "w", encoding="utf-8")
    env = dict(os.environ, NEXT_TELEMETRY_DISABLED="1")
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    proc = subprocess.Popen(cmd, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, env=env, creationflags=flags)
    started.append(proc)
    say(f"started {name} (pid {proc.pid}), log: logs/{name}.log")


def stop_started() -> None:
    for proc in reversed(started):
        if proc.poll() is not None:
            continue
        if os.name == "nt":  # npm/next spawn children; kill the whole tree
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
        else:
            proc.terminate()
        say(f"stopped pid {proc.pid}")


def run_demo(name: str, use_groq: bool) -> dict:
    url = f"{API}/analyze/demo/{name}?use_groq={'true' if use_groq else 'false'}"
    req = urllib.request.Request(url, data=b"", method="POST")
    t0 = time.monotonic()
    with urllib.request.urlopen(req, timeout=600) as resp:
        cert = json.load(resp)
    cert["_seconds"] = round(time.monotonic() - t0)
    return cert


def main() -> int:
    parser = argparse.ArgumentParser(description="Start GhostOps and run both demos.")
    parser.add_argument("--exit", action="store_true", help="stop started services after the demos")
    parser.add_argument("--no-groq", action="store_true", help="use template explanations")
    args = parser.parse_args()

    preflight()
    say("starting MiniStack (docker compose up -d)")
    compose = subprocess.run(["docker", "compose", "up", "-d"], cwd=ROOT, capture_output=True, text=True)
    if compose.returncode != 0:
        raise SystemExit(f"[ghostops] docker compose failed (is Docker Desktop running?):\n{compose.stderr.strip()}")
    wait_for(MINISTACK, "MiniStack", 120)

    if http_ok(f"{API}/health"):
        say(f"API already running at {API}, reusing it")
    else:
        start("api", [str(VENV_PY), "-m", "app.server", "--port", "8000"], ROOT / "backend")
        wait_for(f"{API}/health", "API", 60)

    if http_ok(DASHBOARD):
        say(f"dashboard already running at {DASHBOARD}, reusing it")
    else:
        start("dashboard", [shutil.which("npm") or "npm", "run", "dev"], ROOT / "dashboard")
        wait_for(DASHBOARD, "dashboard", 120)

    ok = True
    for name in ("bad", "good"):
        say(f"running demo/{name} (shadow apply on MiniStack takes 30-120 s)...")
        try:
            cert = run_demo(name, use_groq=not args.no_groq)
        except (urllib.error.URLError, OSError) as exc:
            say(f"demo/{name} FAILED: {exc}")
            ok = False
            continue
        flags = cert["blast_radius"]["risk_flags"]
        severities = {s: sum(f["severity"] == s for f in flags) for s in ("CRITICAL", "HIGH", "MEDIUM")}
        cost = cert["cost_delta"]["monthly_usd"]
        match = cert["verdict"] == EXPECTED[name]
        ok &= match
        say(f"demo/{name}: {cert['verdict']} ({'as expected' if match else 'UNEXPECTED, wanted ' + EXPECTED[name]}) "
            f"in {cert['_seconds']}s | flags {severities} | shadow applied={cert['shadow_run']['applied']} | "
            f"cost {'n/a' if cost is None else f'{cost:+.2f} USD/month'} | explanation by {cert['generated_by']}")
        say(f"  {DASHBOARD}/certificates/{cert['plan_id']}")

    say("all demos behaved as expected" if ok else "a demo did NOT behave as expected")
    if args.exit:
        stop_started()
        return 0 if ok else 1
    say(f"dashboard: {DASHBOARD}   API: {API}   (Ctrl+C to stop what this script started)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        say("stopping")
    finally:
        stop_started()
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        stop_started()
        raise
