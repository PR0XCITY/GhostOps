"""Run every GhostOps check with one command.

    .venv\\Scripts\\python.exe scripts\\test_all.py          everything (needs MiniStack + Infracost login)
    .venv\\Scripts\\python.exe scripts\\test_all.py --fast   skip the slow integration tests (under a minute)
    .venv\\Scripts\\python.exe scripts\\test_all.py --build  also run the dashboard production build

Steps: backend pytest (unit + API + Rego + integration), OPA policy unit tests,
dashboard TypeScript check, dashboard ESLint. Exit code 0 only if all pass.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
DASHBOARD = ROOT / "dashboard"
VENV_PY = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def tool(name: str) -> str:
    found = shutil.which(name)
    if not found and os.name == "nt":  # tools installed after this shell started (e.g. winget opa)
        sys.path.insert(0, str(BACKEND))
        from app.tools import registry_path  # noqa: E402

        found = shutil.which(name, path=registry_path())
    if not found:
        raise SystemExit(f"'{name}' not found on PATH")
    return found


def step(title: str, cmd: list[str], cwd: Path, tail: int) -> tuple[str, bool, float, str]:
    print(f"\n=== {title}\n$ {' '.join(Path(c).name if i == 0 else c for i, c in enumerate(cmd))}", flush=True)
    t0 = time.monotonic()
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          env=dict(os.environ, NEXT_TELEMETRY_DISABLED="1"))
    seconds = time.monotonic() - t0
    lines = (proc.stdout + proc.stderr).strip().splitlines()
    print("\n".join(lines[-tail:]) if lines else "(no output)", flush=True)
    summary = next((l.strip() for l in reversed(lines) if l.strip()), "")
    return title, proc.returncode == 0, seconds, summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Run every GhostOps check.")
    parser.add_argument("--fast", action="store_true", help="skip integration tests (MiniStack, Infracost, Groq)")
    parser.add_argument("--build", action="store_true", help="also run next build (stop the dev server first)")
    args = parser.parse_args()

    pytest_cmd = [str(VENV_PY), "-m", "pytest", "-q", "-p", "no:warnings"] + (["-m", "not integration"] if args.fast else [])
    npx = tool("npx")
    steps = [
        ("Backend tests (pytest)", pytest_cmd, BACKEND, 6),
        ("OPA policy unit tests", [tool("opa"), "test", "rules", "tests/rego"], BACKEND, 3),
        ("Dashboard TypeScript", [npx, "tsc", "--noEmit"], DASHBOARD, 5),
        ("Dashboard ESLint", [npx, "eslint", "."], DASHBOARD, 10),
    ]
    if args.build:
        steps.append(("Dashboard production build", [tool("npm"), "run", "build"], DASHBOARD, 12))

    results = [step(title, cmd, cwd, tail) for title, cmd, cwd, tail in steps]

    print("\n=== Summary")
    width = max(len(r[0]) for r in results)
    for title, ok, seconds, summary in results:
        detail = summary if title.startswith(("Backend", "OPA")) else ("clean" if ok else summary)
        print(f"{'PASS' if ok else 'FAIL'}  {title:<{width}}  {seconds:6.1f}s  {detail}")
    failed = [r[0] for r in results if not r[1]]
    print(f"\n{'ALL CHECKS PASSED' if not failed else 'FAILED: ' + ', '.join(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
