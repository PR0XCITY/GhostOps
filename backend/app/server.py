"""Start the GhostOps API:  python -m app.server [--port 8000]

Checks required settings first and exits with a clear message (no traceback)
if one is missing. Binds to 127.0.0.1 only: this is a local tool.
"""

from __future__ import annotations

import argparse
import sys

import uvicorn

from app.config import ConfigError, check_required, install_secret_filter


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.server")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    try:
        check_required()
    except ConfigError as exc:
        print(exc, file=sys.stderr)
        return 2

    from app.api import create_app

    config = uvicorn.Config(create_app(), host="127.0.0.1", port=args.port, log_level="info")
    install_secret_filter()  # after uvicorn has configured its log handlers
    uvicorn.Server(config).run()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
