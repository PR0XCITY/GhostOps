"""Settings from the environment, with the repo's .env as a fallback.

Values already in the environment win. Nothing here is ever printed.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


def load_env(path: Path = ENV_FILE) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def setting(name: str, default: str | None = None) -> str | None:
    load_env()
    value = os.environ.get(name)
    return value if value else default


REPO_ROOT = ENV_FILE.parent
SECRET_SETTINGS = ("GHOSTOPS_HMAC_SECRET", "GROQ_API_KEY", "GHOSTOPS_API_KEY")
LOCAL_ORIGINS = ("http://localhost:3000", "http://127.0.0.1:3000")


class ConfigError(RuntimeError):
    """A required setting is missing or invalid. The message never contains values."""


def check_required() -> None:
    """Refuse to start without what the backend cannot work without."""
    problems = []
    secret = setting("GHOSTOPS_HMAC_SECRET")
    if not secret:
        problems.append("GHOSTOPS_HMAC_SECRET is not set (it signs every Risk Certificate).")
    elif len(secret) < 32:
        problems.append("GHOSTOPS_HMAC_SECRET is shorter than 32 characters.")
    if hosted():
        key = setting("GHOSTOPS_API_KEY")
        if not key:
            problems.append("GHOSTOPS_API_KEY is not set (GHOSTOPS_HOSTED=1 requires it for every POST/PUT/DELETE).")
        elif len(key) < 24:
            problems.append("GHOSTOPS_API_KEY is shorter than 24 characters.")
    if problems:
        raise ConfigError(
            "GhostOps cannot start:\n  - " + "\n  - ".join(problems) + "\n"
            f"Add it to {ENV_FILE} (template: .env.example). Generate one with:\n"
            '  python -c "import secrets; print(secrets.token_hex(32))"'
        )


def hosted() -> bool:
    """GHOSTOPS_HOSTED=1: running on a public host (Render). Turns on the API key
    check and turns off everything that reads server paths named by the caller."""
    return (setting("GHOSTOPS_HOSTED") or "").strip().lower() in ("1", "true", "yes")


def cors_origins() -> list[str]:
    """The local dashboard plus GHOSTOPS_CORS_ORIGINS (comma-separated, e.g. a Vercel URL).

    Only explicit http(s) origins are accepted; "*" and anything else is ignored.
    """
    extra = [o.strip().rstrip("/") for o in (setting("GHOSTOPS_CORS_ORIGINS") or "").split(",")]
    origins = list(LOCAL_ORIGINS)
    for origin in extra:
        if origin.startswith(("https://", "http://")) and "*" not in origin and origin not in origins:
            origins.append(origin)
    return origins


def db_path() -> Path:
    return Path(setting("GHOSTOPS_DB_PATH") or REPO_ROOT / "data" / "ghostops.db")


class SecretRedactingFilter(logging.Filter):
    """Replace the values of secret settings in any log record (defence in depth)."""

    def filter(self, record: logging.LogRecord) -> bool:
        secrets = [v for v in (setting(n) for n in SECRET_SETTINGS) if v and len(v) >= 8]
        if secrets:
            message = record.getMessage()
            redacted = message
            for value in secrets:
                redacted = redacted.replace(value, "[redacted]")
            if redacted != message:
                record.msg, record.args = redacted, None
        return True


def install_secret_filter(logger_names: tuple[str, ...] = ("", "uvicorn", "uvicorn.error", "uvicorn.access")) -> None:
    flt = SecretRedactingFilter()
    for name in logger_names:
        logger = logging.getLogger(name)
        for handler in logger.handlers:
            if not any(isinstance(f, SecretRedactingFilter) for f in handler.filters):
                handler.addFilter(flt)
        if not any(isinstance(f, SecretRedactingFilter) for f in logger.filters):
            logger.addFilter(flt)
