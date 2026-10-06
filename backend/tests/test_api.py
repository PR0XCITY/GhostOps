import json
import logging
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import cli
from app.api import create_app
from app.certificate import build_certificate, verify
from app.config import ConfigError, SecretRedactingFilter
from app.shadow import ShadowResult
from app.store import Store

FIXTURES = Path(__file__).parent / "fixtures"
BACKEND = Path(__file__).resolve().parents[1]
SECRET = "test-secret-" + "a1b2c3d4" * 6
GROQ_KEY = "gsk_TESTKEYshouldNEVERappearINlogs123456"


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("GHOSTOPS_HMAC_SECRET", SECRET)
    monkeypatch.setenv("GROQ_API_KEY", GROQ_KEY)


class FakeAnalyzer:
    """build_certificate with the slow parts (MiniStack, Infracost, Groq) injected."""

    def __init__(self):
        self.calls = []

    def __call__(self, plan, tf_dir=None, *, use_groq=True):
        self.calls.append({"tf_dir": tf_dir, "use_groq": use_groq})
        shadow = ShadowResult(True, "complete", resources=[{"address": "x.y", "type": "x", "id": "1"}]) if tf_dir else None
        cost = {"monthly_delta_usd": 1.5, "complete": True, "unpriced": [], "resources": []}
        return build_certificate(plan, tf_dir, shadow_result=shadow, cost_result=cost, use_groq=False)


@pytest.fixture
def analyzer():
    return FakeAnalyzer()


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "ghostops.db")


@pytest.fixture
def client(store, analyzer):
    with TestClient(create_app(store=store, analyzer=analyzer)) as c:
        yield c


def analyze(client, fixture, tf_dir="demo/good"):
    body = {"plan_path": str(FIXTURES / fixture), "tf_dir": str(BACKEND.parent / tf_dir) if tf_dir else None}
    return client.post("/analyze", json=body)


# --- /analyze ------------------------------------------------------------------------------


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_analyze_by_path(client, store):
    bad = analyze(client, "bad_plan.json", "demo/bad")
    assert bad.status_code == 200
    cert = bad.json()
    assert cert["verdict"] == "BLOCKED_PENDING_REVIEW"
    assert list(cert)[-1] == "signature" and verify(cert)
    assert store.get_certificate(cert["plan_id"]) == cert
    good = analyze(client, "good_plan.json").json()
    assert good["verdict"] == "AUTO_APPROVED"


def test_analyze_inline_plan(client):
    plan = json.loads((FIXTURES / "good_plan.json").read_text(encoding="utf-8"))
    r = client.post("/analyze", json={"plan": plan, "tf_dir": str(BACKEND.parent / "demo" / "good"), "use_groq": False})
    assert r.status_code == 200 and r.json()["verdict"] == "AUTO_APPROVED"


def test_analyze_upload(client, analyzer):
    with open(FIXTURES / "good_plan.json", "rb") as fh:
        r = client.post("/analyze", files={"plan": ("plan.json", fh, "application/json")},
                        data={"tf_dir": str(BACKEND.parent / "demo" / "good"), "use_groq": "false"})
    assert r.status_code == 200, r.text
    assert r.json()["verdict"] == "AUTO_APPROVED"
    assert analyzer.calls[-1] == {"tf_dir": str(BACKEND.parent / "demo" / "good"), "use_groq": False}


def test_upload_without_tf_dir_is_blocked_unverified(client):
    with open(FIXTURES / "good_plan.json", "rb") as fh:
        cert = client.post("/analyze", files={"plan": ("plan.json", fh, "application/json")}).json()
    assert cert["verdict"] == "BLOCKED_PENDING_REVIEW"
    assert cert["shadow_run"]["applied"] is False


@pytest.mark.parametrize(("kwargs", "status", "detail"), [
    ({"json": {}}, 422, "exactly one of plan_path or plan"),
    ({"json": {"plan_path": "x.json", "plan": {}}}, 422, "exactly one of plan_path or plan"),
    ({"json": {"plan_path": "C:/nope/missing.json"}}, 400, "existing .json file"),
    ({"json": {"plan_path": __file__}}, 400, "existing .json file"),
    ({"json": {"plan": {"no": "format_version"}}}, 422, "not a usable Terraform plan"),
    ({"json": {"plan": {"format_version": "1.2"}, "tf_dir": "C:/nope"}}, 400, "tf_dir must be an existing directory"),
    ({"content": b"not json", "headers": {"content-type": "application/json"}}, 422, "invalid request body"),
    ({"files": {"other": ("p.json", b"{}", "application/json")}}, 400, 'file field named "plan"'),
    ({"files": {"plan": ("p.json", b"{oops", "application/json")}}, 422, "not valid JSON"),
    ({"files": {"plan": ("p.json", b"[1, 2]", "application/json")}}, 422, "must be a JSON object"),
])
def test_analyze_rejects_bad_input(client, kwargs, status, detail):
    r = client.post("/analyze", **kwargs)
    assert r.status_code == status, r.text
    assert detail in r.json()["detail"]


# --- /certificates ----------------------------------------------------------------------------


def test_list_and_get_certificates(client):
    bad = analyze(client, "bad_plan.json", "demo/bad").json()
    good = analyze(client, "good_plan.json").json()
    listing = client.get("/certificates").json()
    assert {c["plan_id"] for c in listing} == {bad["plan_id"], good["plan_id"]}
    summary = next(c for c in listing if c["plan_id"] == bad["plan_id"])
    assert summary["verdict"] == "BLOCKED_PENDING_REVIEW"
    assert summary["risk_flag_counts"] == {"CRITICAL": 3, "HIGH": 5, "MEDIUM": 0, "LOW": 0}
    assert summary["resource_change_count"] == 8 and summary["latest_decision"] is None
    assert client.get(f"/certificates/{bad['plan_id']}").json() == bad


def test_unknown_and_malformed_plan_ids(client):
    assert client.get("/certificates/" + "0" * 64).status_code == 404
    assert client.get("/certificates/not-a-hash").status_code == 422
    assert client.get("/verify/" + "f" * 64).status_code == 404
    assert client.post("/certificates/" + "0" * 64 + "/decision",
                       json={"decision": "approve", "reviewer": "ana"}).status_code == 404


# --- decisions & audit log -------------------------------------------------------------------


def test_decision_is_recorded_and_never_applied(client, analyzer, store):
    cert = analyze(client, "bad_plan.json", "demo/bad").json()
    calls_before = len(analyzer.calls)
    r = client.post(f"/certificates/{cert['plan_id']}/decision",
                    json={"decision": "deny", "reviewer": "ana.lee@example.com", "comment": "SSH must not be public"})
    assert r.status_code == 200
    entry = r.json()
    assert entry["decision"] == "deny" and entry["reviewer"] == "ana.lee@example.com"
    assert entry["applied"] is False and "never applies changes" in entry["note"]
    assert entry["certificate_signature"] == cert["signature"]
    assert entry["verdict_at_decision"] == "BLOCKED_PENDING_REVIEW"
    assert len(analyzer.calls) == calls_before  # nothing re-run, nothing applied

    client.post(f"/certificates/{cert['plan_id']}/decision", json={"decision": "approve", "reviewer": "lead"})
    log = client.get(f"/certificates/{cert['plan_id']}/decisions").json()
    assert [(d["decision"], d["reviewer"]) for d in log] == [("deny", "ana.lee@example.com"), ("approve", "lead")]
    latest = next(c for c in client.get("/certificates").json() if c["plan_id"] == cert["plan_id"])["latest_decision"]
    assert latest["decision"] == "approve" and latest["reviewer"] == "lead"


@pytest.mark.parametrize("body", [
    {"decision": "maybe", "reviewer": "ana"}, {"decision": "approve", "reviewer": ""},
    {"decision": "approve"}, {"decision": "approve", "reviewer": "<script>"},
    {"decision": "approve", "reviewer": "ana", "comment": "x" * 1001},
])
def test_decision_validation(client, body):
    cert = analyze(client, "good_plan.json").json()
    assert client.post(f"/certificates/{cert['plan_id']}/decision", json=body).status_code == 422


def test_audit_log_is_append_only(client, store):
    cert = analyze(client, "good_plan.json").json()
    client.post(f"/certificates/{cert['plan_id']}/decision", json={"decision": "approve", "reviewer": "ana"})
    db = sqlite3.connect(store.path)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        db.execute("UPDATE audit_log SET decision = 'deny'")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        db.execute("DELETE FROM audit_log")
    db.close()


# --- /verify ----------------------------------------------------------------------------------


def tamper(store, plan_id):
    db = sqlite3.connect(store.path)
    body = json.loads(db.execute("SELECT body FROM certificates WHERE plan_id = ?", (plan_id,)).fetchone()[0])
    body["verdict"] = "AUTO_APPROVED"
    db.execute("UPDATE certificates SET body = ? WHERE plan_id = ?", (json.dumps(body), plan_id))
    db.commit()
    db.close()


def test_verify_detects_tampering_in_the_database(client, store):
    cert = analyze(client, "bad_plan.json", "demo/bad").json()
    ok = client.get(f"/verify/{cert['plan_id']}").json()
    assert ok == {"plan_id": cert["plan_id"], "valid": True, "verdict": "BLOCKED_PENDING_REVIEW",
                  "timestamp": cert["timestamp"], "signature": cert["signature"]}
    tamper(store, cert["plan_id"])
    assert client.get(f"/verify/{cert['plan_id']}").json()["valid"] is False
    r = client.post(f"/certificates/{cert['plan_id']}/decision", json={"decision": "approve", "reviewer": "ana"})
    assert r.status_code == 409


# --- CORS -------------------------------------------------------------------------------------


def test_cors_allows_only_the_dashboard(client):
    preflight = {"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"}
    ok = client.options("/analyze", headers={"Origin": "http://localhost:3000", **preflight})
    assert ok.headers["access-control-allow-origin"] == "http://localhost:3000"
    evil = client.options("/analyze", headers={"Origin": "http://evil.example", **preflight})
    assert "access-control-allow-origin" not in evil.headers
    get = client.get("/certificates", headers={"Origin": "http://localhost:3000"})
    assert get.headers["access-control-allow-origin"] == "http://localhost:3000"


# --- startup & secrets -------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["", "too-short"])
def test_refuses_to_start_without_a_valid_secret(monkeypatch, tmp_path, value):
    monkeypatch.setenv("GHOSTOPS_HMAC_SECRET", value)
    with pytest.raises(ConfigError, match="GHOSTOPS_HMAC_SECRET"):
        create_app(store=Store(tmp_path / "db"))


def test_server_exits_with_clear_message_when_secret_missing():
    env = {**__import__("os").environ, "GHOSTOPS_HMAC_SECRET": ""}
    proc = subprocess.run([sys.executable, "-m", "app.server", "--port", "8999"], cwd=BACKEND, env=env,
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 2
    assert "GhostOps cannot start" in proc.stderr and "GHOSTOPS_HMAC_SECRET is not set" in proc.stderr
    assert "Traceback" not in proc.stderr and proc.stdout == ""


def test_secrets_never_reach_the_logs(client, caplog):
    caplog.set_level(logging.DEBUG)
    cert = analyze(client, "bad_plan.json", "demo/bad").json()
    client.post(f"/certificates/{cert['plan_id']}/decision", json={"decision": "deny", "reviewer": "ana"})
    client.get(f"/verify/{cert['plan_id']}")
    client.get("/certificates")
    assert caplog.records, "expected some log output"
    assert SECRET not in caplog.text and GROQ_KEY not in caplog.text


def test_log_filter_redacts_a_leaked_secret():
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "boom %s and %s", (SECRET, GROQ_KEY), None)
    SecretRedactingFilter().filter(record)
    assert record.getMessage() == "boom [redacted] and [redacted]"


# --- CLI ----------------------------------------------------------------------------------------


@pytest.fixture
def fast_cli(monkeypatch, analyzer):
    import app.certificate
    monkeypatch.setattr(app.certificate, "build_certificate", lambda plan, tf, use_groq=True: analyzer(plan, tf))


def test_cli_exit_codes_and_output(fast_cli, capsys):
    good = str(FIXTURES / "good_plan.json")
    assert cli.main(["analyze", str(FIXTURES / "bad_plan.json"), "--tf", str(BACKEND.parent / "demo" / "bad"),
                     "--no-store"]) == 1
    out = capsys.readouterr().out
    assert "VERDICT: BLOCKED_PENDING_REVIEW" in out and "CRITICAL GO-SG-001" in out and "(verified)" in out
    assert cli.main(["analyze", good, "--tf", str(BACKEND.parent / "demo" / "good"), "--no-store"]) == 0
    assert "VERDICT: AUTO_APPROVED" in capsys.readouterr().out
    assert cli.main(["analyze", good, "--no-store"]) == 1  # no shadow run: unverified
    assert "Shadow run: NOT applied" in capsys.readouterr().out
    assert cli.main(["analyze", good, "--tf", str(BACKEND.parent / "demo" / "good"), "--no-store", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "AUTO_APPROVED"


def test_cli_errors_exit_2(fast_cli, monkeypatch, tmp_path, capsys):
    assert cli.main(["analyze", str(tmp_path / "missing.json")]) == 2
    (tmp_path / "bad.json").write_text("{nope", encoding="utf-8")
    assert cli.main(["analyze", str(tmp_path / "bad.json")]) == 2
    assert cli.main(["analyze", str(FIXTURES / "good_plan.json"), "--tf", str(tmp_path / "nodir")]) == 2
    monkeypatch.setenv("GHOSTOPS_HMAC_SECRET", "")
    assert cli.main(["analyze", str(FIXTURES / "good_plan.json")]) == 2
    assert "GhostOps cannot start" in capsys.readouterr().err


def test_ghostops_command_is_installed():
    exe = Path(sys.executable).parent / ("ghostops.exe" if sys.platform == "win32" else "ghostops")
    proc = subprocess.run([str(exe), "analyze", "--help"], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0 and "plan JSON file" in proc.stdout
