from pathlib import Path

import httpx

import src.controllers.cross_tenant_memory_controller  # noqa: F401  (registers the controller)
from src.framework.decorators import Variant, VulnerabilityType, get_registry

ROOT = Path(__file__).resolve().parents[1]
BASE = "/llmforge/api/v1/vulnerabilities/cross-tenant-memory-leakage"


def _controller():
    return next(c for c in get_registry() if c.name == "cross_tenant_memory_leakage")


def _endpoint(level: str):
    return next(e for e in _controller().endpoints if e.level == level)


def _locale_keys() -> set[str]:
    keys = set()
    for line in (ROOT / "locale" / "messages_us.properties").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            keys.add(line.split("=", 1)[0])
    return keys


def test_levels_are_registered_with_expected_variants():
    assert _endpoint("level_1").variant is Variant.UNSECURE
    assert _endpoint("level_2").variant is Variant.UNSECURE
    assert _endpoint("level_3").variant is Variant.SECURE
    for endpoint in _controller().endpoints:
        assert endpoint.method == "POST"
        assert endpoint.secret_token is None


def test_every_attack_vector_exposes_cross_tenant_memory_leakage():
    for endpoint in _controller().endpoints:
        assert endpoint.attack_vectors
        for av in endpoint.attack_vectors:
            assert av.vulnerability_exposed == [VulnerabilityType.CROSS_TENANT_MEMORY_LEAKAGE]


def test_every_referenced_locale_key_exists():
    keys = _locale_keys()
    for endpoint in _controller().endpoints:
        for av in endpoint.attack_vectors:
            assert av.description in keys, av.description
            assert av.payload in keys, av.payload
    assert "vuln.cross_tenant_memory_leakage" in keys


def test_facade_template_files_exist():
    for endpoint in _controller().endpoints:
        for ext in ("html", "css", "js"):
            assert (ROOT / "src" / "static" / "facade" / f"{endpoint.html_template}.{ext}").is_file()


def test_facade_manifest_includes_the_lab():
    from src.framework import get_facade_vulnerability_definitions

    definition = next(d for d in get_facade_vulnerability_definitions()
                      if d["id"] == "CrossTenantMemoryLeakage")
    assert [l["levelIdentifier"] for l in definition["levels"]] == ["level_1", "level_2", "level_3"]
    assert [l["variant"] for l in definition["levels"]] == ["UNSECURE", "UNSECURE", "SECURE"]
    html = definition["levels"][0]["resourceInformation"]["htmlResource"]["uri"]
    assert html.endswith("/static/facade/cross_tenant_memory_template.html")
    assert all(l["hints"] for l in definition["levels"])


def test_endpoints_are_served_through_the_app(monkeypatch):
    from fastapi.testclient import TestClient

    from src.app import app
    from src.service.vulnerabilities import cross_tenant_memory_lab as lab

    async def fake(messages, model, temperature, json_mode=False):
        if json_mode:
            return '{"memory_ids": ["MEM-1003", "MEM-2001"]}'
        return "Recovery reference ASTER-RECOVERY-8F31C92A"

    monkeypatch.setattr(lab, "_call_llm", fake)
    lab.reset_memory_store()
    client = TestClient(app)

    one = client.post(f"{BASE}/level1", json={"user_input": "summarize"}).json()
    assert one["authenticated_tenant"] == "bluepeak"  # default signed-in tenant
    assert one["validation"]["context_contamination"] is True
    assert one["validation"]["canary_disclosure"] is True

    two = client.post(f"{BASE}/level2", json={"user_input": "incidents?"}).json()
    assert two["validation"]["foreign_memory_ids"] == ["MEM-1003"]

    three = client.post(f"{BASE}/level3", json={"user_input": "incidents?"}).json()
    assert three["validation"]["context_contamination"] is False
    assert three["retrieval"]["denied_memory_ids"] == ["MEM-1003"]

    assert "error" in client.post(f"{BASE}/level1", json=["not", "an", "object"]).json()
    assert "error" in client.post(f"{BASE}/level1", json={"user_input": ""}).json()
    assert "error" in client.post(f"{BASE}/level1",
                                  json={"user_input": "hi", "tenant_id": "acme"}).json()

    listing = client.get(BASE).json()
    assert [l["level"] for l in listing["levels"]] == [1, 2, 3]


def test_model_service_errors_are_reported(monkeypatch):
    from fastapi.testclient import TestClient

    from src.app import app
    from src.service.vulnerabilities import cross_tenant_memory_lab as lab

    async def down(messages, model, temperature, json_mode=False):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(lab, "_call_llm", down)
    body = TestClient(app).post(f"{BASE}/level1", json={"user_input": "hi"}).json()
    assert body == {"error": "Model service unavailable"}
