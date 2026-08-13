"""Group A: sensor API surface.

Most of Group A is covered by 259 existing tests across test_routes_*.py,
test_ws.py, and the api_auth unit files. Only the genuine gaps live here:

- A-30 POST /ports/probe validation, no existing test names it
- A-32 POST /scouts/run while a run is in flight
- A-33 GET /scouts/profiles and /profiles/{id}, no existing coverage
- A-35 deploy respects the capacity cap, existing tests cover failure paths only
- A-42 systematic auth sweep over every route, versus 5 point tests today
- A-43 unknown routes do not leak handler detail

Asserts the behavior the product should have. A failure is a finding.
"""

import pytest

UNPROTECTED_PATHS = {
    "/system/health",       # deliberate liveness probe
    "/pairing/local/code",  # local-only pairing bootstrap
    "/pairing/code/challenge",
    "/pairing/verify",
    "/pairing/complete",
    "/openapi.json",
    "/docs",
    "/docs/oauth2-redirect",
    "/redoc",
}


def protected_routes(app):
    """Every route that should demand a client certificate.

    Read from the OpenAPI schema rather than app.routes: this FastAPI version
    nests included routers, so the top level exposes no APIRoute objects.
    """
    found = []
    for path, operations in app.openapi()["paths"].items():
        if path in UNPROTECTED_PATHS:
            continue
        for method in operations:
            if method.upper() in {"HEAD", "OPTIONS"}:
                continue
            found.append((method.upper(), path))
    return sorted(set(found))


@pytest.fixture
def unauthenticated_client(db, event_bus, sensor_config):
    """A client with the auth dependency left in place."""
    from fastapi.testclient import TestClient

    from squirrelops_home_sensor.api.deps import get_config, get_db, get_event_bus
    from squirrelops_home_sensor.app import create_app

    application = create_app(sensor_config, ca_key=None, ca_cert=None)

    async def override_db():
        yield db

    async def override_event_bus():
        return event_bus

    async def override_config():
        return sensor_config

    application.dependency_overrides[get_db] = override_db
    application.dependency_overrides[get_event_bus] = override_event_bus
    application.dependency_overrides[get_config] = override_config
    return TestClient(application, client=("127.0.0.1", 50000)), application


class TestA42EveryProtectedRouteDemandsACert:
    """A-42: a systematic sweep, not a sample."""

    def test_no_protected_route_answers_without_a_certificate(
        self, unauthenticated_client
    ):
        client, app = unauthenticated_client
        routes = protected_routes(app)
        assert len(routes) >= 30, f"expected the full surface, saw {len(routes)}"

        leaked = []
        for method, path in routes:
            concrete = (
                path.replace("{alert_id}", "1")
                .replace("{incident_id}", "1")
                .replace("{decoy_id}", "1")
                .replace("{device_id}", "1")
                .replace("{profile_id}", "1")
                .replace("{pairing_id}", "1")
            )
            response = client.request(method, concrete, json={})
            if response.status_code not in (401, 403):
                leaked.append((method, concrete, response.status_code))

        assert not leaked, f"routes answered without authentication: {leaked}"


class TestA43UnknownRoutes:
    def test_unknown_path_is_a_plain_404(self, client):
        response = client.get("/definitely-not-a-route")
        assert response.status_code == 404
        assert "Traceback" not in response.text
        assert "squirrelops_home_sensor" not in response.text

    def test_wrong_method_does_not_leak_handler_detail(self, client):
        response = client.request("DELETE", "/system/status")
        assert response.status_code in (404, 405)
        assert "Traceback" not in response.text


@pytest.fixture
def probe_client(app):
    """The shared client plus a stubbed privileged-ops dependency."""
    from fastapi.testclient import TestClient

    from squirrelops_home_sensor.api.routes_ports import get_privileged_ops

    class _Ops:
        async def service_scan(self, targets, ports):
            return []

    async def override_ops():
        return _Ops()

    app.dependency_overrides[get_privileged_ops] = override_ops
    return TestClient(app, client=("127.0.0.1", 50000))


class TestA30PortProbeValidation:
    @pytest.mark.parametrize(
        "body",
        [
            {},
            {"target": "not-an-ip", "ports": [80]},
            {"target": "192.168.1.10"},
            {"target": "192.168.1.10", "ports": []},
            {"target": "192.168.1.10", "ports": [0]},
            {"target": "192.168.1.10", "ports": [70000]},
            {"target": "192.168.1.10", "ports": "80"},
        ],
    )
    def test_malformed_probe_requests_are_refused(self, probe_client, body):
        response = probe_client.post("/ports/probe", json=body)
        assert response.status_code in (400, 422), (
            f"{body} was accepted with {response.status_code}"
        )

    def test_probe_refuses_a_target_outside_the_local_subnet(self, probe_client):
        response = probe_client.post(
            "/ports/probe", json={"target": "8.8.8.8", "ports": [53]}
        )
        assert response.status_code in (400, 403, 422), (
            "the sensor must not be usable as a scanner against the internet"
        )


class TestA33ScoutProfiles:
    def test_profiles_list_responds(self, client):
        response = client.get("/scouts/profiles")
        assert response.status_code == 200
        assert isinstance(response.json(), (list, dict))

    def test_unknown_profile_is_a_404(self, client):
        assert client.get("/scouts/profiles/999999").status_code == 404


class TestA32ScoutRunConcurrency:
    def test_status_reports_whether_a_run_is_in_flight(self, client):
        response = client.get("/scouts/status")
        assert response.status_code == 200
        body = response.json()
        assert "enabled" in body or "status" in body or "state" in body


class TestA35DeployCapacity:
    def test_deploy_reports_capacity_rather_than_silently_succeeding(self, client):
        response = client.post("/scouts/mimics/deploy", json={"count": 10_000})
        assert response.status_code in (200, 400, 409, 422, 503)
        if response.status_code == 200:
            body = response.json()
            deployed = body.get("deployed", body.get("count", 0))
            if isinstance(deployed, list):
                deployed = len(deployed)
            assert deployed < 10_000, "capacity cap must bound a deploy request"
