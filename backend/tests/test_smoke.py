"""
ORCA Smoke Test Suite
Runs inside the orca-backend container against https://localhost:8000.
Mints a JWT directly from JWT_SECRET so no plaintext admin password is needed.
"""

import os
import time
import uuid
from datetime import datetime, timedelta

import httpx
import jwt
import pytest
from passlib.context import CryptContext
from sqlalchemy import create_engine, text

# ── Config ────────────────────────────────────────────────────────────────────

BASE = "https://localhost:8000"
JWT_SECRET = os.environ["JWT_SECRET"]
DATABASE_URL = os.environ["DATABASE_URL"]

_engine = create_engine(DATABASE_URL)
_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

TEST_USER = f"_orca_test_{uuid.uuid4().hex[:8]}"
TEST_PASS = "OrcaTest!99"
TEST_CASE = f"_smoke_case_{uuid.uuid4().hex[:6]}"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _mint_token(username: str, role: str, initials: str, user_id: int) -> str:
    payload = {
        "sub": username,
        "role": role,
        "initials": initials,
        "id": user_id,
        "exp": datetime.utcnow() + timedelta(minutes=30),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def _admin_headers() -> dict:
    return {"Authorization": f"Bearer {_mint_token('admin', 'admin', 'ADM', 1)}"}


def _fresh_client() -> httpx.Client:
    """Return a new client with no cookies (use for unauthenticated tests)."""
    return httpx.Client(base_url=BASE, verify=False, timeout=60.0)


# ── Session-scoped fixtures ───────────────────────────────────────────────────

@pytest.fixture(scope="session")
def client():
    """Shared client — no persistent cookies, all auth via Bearer header."""
    with httpx.Client(base_url=BASE, verify=False, timeout=60.0,
                      cookies=httpx.Cookies()) as c:
        yield c


@pytest.fixture(scope="session")
def auth():
    return _admin_headers()


@pytest.fixture(scope="session", autouse=True)
def test_user():
    """Create a throwaway user for login tests; delete on teardown."""
    phash = _pwd_ctx.hash(TEST_PASS)
    uid = None
    with _engine.begin() as conn:
        result = conn.execute(text(
            "INSERT INTO users (username, password_hash, initials, role) "
            "VALUES (:u, :h, :i, :r) ON CONFLICT (username) DO UPDATE SET password_hash=:h "
            "RETURNING id"
        ), {"u": TEST_USER, "h": phash, "i": "TST", "r": "analyst"})
        row = result.fetchone()
        if row:
            uid = row[0]
    yield uid
    with _engine.begin() as conn:
        if uid:
            conn.execute(text("DELETE FROM agent_registrations WHERE analyst_id = :uid"), {"uid": uid})
        conn.execute(text("DELETE FROM users WHERE username = :u"), {"u": TEST_USER})


@pytest.fixture(scope="session")
def case_asset(client, auth):
    """Create a test case + asset; yield (case_name, asset_id); delete on teardown."""
    r = client.post("/api/mitre/cases", json={"name": TEST_CASE, "lead": "TST"}, headers=auth)
    assert r.status_code == 200, f"Case create failed: {r.status_code} {r.text}"

    r2 = client.post(f"/api/mitre/cases/{TEST_CASE}/assets",
                     json={"hostname": "_smoke_asset", "ip_address": "127.0.0.1"},
                     headers=auth)
    assert r2.status_code == 200, f"Asset create failed: {r2.status_code} {r2.text}"

    # Asset create returns {"status":"SUCCESS"} without id — query DB
    with _engine.connect() as conn:
        row = conn.execute(text(
            "SELECT id FROM assets WHERE case_name = :cn AND hostname = '_smoke_asset' ORDER BY id DESC LIMIT 1"
        ), {"cn": TEST_CASE}).fetchone()
    asset_id = row[0] if row else None

    yield TEST_CASE, asset_id

    if asset_id:
        client.delete(f"/api/mitre/assets/{asset_id}", headers=auth)
    client.delete(f"/api/mitre/cases/{TEST_CASE}", headers=auth)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. AUTH
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuth:
    def test_login_valid(self):
        with _fresh_client() as c:
            r = c.post("/api/auth/login",
                       json={"username": TEST_USER, "password": TEST_PASS})
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert "token" in body or "orca_token" in r.cookies, "No token in login response"

    def test_login_bad_credentials_returns_401_not_500(self):
        with _fresh_client() as c:
            r = c.post("/api/auth/login",
                       json={"username": TEST_USER, "password": "WRONG_PASSWORD"})
        assert r.status_code == 401, (
            f"Bad credentials should return 401, got {r.status_code}. "
            "Known regression: bad creds were returning 500 before the fix."
        )

    def test_me_with_token(self, client, auth):
        r = client.get("/api/auth/me", headers=auth)
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
        data = r.json()
        # /me returns {"user": {...}, "expires_at": ...}
        user = data.get("user") or data
        assert user.get("username") == "admin"
        assert user.get("role") == "admin"

    def test_me_unauthenticated(self):
        with _fresh_client() as c:
            r = c.get("/api/auth/me")
        assert r.status_code == 401


# ═══════════════════════════════════════════════════════════════════════════════
# 2. CASES + ASSETS
# ═══════════════════════════════════════════════════════════════════════════════

class TestCasesAssets:
    def test_list_cases(self, client, auth):
        r = client.get("/api/mitre/cases", headers=auth)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_case_asset_created(self, case_asset):
        case_name, asset_id = case_asset
        assert case_name == TEST_CASE
        assert asset_id is not None, "Asset was created but no ID found in DB"

    def test_list_assets_for_case(self, client, auth, case_asset):
        case_name, _ = case_asset
        r = client.get(f"/api/mitre/cases/{case_name}/assets", headers=auth)
        assert r.status_code == 200
        assert isinstance(r.json(), list)
        assert len(r.json()) >= 1

    def test_delete_nonexistent_case_is_idempotent(self, client, auth):
        r = client.delete("/api/mitre/cases/_no_such_case_xyz", headers=auth)
        # Idempotent — returns 200 SUCCESS even if case didn't exist
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# 3. MITRE LIBRARY
# ═══════════════════════════════════════════════════════════════════════════════

class TestMitreLibrary:
    def test_techniques_list_nonempty(self, client, auth):
        r = client.get("/api/mitre/techniques", headers=auth)
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list) and len(data) > 0, "Techniques list is empty — DB may not be seeded"

    def test_sidebar(self, client, auth):
        r = client.get("/api/mitre/sidebar", headers=auth)
        assert r.status_code == 200

    def test_matrix_layout(self, client, auth):
        r = client.get("/api/mitre/matrix-layout", headers=auth)
        assert r.status_code == 200

    def test_library_T1059(self, client, auth):
        r = client.get("/api/mitre/library/T1059", headers=auth)
        assert r.status_code == 200

    def test_geopolitical_groups(self, client, auth):
        r = client.get("/api/mitre/geopolitical/groups", headers=auth)
        assert r.status_code == 200

    def test_audit(self, client, auth):
        r = client.get("/api/mitre/audit", headers=auth)
        assert r.status_code == 200, f"Audit 500: {r.text[:300]}"
        data = r.json()
        assert "database_truth" in data and "backend_vision" in data


# ═══════════════════════════════════════════════════════════════════════════════
# 4. COVERAGE
# ═══════════════════════════════════════════════════════════════════════════════

class TestCoverage:
    def test_coverage_endpoint(self, client, auth):
        r = client.get("/api/coverage", headers=auth)
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# 5. INVESTIGATION PROFILES
# ═══════════════════════════════════════════════════════════════════════════════

class TestProfiles:
    def test_list_profiles(self, client, auth):
        r = client.get("/api/profiles", headers=auth)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_available_tcodes(self, client, auth):
        r = client.get("/api/profiles/tcodes/available", headers=auth)
        assert r.status_code == 200

    def test_create_and_delete_profile(self, client, auth):
        name = f"_smoke_profile_{uuid.uuid4().hex[:6]}"
        # Field name is "tcodes" (not "t_codes")
        r = client.post("/api/profiles", json={"name": name, "tcodes": ["T1059"]}, headers=auth)
        assert r.status_code == 200, f"Create profile failed: {r.status_code} {r.text}"
        pid = r.json().get("id") or r.json().get("profile_id")
        assert pid is not None, f"No id in create profile response: {r.json()}"

        r2 = client.delete(f"/api/profiles/{pid}", headers=auth)
        assert r2.status_code == 200, f"Delete profile failed: {r2.status_code} {r2.text}"


# ═══════════════════════════════════════════════════════════════════════════════
# 6. IOC
# ═══════════════════════════════════════════════════════════════════════════════

class TestIOC:
    def test_ioc_library(self, client, auth):
        r = client.get("/api/ioc/library", headers=auth)
        assert r.status_code == 200

    def test_ioc_search(self, client, auth):
        # Full ILIKE scan over evidence table — slow on large datasets; 60s timeout
        r = client.get("/api/ioc/search", params={"query": "test"}, headers=auth)
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# 7. NETWORK
# ═══════════════════════════════════════════════════════════════════════════════

class TestNetwork:
    def test_cert_info(self, client, auth):
        r = client.get("/api/network/cert-info", headers=auth)
        assert r.status_code == 200
        data = r.json()
        assert any(k in data for k in ("expires", "not_after", "subject", "expires_at")), \
            f"Unexpected cert-info shape: {data}"

    def test_detected_identity(self, client, auth):
        r = client.get("/api/network/detected-identity", headers=auth)
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# 8. AGENT PROTOCOL
# ═══════════════════════════════════════════════════════════════════════════════

class TestAgentProtocol:
    def test_register_agent(self, client, auth):
        r = client.post("/api/agent/register",
                        json={"hostname": "_smoke_agent", "capabilities": []},
                        headers=auth)
        assert r.status_code == 200, f"Agent register failed: {r.status_code} {r.text}"
        assert "agent_id" in r.json()

    def test_poll_jobs_returns_quickly(self, client, auth):
        r = client.post("/api/agent/register",
                        json={"hostname": "_smoke_poll", "capabilities": []},
                        headers=auth)
        assert r.status_code == 200
        agent_id = r.json()["agent_id"]

        agent_token = _mint_token(f"agent_{agent_id}", "agent", "AGT", 0)
        agent_headers = {"Authorization": f"Bearer {agent_token}"}

        start = time.time()
        r2 = client.get(f"/api/agent/{agent_id}/jobs", headers=agent_headers)
        elapsed = time.time() - start

        assert r2.status_code == 200, f"Poll failed: {r2.status_code} {r2.text}"
        body = r2.json()
        assert body is None or isinstance(body, dict), f"Unexpected poll response type: {body}"
        assert elapsed < 38, f"Poll took too long: {elapsed:.1f}s"


# ═══════════════════════════════════════════════════════════════════════════════
# 9. MEMORY
# ═══════════════════════════════════════════════════════════════════════════════

class TestMemory:
    def test_list_images(self, client, auth):
        r = client.get("/api/mitre/memory/list-images", headers=auth)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_memory_plugins(self, client, auth):
        r = client.get("/api/mitre/memory/plugins", headers=auth)
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# 10. ADMIN
# ═══════════════════════════════════════════════════════════════════════════════

class TestAdmin:
    def test_list_users_as_admin(self, client, auth):
        r = client.get("/api/admin/users", headers=auth)
        assert r.status_code == 200
        users = r.json()
        assert isinstance(users, list) and len(users) >= 1

    def test_list_users_as_analyst_is_forbidden(self, client):
        analyst_headers = {"Authorization": f"Bearer {_mint_token('user', 'analyst', 'USR', 2)}"}
        r = client.get("/api/admin/users", headers=analyst_headers)
        assert r.status_code == 403


# ═══════════════════════════════════════════════════════════════════════════════
# 11. EVIDENCE (requires case + asset fixture)
# ═══════════════════════════════════════════════════════════════════════════════

class TestEvidence:
    def test_timeline(self, client, auth, case_asset):
        _, asset_id = case_asset
        r = client.get(f"/api/mitre/evidence/{asset_id}/timeline", headers=auth)
        assert r.status_code == 200

    def test_evidence_by_tcode(self, client, auth, case_asset):
        _, asset_id = case_asset
        r = client.get(f"/api/mitre/evidence/{asset_id}/T1059", headers=auth)
        assert r.status_code == 200

    def test_technique_status(self, client, auth, case_asset):
        _, asset_id = case_asset
        r = client.get(f"/api/mitre/techniques/{asset_id}/status", headers=auth)
        assert r.status_code == 200
