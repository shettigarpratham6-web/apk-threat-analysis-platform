import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import backend.database.models  # noqa: F401  (registers tables)
from backend.app.routes import auth as auth_module
from backend.app.routes.auth import get_current_user, router
from backend.database.database import Base, engine

VALID = {"full_name": "Test Analyst", "email": "Analyst@Example.com", "password": "S3curePass99"}


@pytest.fixture()
def client():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    auth_module._failures.clear()

    app = FastAPI()
    app.include_router(router, prefix="/api/auth")

    @app.get("/secret")
    def secret(user=Depends(get_current_user)):
        return {"email": user.email}

    return TestClient(app)


def test_signup_sets_session_and_normalizes_email(client):
    r = client.post("/api/auth/signup", json=VALID)
    assert r.status_code == 201
    assert r.json()["email"] == "analyst@example.com"
    assert "password" not in r.text and "password_hash" not in r.text
    assert "httponly" in r.headers["set-cookie"].lower()
    assert client.get("/api/auth/me").json()["full_name"] == "Test Analyst"


def test_duplicate_email_is_rejected_case_insensitively(client):
    client.post("/api/auth/signup", json=VALID)
    r = client.post("/api/auth/signup", json={**VALID, "email": "ANALYST@example.com"})
    assert r.status_code == 409


@pytest.mark.parametrize("password", ["short1", "allletters", "12345678"])
def test_weak_passwords_are_rejected(client, password):
    r = client.post("/api/auth/signup", json={**VALID, "password": password})
    assert r.status_code == 422


def test_login_success_and_generic_failure_message(client):
    client.post("/api/auth/signup", json=VALID)
    client.post("/api/auth/logout")
    bad_pw = client.post("/api/auth/login", json={"email": VALID["email"], "password": "wrongpass1"})
    unknown = client.post("/api/auth/login", json={"email": "nobody@example.com", "password": "wrongpass1"})
    assert bad_pw.status_code == unknown.status_code == 401
    assert bad_pw.json() == unknown.json()  # no user enumeration
    ok = client.post("/api/auth/login", json={"email": VALID["email"], "password": VALID["password"]})
    assert ok.status_code == 200


def test_protected_route_requires_session_and_logout_clears_it(client):
    assert client.get("/secret").status_code == 401
    client.post("/api/auth/signup", json=VALID)
    assert client.get("/secret").json() == {"email": "analyst@example.com"}
    client.post("/api/auth/logout")
    assert client.get("/secret").status_code == 401


def test_tampered_token_is_rejected(client):
    client.cookies.set(auth_module.COOKIE_NAME, "not.a.jwt")
    assert client.get("/api/auth/me").status_code == 401


def test_lockout_after_repeated_failures(client):
    client.post("/api/auth/signup", json=VALID)
    client.post("/api/auth/logout")
    for _ in range(5):
        assert client.post("/api/auth/login", json={"email": VALID["email"], "password": "wrongpass1"}).status_code == 401
    r = client.post("/api/auth/login", json={"email": VALID["email"], "password": VALID["password"]})
    assert r.status_code == 429
