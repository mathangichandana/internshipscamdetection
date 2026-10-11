import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app, init_db, get_db

@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-key"
    with app.test_client() as client:
        with app.app_context():
            init_db()
        yield client


# Tests home page renders with sample buttons and status 200
def test_app_home_get(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"InternGuard" in response.data
    assert b"Analyze Internship Posting" in response.data
    assert b"Load Scam Example" in response.data


# Tests post submission of internship scanning
def test_app_home_post_scan(client):
    scam_text = "Work from home typing job. Earn Rs. 50,000 per month. Pay Rs. 2000 registration fee. Immediate joining."
    response = client.post("/", data={"posting": scam_text})
    assert response.status_code == 200
    assert b"Assessment Outcome" in response.data
    assert b"Rule Engine Score" in response.data
    assert b"ML Model Probability" in response.data


# Tests user registration, session creation, and login flow
def test_app_auth_flow(client):
    # 1. Register new user
    import time
    username = f"student_{int(time.time() * 1000)}"
    reg_response = client.post(
        "/register",
        data={
            "username": username,
            "password": "password123",
            "confirm_password": "password123",
        },
        follow_redirects=True,
    )
    assert reg_response.status_code == 200
    assert bytes(username, "utf-8") in reg_response.data

    # 2. View history page as authenticated user
    hist_response = client.get("/history")
    assert hist_response.status_code == 200
    assert b"Report History" in hist_response.data

    # 3. Logout
    logout_response = client.get("/logout", follow_redirects=True)
    assert logout_response.status_code == 200
    assert b"Sign In" in logout_response.data

    # 4. Login with registered credentials
    login_response = client.post(
        "/login",
        data={"username": username, "password": "password123"},
        follow_redirects=True,
    )
    assert login_response.status_code == 200
    assert bytes(username, "utf-8") in login_response.data


# Tests dashboard renders statistics and bar chart elements
def test_app_dashboard(client):
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert b"Risk Analytics Dashboard" in response.data
    assert b"Risk Level Distribution" in response.data
    assert b"Machine Learning Model Performance" in response.data
