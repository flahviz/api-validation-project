import pytest
from fastapi.testclient import TestClient
from main import app
import jwt

JWT_SECRET = "local-dev-secret"
JWT_ALG = "HS256"

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

def test_validate_api_success():
    response = client.post(
        "/validate-api",
        json={
            "api_url": "https://jsonplaceholder.typicode.com/posts/1",
            "method": "GET",
            "expected_status": 200,
            "validation_rules": [
                {"field": "userId", "operator": "equals", "value": 1},
                {"field": "id", "operator": "exists", "value": None}
            ]
        },
    )
    assert response.status_code == 200
    assert response.json()["message"] == "API validated successfully"
    assert all(res["is_valid"] for res in response.json()["validation_results"])

def test_validate_api_failure_status_code():
    response = client.post(
        "/validate-api",
        json={
            "api_url": "https://jsonplaceholder.typicode.com/posts/1",
            "method": "GET",
            "expected_status": 201, # Expecting 201, but API returns 200
            "validation_rules": []
        },
    )
    assert response.status_code == 400
    assert "Expected status code 201, but got 200" in response.json()["detail"]

def test_validate_api_failure_rule():
    response = client.post(
        "/validate-api",
        json={
            "api_url": "https://jsonplaceholder.typicode.com/posts/1",
            "method": "GET",
            "expected_status": 200,
            "validation_rules": [
                {"field": "userId", "operator": "equals", "value": 999} # This should fail
            ]
        },
    )
    assert response.status_code == 400
    assert response.json()["detail"]["message"] == "Validation failed"
    assert len(response.json()["detail"]["failed_rules"]) == 1
    assert response.json()["detail"]["failed_rules"][0]["rule"]["field"] == "userId"

def test_require_role_missing_token():
    response = client.post(
        "/validate-api",
        json={
            "api_url": "https://jsonplaceholder.typicode.com/posts/1",
            "method": "GET",
            "expected_status": 200,
            "validation_rules": [],
            "require_role": "admin"
        },
    )
    assert response.status_code == 401
    assert "Authorization" in response.json()["detail"]

def test_require_role_ok():
    token = jwt.encode({"roles": ["admin"]}, JWT_SECRET, algorithm=JWT_ALG)
    response = client.post(
        "/validate-api",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "api_url": "https://jsonplaceholder.typicode.com/posts/1",
            "method": "GET",
            "expected_status": 200,
            "validation_rules": [],
            "require_role": "admin"
        },
    )
    assert response.status_code == 200

def test_api_key_and_product_validation_ok():
    # Uses seeded product 'demo' and api_key 'demo-key' from startup
    response = client.post(
        "/validate-api",
        json={
            "api_url": "https://jsonplaceholder.typicode.com/posts/1",
            "method": "GET",
            "expected_status": 200,
            "validation_rules": [],
            "product_name": "demo",
            "api_key": "demo-key"
        },
    )
    assert response.status_code == 200

