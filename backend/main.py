from typing import Any

import requests
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from jsonschema import validate as jsonschema_validate
import os

from auth import decode_jwt
from config import settings
from db import Base, engine, get_db
from models import Product, ApiKey
from schemas import APIValidationRequest, ValidationRule
from services_openapi import load_openapi_spec, validate_openapi_basic
from validators import (
    ensure_product_exists,
    validate_api_key_belongs_to_product,
    validate_server_url_allowed,
)
from sqlalchemy.orm import Session
from scanner_openapi import run_scan, render_html_report, render_html_executive_report

app = FastAPI(
    title="API Validation Service",
    description="Service for validating external APIs based on provided schemas and rules.",
)

# CORS for local dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    # Ensure data folder exists for SQLite persistence
    os.makedirs("data", exist_ok=True)
    # Create tables
    Base.metadata.create_all(bind=engine)
    # Optional: seed demo product and key for local testing
    from db import SessionLocal

    db = SessionLocal()
    try:
        demo = db.query(Product).filter(Product.name == "demo").first()
        if not demo:
            demo = Product(name="demo", description="Produto de exemplo")
            db.add(demo)
            db.commit()
            db.refresh(demo)
        has_key = db.query(ApiKey).filter(ApiKey.key == "demo-key").first()
        if not has_key:
            k = ApiKey(key="demo-key", product_id=demo.id)
            db.add(k)
            db.commit()
    finally:
        db.close()


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


@app.post("/validate-api")
async def validate_api(
    request_data: APIValidationRequest,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    # 1) Validate server URL whitelist
    validate_server_url_allowed(str(request_data.api_url))

    # 2) If require_role provided, validate JWT roles
    if request_data.require_role:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Authorization header ausente ou inválido")
        payload = decode_jwt(authorization.split(" ", 1)[1])
        roles = payload.get("roles", [])
        if request_data.require_role not in (roles if isinstance(roles, list) else [roles]):
            raise HTTPException(status_code=403, detail="Usuário não possui a role necessária")

    # 3) Product existence and API key association validations
    if request_data.product_name:
        ensure_product_exists(db, request_data.product_name)
    if request_data.api_key and request_data.product_name:
        validate_api_key_belongs_to_product(db, request_data.api_key, request_data.product_name)
    elif request_data.api_key and not request_data.product_name:
        # If key provided without product, still ensure key is valid
        from validators import validate_api_key

        validate_api_key(db, request_data.api_key)

    # 4) Make the external API request
    try:
        response = requests.request(
            method=request_data.method,
            url=str(request_data.api_url),
            headers=request_data.headers,
            json=request_data.body if request_data.body else None,
            timeout=10,
        )
        # Do not raise for status yet; we check expected manually
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=400, detail=f"API request failed: {e}")

    # 5) Status code validation
    if response.status_code != request_data.expected_status:
        raise HTTPException(
            status_code=400,
            detail=f"Expected status code {request_data.expected_status}, but got {response.status_code}",
        )

    # 6) Parse JSON response
    try:
        response_json: dict[str, Any] = response.json()
    except ValueError:
        raise HTTPException(status_code=400, detail="Resposta da API não é um JSON válido")

    # 7) Field-level validation rules
    validation_results = []
    for rule in request_data.validation_rules:
        field_value = response_json.get(rule.field)
        is_valid = False
        if rule.operator == "equals":
            is_valid = field_value == rule.value
        elif rule.operator == "not_equals":
            is_valid = field_value != rule.value
        elif rule.operator == "greater_than":
            is_valid = field_value > rule.value
        elif rule.operator == "less_than":
            is_valid = field_value < rule.value
        elif rule.operator == "contains":
            is_valid = (rule.value in field_value) if isinstance(field_value, str) else False
        elif rule.operator == "not_contains":
            is_valid = (rule.value not in field_value) if isinstance(field_value, str) else False
        elif rule.operator == "exists":
            is_valid = field_value is not None
        elif rule.operator == "not_exists":
            is_valid = field_value is None
        validation_results.append({
            "rule": rule.dict(),
            "field_value": field_value,
            "is_valid": is_valid,
        })

    # 8) OpenAPI spec validation (basic + optional schema validation)
    openapi_validation = {"checked": False}
    if request_data.swagger_url:
        spec = load_openapi_spec(str(request_data.swagger_url))
        ok, errors = validate_openapi_basic(spec)
        if not ok:
            raise HTTPException(status_code=400, detail={"message": "OpenAPI inválida", "errors": errors})
        openapi_validation = {"checked": True, "basic_valid": True}

        if request_data.schema_ref:
            try:
                schema = spec.get("components", {}).get("schemas", {}).get(request_data.schema_ref)
                if not schema:
                    raise HTTPException(status_code=400, detail=f"Schema '{request_data.schema_ref}' não encontrado em components.schemas")
                jsonschema_validate(instance=response_json, schema=schema)
                openapi_validation["schema_valid"] = True
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Validação de schema falhou: {e}")

    if not all(res["is_valid"] for res in validation_results):
        failed_rules = [res for res in validation_results if not res["is_valid"]]
        raise HTTPException(
            status_code=400,
            detail={"message": "Validation failed", "failed_rules": failed_rules},
        )

    return {
        "message": "API validated successfully",
        "validation_results": validation_results,
        "api_response": response_json,
        "openapi_validation": openapi_validation,
    }


@app.post("/scan-openapi")
async def scan_openapi(payload: dict):
    """
    Body:
    {
      "swagger_url": "https://.../openapi.json",
      "base_url_override": "https://api.example.com" (opcional)
    }
    """
    import traceback, logging
    logger = logging.getLogger("uvicorn.error")

    swagger_url = payload.get("swagger_url")
    base_url_override = payload.get("base_url_override")
    destructive_mode = payload.get("destructive_mode", "safe")
    include_paths = payload.get("include_paths")
    if not swagger_url:
        raise HTTPException(status_code=400, detail="swagger_url é obrigatório")
    try:
        report = run_scan(
            swagger_url=swagger_url,
            base_url_override=base_url_override,
            destructive_mode=destructive_mode,
            include_paths=include_paths,
        )
        return report
    except HTTPException:
        # re-raise known http errors
        raise
    except Exception as e:
        logger.error("Scan unexpected error: %s\n%s", e, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"scan_error: {e}")


@app.post("/scan-openapi/html/executive")
async def scan_openapi_html_executive(payload: dict):
    """
    Executive version of the HTML report with concise insights and recommendations.
    Body is the same as /scan-openapi.
    """
    import traceback, logging
    logger = logging.getLogger("uvicorn.error")

    swagger_url = payload.get("swagger_url")
    base_url_override = payload.get("base_url_override")
    destructive_mode = payload.get("destructive_mode", "safe")
    include_paths = payload.get("include_paths")
    if not swagger_url:
        raise HTTPException(status_code=400, detail="swagger_url é obrigatório")
    try:
        report = run_scan(
            swagger_url=swagger_url,
            base_url_override=base_url_override,
            destructive_mode=destructive_mode,
            include_paths=include_paths,
        )
        html = render_html_executive_report(report)
        return Response(content=html, media_type="text/html")
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Scan Executive HTML unexpected error: %s\n%s", e, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"scan_error: {e}")


@app.post("/scan-openapi/html")
async def scan_openapi_html(payload: dict):
    """
    Same body as /scan-openapi, but returns an HTML report.
    """
    import traceback, logging
    logger = logging.getLogger("uvicorn.error")

    swagger_url = payload.get("swagger_url")
    base_url_override = payload.get("base_url_override")
    destructive_mode = payload.get("destructive_mode", "safe")
    include_paths = payload.get("include_paths")
    if not swagger_url:
        raise HTTPException(status_code=400, detail="swagger_url é obrigatório")
    try:
        report = run_scan(
            swagger_url=swagger_url,
            base_url_override=base_url_override,
            destructive_mode=destructive_mode,
            include_paths=include_paths,
        )
        html = render_html_report(report)
        return Response(content=html, media_type="text/html")
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Scan HTML unexpected error: %s\n%s", e, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"scan_error: {e}")
