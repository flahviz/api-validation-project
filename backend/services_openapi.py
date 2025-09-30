from typing import Any, Dict, Tuple
import json
import yaml
import requests
from fastapi import HTTPException
from copy import deepcopy

REQUIRED_OPENAPI_FIELDS = ["openapi", "info", "paths"]


def _normalize_openapi_spec(spec: Dict[str, Any]) -> Dict[str, Any]:
    """If the spec is Swagger 2.0, normalize it to a minimal OpenAPI 3-like
    structure that our scanner expects (servers, components.securitySchemes,
    requestBody for body params). Non-destructive for OpenAPI 3.x.
    """
    if isinstance(spec, dict) and spec.get("swagger") == "2.0":
        v2 = deepcopy(spec)
        v3: Dict[str, Any] = {}
        # Basic fields
        v3["openapi"] = "3.0.0"
        v3["info"] = v2.get("info", {})
        v3["paths"] = deepcopy(v2.get("paths", {}))

        # Servers from host/schemes/basePath
        host = v2.get("host") or ""
        base_path = v2.get("basePath") or ""
        schemes = v2.get("schemes") or ["http"]
        servers = []
        for sch in schemes:
            if host:
                url = f"{sch}://{host}{base_path}"
                servers.append({"url": url})
        if not servers and host:
            servers = [{"url": f"http://{host}{base_path}"}]
        v3["servers"] = servers

        # SecuritySchemes
        sec_defs = v2.get("securityDefinitions", {})
        v3["components"] = {"securitySchemes": deepcopy(sec_defs)}
        # Global/op security stays compatible
        if "security" in v2:
            v3["security"] = deepcopy(v2.get("security"))

        # Convert body parameters -> requestBody
        for path, methods in list(v3["paths"].items()):
            for method, op in list(methods.items()):
                if not isinstance(op, dict):
                    continue
                params = op.get("parameters", []) or []
                body_param = None
                other_params = []
                for p in params:
                    if isinstance(p, dict) and p.get("in") == "body" and p.get("schema"):
                        if body_param is None:
                            body_param = p
                    else:
                        other_params.append(p)
                if body_param:
                    op["requestBody"] = {
                        "content": {
                            "application/json": {
                                "schema": deepcopy(body_param["schema"])
                            }
                        }
                    }
                # keep non-body params
                op["parameters"] = other_params
        # Mark original
        v3["x-original-spec"] = "swagger_2.0"
        return v3
    # Already OpenAPI 3.x or unrecognized -> return as-is
    return spec


def load_openapi_spec(url: str) -> Dict[str, Any]:
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
    except requests.RequestException as e:
        raise HTTPException(status_code=400, detail=f"Falha ao baixar especificação OpenAPI: {e}")

    text = resp.text
    try:
        if url.endswith((".yaml", ".yml")):
            raw = yaml.safe_load(text)
        else:
            raw = json.loads(text)
        return _normalize_openapi_spec(raw)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Falha ao parsear especificação OpenAPI: {e}")


def validate_openapi_basic(spec: Dict[str, Any]) -> Tuple[bool, list[str]]:
    errors: list[str] = []
    for field in REQUIRED_OPENAPI_FIELDS:
        if field not in spec:
            errors.append(f"Campo obrigatório ausente na especificação: {field}")
    return (len(errors) == 0, errors)
