from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
import re
import requests
from faker import Faker
from jsonschema import validate as jsonschema_validate
from fastapi import HTTPException

from services_openapi import load_openapi_spec, validate_openapi_basic
from urllib.parse import urlparse, parse_qs
from fnmatch import fnmatch
from validators import validate_server_url_allowed

fake = Faker()


def _mock_primitive(schema: Dict[str, Any]) -> Any:
    t = schema.get("type")
    fmt = schema.get("format")
    enum = schema.get("enum")
    if enum:
        return enum[0]
    if t == "string":
        if fmt == "date-time":
            return fake.iso8601()
        if fmt == "email":
            return fake.email()
        if fmt == "uuid":
            return str(fake.uuid4())
        if fmt == "uri":
            return fake.url()
        return fake.word()
    if t == "integer":
        return fake.random_int(min=0, max=100)
    if t == "number":
        return float(fake.pydecimal(left_digits=2, right_digits=2, positive=True))
    if t == "boolean":
        return fake.pybool()
    return None


def _resolve_schema(schema: Dict[str, Any], components: Optional[Dict[str, Any]], visited: set[str], depth: int) -> Dict[str, Any]:
    """Resolve $ref and simple composed schemas to a concrete schema safely."""


def render_html_executive_report(report: Dict[str, Any]) -> str:
    """Render an executive, non-technical HTML report with concise insights and recommendations."""
    import html
    s = report.get("summary", {})
    findings = report.get("findings", [])
    meta = report.get("meta", {})

    outsider_can_access = bool(s.get("read_exposures", 0))
    outsider_can_act = bool(s.get("write_exposures", 0))

    # Group exposures (reads) by endpoint
    exposures = [f for f in findings if f.get("issue") == "potential_exposure"]
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for f in exposures:
        key = f"{str(f.get('method',''))} {str(f.get('path',''))}"
        grouped.setdefault(key, []).append(f)

    grouped_items: List[str] = []
    for k, arr in sorted(grouped.items(), key=lambda x: (-len(x[1]), x[0])):
        examples = "; ".join(str(a.get("detail", "")) for a in arr[:2])
        grouped_items.append(f"<li>{html.escape(k)} — {len(arr)} cenários (ex.: {html.escape(examples)})</li>")
    exposed_list_html = "\n".join(grouped_items) if grouped_items else "<li>Nenhum endpoint de leitura exposto detectado.</li>"

    invalids = [f for f in findings if f.get("issue") == "invalid_status"]
    invalids_html = "\n".join(
        f"<li>{html.escape(str(f.get('method','')))} {html.escape(str(f.get('path','')))} — {html.escape(str(f.get('detail','')))}</li>"
        for f in invalids
    ) or "<li>Nenhum</li>"

    # Recommendations (simple rules)
    recs: List[str] = []
    if outsider_can_access:
        recs.append("Aplicar autenticação obrigatória nos endpoints de leitura listados abaixo (401/403 sem credencial válida).")
    if outsider_can_act:
        recs.append("Bloquear operações de escrita sem credencial válida; validar token antes de executar ações.")
    if s.get("invalid_status", 0):
        recs.append("Alinhar documentação: adicionar respostas 4xx/5xx/405 esperadas ou ajustar comportamento do servidor.")
    if s.get("schema_mismatches", 0):
        recs.append("Revisar contratos: corrigir schemas ou payloads para aderência ao OpenAPI.")
    if not recs:
        recs.append("Sem ações críticas no momento. Manter monitoramento periódico.")
    recs_html = "\n".join(f"<li>{html.escape(r)}</li>" for r in recs)

    current_date = datetime.now().strftime('%d/%m/%Y')
    return f"""
<!DOCTYPE html>
<html lang="pt-br">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Relatório Executivo - Scan OpenAPI</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color:#1f2937; }}
    h1 {{ margin-bottom: 4px; }}
    h2 {{ margin-top: 18px; }}
    .meta {{ color:#4b5563; font-size:14px; margin-bottom:14px; }}
    .kpis {{ display:grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 10px; }}
    .kpis div {{ border:1px solid #e5e7eb; border-radius:10px; padding:10px 12px; background:#fafafa; }}
    .badge {{ display:inline-block; padding:4px 8px; border-radius:12px; font-size:12px; color:#fff; }}
    .ok {{ background:#10b981; }}
    .danger {{ background:#ef4444; }}
    ul {{ margin: 8px 0 0 18px; }}
  </style>
</head>
<body>
  <h1>Relatório Executivo - Scan OpenAPI</h1>
  <div class="meta">
    <div><strong>Spec:</strong> {html.escape(str(meta.get('swagger_url','')))}</div>
    <div><strong>Base URL:</strong> {html.escape(str(meta.get('base_url','')))}</div>
    <div><strong>Quando:</strong> {html.escape(str(meta.get('timestamp','')))}</div>
  </div>
  <div class="kpis">
    <div><strong>Acesso de fora possível?</strong> <span class="badge { 'danger' if outsider_can_access else 'ok' }">{ 'SIM' if outsider_can_access else 'NÃO' }</span></div>
    <div><strong>Ações de fora possíveis?</strong> <span class="badge { 'danger' if outsider_can_act else 'ok' }">{ 'SIM' if outsider_can_act else 'NÃO' }</span></div>
    <div><strong>Leituras expostas:</strong> {html.escape(str(s.get('read_exposures',0)))}</div>
    <div><strong>Escritas expostas:</strong> {html.escape(str(s.get('write_exposures',0)))}</div>
    <div><strong>Status não documentados:</strong> {html.escape(str(s.get('invalid_status',0)))}</div>
    <div><strong>Erros de requisição:</strong> {html.escape(str(s.get('request_errors',0)))}</div>
  </div>

  <h2>Principais Achados (Leitura Exposta)</h2>
  <ul>
    {exposed_list_html}
  </ul>

  <h2>Status Não Documentados</h2>
  <ul>
    {invalids_html}
  </ul>

  <h2>Recomendações</h2>
  <ul>
    {recs_html}
  </ul>
</body>
</html>
"""
    if not isinstance(schema, dict):
        return {}
    if depth > 4:
        return {}

    # $ref
    if "$ref" in schema and components:
        ref = schema["$ref"]
        if ref in visited:
            return {}
        visited.add(ref)
        parts = ref.split("/")
        if len(parts) >= 4 and parts[1] == "components" and parts[2] == "schemas":
            name = parts[3]
            target = components.get("schemas", {}).get(name)
            if isinstance(target, dict):
                return _resolve_schema(target, components, visited, depth + 1)
            return {}

    # allOf: shallow merge properties and type when available
    if isinstance(schema.get("allOf"), list):
        merged: Dict[str, Any] = {}
        merged_props: Dict[str, Any] = {}
        for part in schema["allOf"]:
            res = _resolve_schema(part, components, visited, depth + 1)
            if "properties" in res and isinstance(res["properties"], dict):
                merged_props.update(res["properties"])
            # prefer explicit type when provided
            if "type" in res:
                merged["type"] = res["type"]
        if merged_props:
            merged["type"] = merged.get("type", "object")
            merged["properties"] = merged_props
        return merged or schema

    # oneOf/anyOf: pick first resolved subschema
    for key in ("oneOf", "anyOf"):
        if isinstance(schema.get(key), list) and schema[key]:
            return _resolve_schema(schema[key][0], components, visited, depth + 1)

    # Nothing to resolve further
    return schema


def generate_mock_from_schema(
    schema: Dict[str, Any],
    components: Dict[str, Any] | None = None,
    depth: int = 0,
    visited: set[str] | None = None,
) -> Any:
    if visited is None:
        visited = set()
    # Resolve to a concrete schema first
    schema = _resolve_schema(schema, components, visited, depth)
    if not isinstance(schema, dict):
        return None
    if depth > 4:
        return None

    schema_type = schema.get("type")

    if schema_type == "object" or ("properties" in schema):
        props = schema.get("properties", {}) or {}
        obj = {}
        for key, prop_schema in props.items():
            obj[key] = generate_mock_from_schema(prop_schema, components, depth + 1, visited)
        return obj

    if schema_type == "array":
        item_schema = schema.get("items", {"type": "string"})
        return [generate_mock_from_schema(item_schema, components, depth + 1, visited) for _ in range(2)]

    return _mock_primitive(schema)


def safe_generate(schema: Dict[str, Any], components: Dict[str, Any]) -> Any:
    try:
        return generate_mock_from_schema(schema, components, depth=0, visited=set())
    except RecursionError:
        return None
    except Exception:
        return None


def build_request_data_for_operation(spec: Dict[str, Any], path: str, method: str) -> Dict[str, Any]:
    op = spec.get("paths", {}).get(path, {}).get(method.lower(), {})
    params = op.get("parameters", []) + spec.get("paths", {}).get(path, {}).get("parameters", [])
    components = spec.get("components", {})

    path_params: Dict[str, str] = {}
    query_params: Dict[str, str] = {}
    headers: Dict[str, str] = {}

    for p in params:
        name = p.get("name")
        loc = p.get("in")
        schema = p.get("schema", {})
        val = safe_generate(schema, components)
        if val is None:
            continue
        val_str = str(val)
        if loc == "path":
            path_params[name] = val_str
        elif loc == "query":
            query_params[name] = val_str
        elif loc == "header":
            headers[name] = val_str

    # requestBody
    body_json: Optional[Dict[str, Any]] = None
    request_body = op.get("requestBody")
    if isinstance(request_body, dict):
        content = request_body.get("content", {})
        app_json = content.get("application/json")
        if app_json:
            schema = app_json.get("schema", {"type": "object"})
            body_json = safe_generate(schema, components)

    return {
        "path_params": path_params,
        "query_params": query_params,
        "headers": headers,
        "json": body_json,
    }


def _apply_path_params(path: str, path_params: Dict[str, str]) -> str:
    for k, v in path_params.items():
        path = re.sub(r"{\s*" + re.escape(k) + r"\s*}", v, path)
    return path


def detect_security_requirement(spec: Dict[str, Any], op: Dict[str, Any]) -> bool:
    # global or op-level security presence indicates auth required
    global_sec = spec.get("security")
    op_sec = op.get("security")
    return bool(global_sec) or bool(op_sec)


def collect_required_schemes(spec: Dict[str, Any], op: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return list of security requirement objects applicable to the operation.
    Each obj is a dict of { schemeName: [] } as per OpenAPI.
    """
    reqs: List[Dict[str, Any]] = []
    if isinstance(spec.get("security"), list):
        reqs.extend([r for r in spec["security"] if isinstance(r, dict)])
    if isinstance(op.get("security"), list):
        reqs.extend([r for r in op["security"] if isinstance(r, dict)])
    return reqs


def apply_auth_scenario(headers: Dict[str, str], params: Dict[str, str], scheme_name: str, scheme_def: Dict[str, Any], scenario: str):
    """Mutate headers/params to simulate an auth scenario for a given scheme.
    scenario in { 'none', 'invalid_bearer', 'invalid_api_key' }
    """
    stype = (scheme_def.get("type") or "").lower()
    if scenario == "none":
        return
    if stype == "http" and (scheme_def.get("scheme") or "").lower() == "bearer":
        if scenario == "invalid_bearer":
            headers["Authorization"] = "Bearer INVALIDO"  # invalid token
        elif scenario == "bearer_wrong_prefix":
            headers["Authorization"] = "Token QUALQUER"  # wrong auth scheme
        elif scenario == "bearer_empty":
            headers["Authorization"] = "Bearer "  # empty token
    if stype == "apiKey":
        name = scheme_def.get("name") or "X-API-KEY"
        location = (scheme_def.get("in") or "header").lower()
        if scenario == "invalid_api_key":
            if location == "header":
                headers[name] = "INVALIDA"
            elif location == "query":
                params[name] = "INVALIDA"
            # cookie not supported in this scan
        elif scenario == "api_key_empty":
            if location == "header":
                headers[name] = ""
            elif location == "query":
                params[name] = ""


def run_scan(
    swagger_url: str,
    base_url_override: Optional[str] = None,
    destructive_mode: str = "safe",
    include_paths: Optional[List[str]] = None,
) -> Dict[str, Any]:
    # Allow users to paste a Swagger UI HTML; try extract ?url= raw spec
    if swagger_url.endswith(".html"):
        parsed = urlparse(swagger_url)
        q = parse_qs(parsed.query)
        raw_url = q.get("url", [None])[0]
        if not raw_url:
            # try common candidates on same origin
            origin = f"{parsed.scheme}://{parsed.netloc}"
            candidates = [
                f"{origin}/openapi.json",
                f"{origin}/v3/api-docs",
                f"{origin}/swagger/v1/swagger.json",
            ]
            for cand in candidates:
                try:
                    r = requests.get(cand, timeout=5)
                    r.raise_for_status()
                    # rudimentary check: JSON parseable
                    _ = r.json()
                    raw_url = cand
                    break
                except Exception:
                    continue
        if not raw_url:
            raise HTTPException(status_code=400, detail="Forneça a URL do OpenAPI (JSON/YAML) ou use um Swagger UI com parâmetro ?url=<spec.json>")
        swagger_url = raw_url

    # Load and basic validate spec
    spec = load_openapi_spec(swagger_url)
    ok, errors = validate_openapi_basic(spec)
    if not ok:
        raise HTTPException(status_code=400, detail={"message": "OpenAPI inválida", "errors": errors})

    # Determine base URL
    parsed_sw_url = urlparse(swagger_url)
    origin = f"{parsed_sw_url.scheme}://{parsed_sw_url.netloc}" if parsed_sw_url.scheme and parsed_sw_url.netloc else ""

    base_url = None
    if base_url_override:
        base_url = base_url_override
    else:
        servers = spec.get("servers", []) or []
        if isinstance(servers, list) and servers:
            raw = servers[0].get("url") if isinstance(servers[0], dict) else None
            if raw:
                if raw.startswith("http://") or raw.startswith("https://"):
                    base_url = raw
                elif raw.startswith("/") and origin:
                    base_url = origin.rstrip("/") + raw
                else:
                    # relative or unexpected, try join with origin
                    base_url = origin.rstrip("/") + "/" + raw.lstrip("/") if origin and raw else None
        if not base_url and origin:
            base_url = origin
    if not base_url:
        raise HTTPException(status_code=400, detail="Não foi possível determinar a base da API. Informe base_url_override.")

    validate_server_url_allowed(base_url)

    paths = spec.get("paths", {})
    components = spec.get("components", {})

    report: Dict[str, Any] = {
        "summary": {
            "total_operations": 0,
            "potential_exposures": 0,
            "exposures_unauth": 0,
            "exposures_invalid_token": 0,
            "exposures_invalid_format": 0,
            "invalid_status": 0,
            "schema_mismatches": 0,
            "request_errors": 0,
            "read_exposures": 0,
            "write_exposures": 0,
            "outsider_can_access": False,
            "outsider_can_perform_actions": False,
            "verified_deletions": 0,
            "verified_updates": 0,
        },
        "findings": [],
        "meta": {
            "swagger_url": swagger_url,
            "base_url": base_url,
            "destructive_mode": destructive_mode,
            "include_paths": include_paths or [],
            "timestamp": fake.iso8601(),
        },
    }

    def _included(p: str) -> bool:
        if not include_paths:
            return True
        for pat in include_paths:
            if fnmatch(p, pat):
                return True
        return False

    allowed_methods = {"get", "post", "put", "patch", "delete"}
    # Category per issue type
    def _category_for(issue: str) -> str:
        if issue == "potential_exposure":
            return "Autenticação/Autorização"
        if issue in ("invalid_status", "schema_mismatch"):
            return "Contrato (OpenAPI)"
        if issue in ("side_effect", "side_effect_verify_error"):
            return "Efeito colateral"
        if issue == "request_error":
            return "Requisição"
        if issue == "recursion_limit":
            return "Mock/Geração"
        return "Outros"
    for path, methods in paths.items():
        if not _included(path):
            continue
        for method, op in methods.items():
            if method.lower() not in allowed_methods:
                continue
            report["summary"]["total_operations"] += 1
            # Build expected statuses string for this operation to attach to all findings
            try:
                _op_responses = op.get("responses", {}) if isinstance(op, dict) else {}
                _expected_statuses = sorted(_op_responses.keys()) if isinstance(_op_responses, dict) else []
            except Exception:
                _expected_statuses = []
            _expected_str = ", ".join(_expected_statuses) if _expected_statuses else "Não documentado"
            try:
                request_data = build_request_data_for_operation(spec, path, method)
            except RecursionError:
                report["findings"].append({
                    "path": path,
                    "method": method.upper(),
                    "issue": "recursion_limit",
                    "category": _category_for("recursion_limit"),
                    "scenario": "-",
                    "detail": "Mock generation exceeded recursion depth",
                    "expected": _expected_str,
                })
                continue
            url_path = _apply_path_params(path, request_data["path_params"]) if request_data["path_params"] else path
            url = base_url.rstrip("/") + "/" + url_path.lstrip("/")

            requires_auth = detect_security_requirement(spec, op)
            _expected_outsider = "401/403" if requires_auth else "— (público)"

            # Build scenarios
            schemes_req = collect_required_schemes(spec, op)
            sec_schemes = spec.get("components", {}).get("securitySchemes", {})
            scenarios = [
                ("none", {}),
            ]
            # Add invalid bearer/apiKey scenarios if present in schemes
            scheme_names = set()
            for r in schemes_req:
                for name in r.keys():
                    scheme_names.add(name)
            has_bearer = any((sec_schemes.get(n, {}).get("type") == "http" and (sec_schemes.get(n, {}).get("scheme") or "").lower() == "bearer") for n in scheme_names)
            has_api_key = any((sec_schemes.get(n, {}).get("type") == "apiKey") for n in scheme_names)
            if has_bearer:
                scenarios.append(("invalid_bearer", {}))
                scenarios.append(("bearer_wrong_prefix", {}))
                scenarios.append(("bearer_empty", {}))
            if has_api_key:
                scenarios.append(("invalid_api_key", {}))
                scenarios.append(("api_key_empty", {}))

            # Run scenarios
            last_resp = None
            for scenario_name, _ in scenarios:
                headers = dict(request_data["headers"])
                params = dict(request_data["query_params"])
                # Apply auth mutation for each required scheme (OR semantics between requirement objects)
                for r in schemes_req:
                    for n in r.keys():
                        scheme_def = sec_schemes.get(n, {})
                        apply_auth_scenario(headers, params, n, scheme_def, scenario_name)
                try:
                    resp = requests.request(
                        method.upper(),
                        url,
                        headers=headers,
                        params=params,
                        json=request_data["json"],
                        timeout=15,
                    )
                    last_resp = resp
                except requests.RequestException as e:
                    report["summary"]["request_errors"] += 1
                    report["findings"].append({
                        "path": path,
                        "method": method.upper(),
                        "issue": "request_error",
                        "category": _category_for("request_error"),
                        "scenario": scenario_name,
                        "detail": f"Erro no cenário {scenario_name}: {e}",
                        "expected": _expected_str,
                        "expected_outsider": _expected_outsider,
                    })
                    continue

                # exposure checks
                if requires_auth and 200 <= resp.status_code < 300:
                    key = "potential_exposures"
                    if scenario_name == "none":
                        report["summary"]["exposures_unauth"] += 1
                    elif scenario_name in ("invalid_bearer", "invalid_api_key"):
                        report["summary"]["exposures_invalid_token"] += 1
                    elif scenario_name in ("bearer_wrong_prefix", "bearer_empty", "api_key_empty"):
                        report["summary"]["exposures_invalid_format"] += 1
                    report["summary"][key] += 1
                    # Categorize as read/write exposure
                    if method.upper() == "GET":
                        report["summary"]["read_exposures"] += 1
                    elif method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
                        report["summary"]["write_exposures"] += 1
                    report["findings"].append({
                        "path": path,
                        "method": method.upper(),
                        "issue": "potential_exposure",
                        "category": _category_for("potential_exposure"),
                        "scenario": scenario_name,
                        "detail": f"Protegido no spec: cenário {scenario_name} deveria retornar 401/403; retornou {resp.status_code}.",
                        "status": resp.status_code,
                        "expected": _expected_str,
                        "expected_outsider": _expected_outsider,
                    })

            # 2) side-effect verification (basic) for DELETE
            if method.upper() == "DELETE" and last_resp is not None and 200 <= last_resp.status_code < 300:
                try:
                    verify_resp = requests.get(url, headers={}, params={}, timeout=10)
                    if verify_resp.status_code in (404, 410):
                        report["summary"]["verified_deletions"] += 1
                        report["findings"].append({
                            "path": path,
                            "method": method.upper(),
                            "issue": "side_effect",
                            "category": _category_for("side_effect"),
                            "scenario": scenario_name,
                            "detail": "DELETE seguido de GET retornou 404/410 (deleção confirmada)",
                            "status": verify_resp.status_code,
                            "side_effect_verified": True,
                            "verification_detail": "GET após DELETE retornou not-found",
                            "expected": _expected_str,
                            "expected_outsider": _expected_outsider,
                        })
                    else:
                        report["findings"].append({
                            "path": path,
                            "method": method.upper(),
                            "issue": "side_effect",
                            "category": _category_for("side_effect"),
                            "scenario": scenario_name,
                            "detail": f"DELETE seguido de GET retornou {verify_resp.status_code} (não confirmado)",
                            "status": verify_resp.status_code,
                            "side_effect_verified": False,
                            "verification_detail": "GET após DELETE não retornou not-found",
                            "expected": _expected_str,
                            "expected_outsider": _expected_outsider,
                        })
                except requests.RequestException as e:
                    report["findings"].append({
                        "path": path,
                        "method": method.upper(),
                        "issue": "side_effect_verify_error",
                        "category": _category_for("side_effect_verify_error"),
                        "scenario": scenario_name,
                        "detail": str(e),
                        "expected": _expected_str,
                        "expected_outsider": _expected_outsider,
                    })

            # 3) invalid status: not in documented responses
            documented_statuses = set(op.get("responses", {}).keys())
            status_str = str((last_resp or resp).status_code)
            if documented_statuses and status_str not in documented_statuses and f"{status_str[0]}XX" not in documented_statuses:
                report["summary"]["invalid_status"] += 1
                expected_list = sorted(documented_statuses)
                report["findings"].append({
                    "path": path,
                    "method": method.upper(),
                    "issue": "invalid_status",
                    "category": _category_for("invalid_status"),
                    "scenario": scenario_name,
                    "detail": f"Status {(last_resp or resp).status_code} não documentado",
                    "status": (last_resp or resp).status_code,
                    "expected": ", ".join(expected_list),
                    "expected_outsider": _expected_outsider,
                })

            # 4) schema validate (if available)
            try:
                ct = (last_resp or resp).headers.get("Content-Type", "")
                if "application/json" in ct:
                    response_json = (last_resp or resp).json()
                    # Prefer the schema for the exact status, else 2XX
                    resp_obj = op.get("responses", {}).get(status_str) or op.get("responses", {}).get("2XX") or {}
                    content = resp_obj.get("content", {}).get("application/json")
                    if content and "schema" in content:
                        schema = content["schema"]
                        # resolve refs using components
                        def resolve_refs(node: Dict[str, Any]) -> Dict[str, Any]:
                            if "$ref" in node:
                                ref = node["$ref"]
                                parts = ref.split("/")
                                if len(parts) >= 4 and parts[1] == "components" and parts[2] == "schemas":
                                    name = parts[3]
                                    return components.get("schemas", {}).get(name, {})
                            return node
                        resolved = resolve_refs(schema)
                        try:
                            jsonschema_validate(instance=response_json, schema=resolved)
                        except RecursionError as re:
                            raise Exception("schema validation recursion too deep") from re
            except Exception as e:
                report["summary"]["schema_mismatches"] += 1
                report["findings"].append({
                    "path": path,
                    "method": method.upper(),
                    "issue": "schema_mismatch",
                    "category": _category_for("schema_mismatch"),
                    "scenario": scenario_name,
                    "detail": str(e),
                    "expected": _expected_str,
                    "expected_outsider": _expected_outsider,
                })

    # Compute high-level verdicts
    report["summary"]["outsider_can_access"] = report["summary"].get("read_exposures", 0) > 0
    report["summary"]["outsider_can_perform_actions"] = report["summary"].get("write_exposures", 0) > 0
    return report


def render_html_report(report: Dict[str, Any]) -> str:
    """Render a simple HTML report from the scan results."""
    import html
    from datetime import datetime
    s = report.get("summary", {})
    findings = report.get("findings", [])
    outsider_can_access = s.get("outsider_can_access") or (s.get("read_exposures", 0) > 0)
    outsider_can_perform_actions = s.get("outsider_can_perform_actions") or (s.get("write_exposures", 0) > 0)
    meta = report.get("meta", {})
    rows = []
    for f in findings:
        rows.append(
            f"<tr>"
            f"<td>{html.escape(str(f.get('path','')))}</td>"
            f"<td>{html.escape(str(f.get('method','')))}</td>"
            f"<td>{html.escape(str(f.get('issue','')))}</td>"
            f"<td>{html.escape(str(f.get('category','')))}</td>"
            f"<td>{html.escape(str(f.get('scenario','—')))}</td>"
            f"<td>{html.escape(str(f.get('status','')))}</td>"
            f"<td>{html.escape(str(f.get('expected','')))}</td>"
            f"<td>{html.escape(str(f.get('expected_outsider','')))}</td>"
            f"</tr>"
        )
    rows_html = "\n".join(rows)
    current_date = datetime.now().strftime('%d/%m/%Y')
    return f"""
<!DOCTYPE html>
<html lang="pt-br">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Relatório de Scan OpenAPI</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; }}
    h1 {{ margin-bottom: 8px; }}
    .summary {{ margin: 16px 0; }}
    .summary li {{ margin: 6px 0; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
    th {{ background: #f2f2f2; }}
    .badge {{ display:inline-block; padding:4px 8px; border-radius:12px; font-size:12px; color:#fff; }}
    .ok {{ background:#2ecc71; }}
    .warn {{ background:#e67e22; }}
    .danger {{ background:#e74c3c; }}
    .meta {{ color:#555; font-size: 14px; margin-bottom: 12px; }}
    .legend {{ font-size: 14px; color:#333; margin: 12px 0 18px; }}
  </style>
  </head>
  <body>
    <h1>Relatório de Scan OpenAPI</h1>
    <div class="meta">
      <div><strong>Spec:</strong> {html.escape(str(meta.get('swagger_url','')))}</div>
      <div><strong>Base URL:</strong> {html.escape(str(meta.get('base_url','')))}</div>
      <div><strong>Modo:</strong> {html.escape(str(meta.get('destructive_mode','safe')))}</div>
      <div><strong>Include paths:</strong> {html.escape(', '.join(meta.get('include_paths', [])) )}</div>
      <div><strong>Quando:</strong> {html.escape(current_date)}</div>
    </div>
    <div class="summary">
      <ul>
        <li><strong>Total de operações:</strong> {html.escape(str(s.get('total_operations',0)))}</li>
        <li><strong>Potenciais exposições:</strong> {html.escape(str(s.get('potential_exposures',0)))}</li>
        <li><strong>Acesso de fora possível?</strong> <span class="badge { 'danger' if outsider_can_access else 'ok' }">{ 'SIM' if outsider_can_access else 'NÃO' }</span> (leituras expostas: {html.escape(str(s.get('read_exposures',0)))})</li>
        <li><strong>Ações de fora possíveis?</strong> <span class="badge { 'danger' if outsider_can_perform_actions else 'ok' }">{ 'SIM' if outsider_can_perform_actions else 'NÃO' }</span> (operações de escrita expostas: {html.escape(str(s.get('write_exposures',0)))})</li>
        <li><strong>Deleções confirmadas (básico):</strong> {html.escape(str(s.get('verified_deletions',0)))}</li>
        <li><strong>Exposições sem auth:</strong> {html.escape(str(s.get('exposures_unauth',0)))}</li>
        <li><strong>Exposições com token inválido:</strong> {html.escape(str(s.get('exposures_invalid_token',0)))}</li>
        <li><strong>Status inválidos:</strong> {html.escape(str(s.get('invalid_status',0)))}</li>
        <li><strong>Incompatibilidades de schema:</strong> {html.escape(str(s.get('schema_mismatches',0)))}</li>
        <li><strong>Erros de requisição:</strong> {html.escape(str(s.get('request_errors',0)))}</li>
      </ul>
    </div>
    <div class="legend">
      <strong>Legenda:</strong>
      <ul>
        <li><strong>none</strong>: requisição enviada sem credencial (sem cabeçalho Authorization ou chave).</li>
        <li><strong>invalid_bearer</strong>: Authorization: Bearer com token inválido.</li>
        <li><strong>bearer_wrong_prefix</strong>: Authorization com prefixo errado (ex.: Token em vez de Bearer).</li>
        <li><strong>bearer_empty</strong>: Authorization: Bearer com token vazio.</li>
        <li><strong>invalid_api_key</strong>: chave de API inválida no header ou query, conforme definido no spec.</li>
        <li><strong>api_key_empty</strong>: chave de API vazia no header ou query.</li>
        <li><strong>invalid_status</strong>: código de status retornado não está documentado para a operação; a coluna "Esperado" lista os códigos documentados no spec (ex.: 200, 201, 4XX).</li>
        <li><strong>Esperado (outsider)</strong>: para operações com security, o esperado em cenários sem credencial ou com credencial inválida é <em>401/403</em>. Para operações públicas, <em>— (público)</em>.</li>
        <li><strong>Categorias</strong>: Autenticação/Autorização (exposição de acesso), Contrato (OpenAPI) (diferenças entre spec e servidor), Efeito colateral (comportamento após DELETE), Requisição (erros de chamada), Mock/Geração (limite de geração de dados).</li>
      </ul>
    </div>
    <h2>Achados</h2>
    <table>
      <thead>
        <tr>
          <th>Path</th>
          <th>Método</th>
          <th>Tipo</th>
          <th>Categoria</th>
          <th>Cenário</th>
          <th>Status</th>
          <th>Esperado</th>
          <th>Esperado (outsider)</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </body>
  </html>
"""
