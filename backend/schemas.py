from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, AnyHttpUrl

class ValidationRule(BaseModel):
    field: str
    operator: str
    value: Any | None = None

class APIValidationRequest(BaseModel):
    api_url: AnyHttpUrl = Field(..., example="https://jsonplaceholder.typicode.com/posts/1")
    method: str = Field("GET", example="GET")
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Dict[str, Any] = Field(default_factory=dict)
    expected_status: int = Field(200, example=200)
    validation_rules: List[ValidationRule] = Field(default_factory=list)

    # Extra validations
    swagger_url: Optional[AnyHttpUrl] = Field(default=None, description="URL da especificação OpenAPI/Swagger (json/yaml)")
    product_name: Optional[str] = Field(default=None, description="Nome do produto para checagem de existência")
    api_key: Optional[str] = Field(default=None, description="Chave de API para checagem e associação com produto")
    require_role: Optional[str] = Field(default=None, description="Role necessária para acessar a validação")
    schema_ref: Optional[str] = Field(default=None, description="Nome do schema em components.schemas para validar a resposta")
