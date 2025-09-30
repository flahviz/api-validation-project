from urllib.parse import urlparse
from fastapi import HTTPException
from sqlalchemy.orm import Session
from config import settings
from models import Product, ApiKey


def validate_server_url_allowed(api_url: str):
    host = urlparse(api_url).hostname
    if not host:
        raise HTTPException(status_code=400, detail="URL do servidor inválida")
    host_l = host.lower()
    allowed = [h.lower() for h in settings.allowed_server_hosts]
    if "*" in allowed:
        return
    def match(h: str) -> bool:
        return host_l == h or host_l.endswith("." + h)
    if not any(match(h) for h in allowed):
        raise HTTPException(status_code=403, detail=f"Servidor '{host}' não está na lista permitida")


def ensure_product_exists(db: Session, product_name: str):
    product = db.query(Product).filter(Product.name == product_name).first()
    if not product:
        raise HTTPException(status_code=404, detail=f"Produto '{product_name}' não encontrado")
    return product


def validate_api_key(db: Session, api_key: str):
    key = db.query(ApiKey).filter(ApiKey.key == api_key).first()
    if not key:
        raise HTTPException(status_code=401, detail="Chave de API inválida")
    return key


def validate_api_key_belongs_to_product(db: Session, api_key: str, product_name: str):
    key = validate_api_key(db, api_key)
    product = ensure_product_exists(db, product_name)
    if key.product_id != product.id:
        raise HTTPException(status_code=403, detail="Chave de API não pertence ao produto informado")
    return True
