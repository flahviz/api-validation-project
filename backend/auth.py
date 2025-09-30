import time
from typing import List, Optional
import jwt
from fastapi import HTTPException, Header
from config import settings


def decode_jwt(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=settings.jwt_algorithms)
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")


def require_token_and_roles(roles: Optional[List[str]] = None):
    async def dependency(authorization: Optional[str] = Header(default=None)):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Authorization header ausente ou inválido")
        token = authorization.split(" ", 1)[1]
        payload = decode_jwt(token)
        # Minimal role enforcement
        user_roles = payload.get("roles", [])
        if roles:
            if not isinstance(user_roles, list):
                user_roles = [user_roles]
            if not any(role in user_roles for role in roles):
                raise HTTPException(status_code=403, detail="Usuário não autorizado para este recurso")
        return payload
    return dependency
