from pydantic import BaseModel
from typing import List
import os

class Settings(BaseModel):
    jwt_secret: str = os.getenv("JWT_SECRET", "dev-secret")
    jwt_algorithms: List[str] = [alg.strip() for alg in os.getenv("JWT_ALGORITHMS", "HS256").split(",")]
    allowed_server_hosts: List[str] = [
        h.strip()
        for h in os.getenv(
            "ALLOWED_SERVER_HOSTS",
            "jsonplaceholder.typicode.com,localhost,127.0.0.1,dados.gov.br,www.dados.gov.br,petstore3.swagger.io,petstore.swagger.io",
        ).split(",")
    ]
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./data/data.db")

settings = Settings()
