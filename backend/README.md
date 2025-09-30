# Backend (FastAPI)

Este é o serviço de backend para a aplicação de validação de APIs, construído com FastAPI.

## Funcionalidades

- **Health Check**: Endpoint `/health` para verificar o status do serviço.
- **Validação de API**: Endpoint `/validate-api` que aceita uma URL de API, método HTTP, cabeçalhos, corpo, status esperado e um conjunto de regras de validação. Ele faz uma requisição à API externa e valida a resposta com base nas regras fornecidas.

## Como Executar Localmente

1.  Navegue até o diretório `backend`:
    ```bash
    cd api-validation-project/backend
    ```
2.  Instale as dependências Python:
    ```bash
    pip install -r requirements.txt
    ```
3.  Inicie o servidor FastAPI:
    ```bash
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload
    ```
    O servidor estará disponível em `http://localhost:8000`.

## Testes

Para executar os testes do backend, use o seguinte comando no diretório `backend`:

```bash
pytest
```

## Endpoints

-   `GET /health`: Retorna `{"status": "healthy"}`.
-   `POST /validate-api`: Valida uma API externa.
    -   **Request Body**: `APIValidationRequest` (veja `main.py` para o esquema Pydantic).
    -   **Response**: `{"message": "API validated successfully", "validation_results": [...], "api_response": {...}}` ou erro com detalhes.

