# Frontend (React com Vite)

Esta é a interface de usuário para a aplicação de validação de APIs, construída com React e Vite.

## Funcionalidades

-   Formulário para inserir URL da API, método HTTP, cabeçalhos, corpo, status esperado e regras de validação.
-   Adição e remoção dinâmica de regras de validação.
-   Exibição dos resultados da validação e da resposta da API.

## Como Executar Localmente

1.  Navegue até o diretório `frontend`:
    ```bash
    cd api-validation-project/frontend
    ```
2.  Instale as dependências Node.js:
    ```bash
    npm install
    ```
3.  Inicie o servidor de desenvolvimento do Vite:
    ```bash
    npm run dev
    ```
    O aplicativo estará disponível em `http://localhost:3000`.

    **Nota**: O frontend está configurado para fazer proxy das requisições `/api` para o backend rodando em `http://localhost:8000`.

## Estrutura do Projeto

-   `src/App.jsx`: Componente principal da aplicação, contendo o formulário e a lógica de validação.
-   `src/index.css` e `src/App.css`: Estilos globais e específicos do componente.
-   `vite.config.js`: Configuração do Vite, incluindo o proxy para o backend.

