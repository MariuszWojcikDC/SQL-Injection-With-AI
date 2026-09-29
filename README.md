# Adventure Works Shop (Python + Flask)

A single Python web app frontend for Adventure Works on SQL Server with two runtime modes:
- secure mode (resistant to SQL Injection),
- vulnerable mode (controlled SQL Injection lab for demos).

## Features

- browse a product list (name, price, description),
- search products by name,
- view product details,
- run a controlled SQL Injection demo package (read bypass, controlled UNION leak, controlled INSERT impact, time-based blind delay, error-based exception leak),
- reset demo data from the UI for repeatable workshops,
- keep database connection settings in `sql_injection_lab/config.py`,
- switch between secure and vulnerable mode directly from the header menu,
- chatbot powered by Azure OpenAI Responses API with Labs schema access and semantic product search,
- remote prompt-injection demo using an HTML source with hidden comment instructions.

## Requirements

- Python 3.11+,
- SQL Server 2025 running locally,
- Adventure Works database (for example `AdventureWorks2022`),
- installed SQL Server ODBC driver (for example `ODBC Driver 18 for SQL Server`).

## Run

1. Create and activate a virtual environment:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Configure database connection in `sql_injection_lab/config.py`:

- `server` (for example `localhost` or `localhost\SQLEXPRESS`),
- `database` (your Adventure Works database name),
- optional `driver`, `encrypt`, `trust_server_certificate`,
- connection uses Windows Authentication (`Trusted_Connection=yes`) based on your current Windows account.

4. Configure Azure OpenAI chatbot settings in a local `.env` file:

```powershell
Copy-Item .env.example .env
```

Then fill in `.env` locally:

```env
AZURE_OPENAI_ENDPOINT=
AZURE_OPENAI_API_KEY=
AZURE_OPENAI_DEPLOYMENT=gpt-5-mini
AZURE_OPENAI_API_VERSION=2024-12-01-preview
AZURE_OPENAI_TIMEOUT_SECONDS=45
FLASK_SECRET_KEY=
```

`FLASK_SECRET_KEY` is used by Flask to sign session cookies. Generate a local value with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Do not commit `.env`. It is ignored by git.

Optional: enable a local pre-commit secret scan:

```powershell
pip install pre-commit detect-secrets
pre-commit install
detect-secrets scan > .secrets.baseline
```

5. Start the app:

```powershell
python app.py
```

6. Open:

`http://127.0.0.1:5000`

7. Use the top menu switch to choose:

- `Secure` (default),
- `Vulnerable` (training/simulation mode).

## Controlled lab package

On application startup, the app recreates the lab tables from scratch and seeds them for safe training scope:

- `Labs.ProductSearchSnapshot` (100 seeded `Available` products matching the list view shape from `LIST_PRODUCTS_QUERY`),
- product IDs in `Labs.ProductSearchSnapshot` are normalized to six-digit numbers,
- `Labs.ProductSearchSnapshot.product_status` (one of `Available`, `Unavailable`, `Pending release`),
- 25 additional lab products with `Unavailable` or `Pending release` status,
- `Labs.ProductSearchSnapshot.created_at` (timestamp showing when each snapshot row was created),
- `Labs.EmployeeSnapshot` (employee demo table for UNION payload column shape),
- `Labs.AttackLog` (captured injected-write events),
- reset workflow from UI button (`POST /lab/reset`) also recreates and reseeds the lab tables.

Demo flow:

1. Start in vulnerable mode and observe default empty search (preview subset).
2. Enter a bypass payload pattern to simulate filter bypass and expanded result set.
3. Enter an INSERT-style payload targeting `INTO [Labs].[ProductSearchSnapshot]` to show controlled injected rows appended to results.
4. Enter a UNION-style payload targeting `FROM [Labs].[EmployeeSnapshot]` to show employee demo rows merged into search results.
5. Enter a time-based payload pattern (for example `IF(SUBSTRING((SELECT DB_NAME()),1,1)='A') WAITFOR DELAY '00:00:01.000'`) to run a single blind probe and compare response times (for example `A` vs `B`).
6. Enter an error-based payload pattern (for example `SELECT CAST(N'SQLI_DEMO_ERROR' AS INT)`) to trigger a DB exception and display full error details in vulnerable mode.
7. Click **Reset lab data** to restore deterministic state.

## Prompt Injection demo (HTML remote content)

The chatbot includes a simulated external HTML source:

- `sql_injection_lab/demo_assets/remote_shop_notice.html`
- `http://127.0.0.1:5000/demo-assets/remote_shop_notice.html` (when the application runs locally on port 5000)

This file contains a hidden HTML comment with an injected instruction block.

Demo flow:

1. Switch app mode to `Vulnerable`.
2. Open **AI Chat** and ask: `Summarize this HTML page: http://127.0.0.1:5000/demo-assets/remote_shop_notice.html`
3. The model passes the supplied link to `fetch_remote_html`, which loads the corresponding HTML source.
   In vulnerable mode, the model can receive the HTML source, including hidden instructions,
   and may execute `update_product_prices`.
4. Switch to `Secure` and repeat the same message.
5. In secure mode, hidden HTML comments are removed before tool output is returned to the model.

## Project structure

- `app.py` - main app entrypoint,
- `app_vulnerable.py` - vulnerable-mode demo entrypoint,
- `sql_injection_lab/app_factory.py` - Flask routes/UI behavior and runtime mode switching,
- `sql_injection_lab/config.py` - SQL Server connection settings,
- `sql_injection_lab/repositories/secure.py` - secure SQL queries and data access,
- `sql_injection_lab/repositories/vulnerable.py` - controlled vulnerable training behaviors + lab data setup/reset/logging,
- `sql_injection_lab/services/chatbot.py` - Azure OpenAI chatbot orchestration, Labs DB tool, semantic product search,
- `sql_injection_lab/demo_assets/remote_shop_notice.html` - simulated remote HTML content with hidden prompt-injection payload,
- `sql_injection_lab/templates/` - HTML templates,
- `sql_injection_lab/static/styles.css` - UI styles,
- `requirements.txt` - Python dependencies.

## Security note

- Secure mode uses parameterized SQL queries (`SQLAlchemy`) and is the production-safe baseline.
- Vulnerable mode demonstrates SQL Injection effects only in a controlled lab scope (`Labs.ProductSearchSnapshot`, `Labs.EmployeeSnapshot`, `Labs.AttackLog`).
- Secure mode returns generic error messages to users and keeps error details in server logs.
- Vulnerable mode intentionally exposes detailed SQL/stack errors in the UI to demonstrate poor security practices (use only in isolated demos).



