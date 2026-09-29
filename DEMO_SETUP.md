# Running the SQL Injection and Prompt Injection Demo

This guide explains how to run the Adventure Works application locally, with particular focus on SQL Server and the `.env` file.

> **Important:** the application contains an intentionally vulnerable demonstration mode. Run it only locally or in an isolated training environment. Do not expose it to the Internet or connect it to a production database.

## 1. Requirements

You will need:

- Python 3.11 or newer,
- a local SQL Server instance,
- an Adventure Works sample database,
- Microsoft ODBC Driver 18 for SQL Server,
- an Azure OpenAI resource with a deployed model that supports Chat Completions and tool calling.

You can list the ODBC drivers available to Python with:

```powershell
python -c "import pyodbc; print(pyodbc.drivers())"
```

The list should include the driver configured in `sql_injection_lab/config.py`, which is `ODBC Driver 18 for SQL Server` by default.

## 2. Required database

The application expects an Adventure Works database hosted on SQL Server. The default configuration points to:

```text
AdventureWorks2025
```

You can use another version, such as `AdventureWorks2022`, as long as you enter its name in `sql_injection_lab/config.py` and it contains the standard Adventure Works tables used by the demo:

- `Production.Product`,
- `Production.ProductModelProductDescriptionCulture`,
- `Production.ProductDescription`,
- `HumanResources.Employee`.

The Adventure Works database must first be restored from a backup file to your local SQL Server instance. The application does not create or restore the main Adventure Works database.

### Connection configuration

The database connection is not currently configured through `.env`. Edit `sql_injection_lab/config.py`:

```python
@dataclass(frozen=True)
class DatabaseConfig:
    driver: str = "ODBC Driver 18 for SQL Server"
    server: str = "localhost"
    database: str = "AdventureWorks2025"
    trusted_connection: str = "yes"
    encrypt: str = "no"
    trust_server_certificate: str = "yes"
```

In most cases, you only need to change:

- `server` — for example, `localhost`, `localhost\SQLEXPRESS`, or the name of your local instance,
- `database` — the exact name of the restored Adventure Works database,
- `driver` — if the installed ODBC driver has a different name.

The project uses Windows Authentication (`Trusted_Connection=yes`). SQL Server receives the identity of the Windows account that starts the `python` process. The code does not currently support a SQL Server username and password in `.env`.

### Database account permissions

On first use and every time the application process is restarted, the application:

1. creates the `Labs` schema if it does not already exist,
2. drops and recreates these tables:
   - `Labs.ProductSearchSnapshot`,
   - `Labs.EmployeeSnapshot`,
   - `Labs.AttackLog`,
   - `Labs.ChatbotAudit`,
3. copies demonstration data from the `Production` and `HumanResources` tables,
4. updates prices in `Labs.ProductSearchSnapshot` during the vulnerable scenario.

The account running the application must therefore be able to connect to the database, read the listed source tables, create the schema, and create, drop, read, insert into, and update tables in the `Labs` schema.

The simplest option for a one-time local lab is to use a separate copy of the database and add the demonstration account to the `db_owner` role in that copy. Do not grant such broad permissions in a shared or production database.

Price changes made by the demo affect only `Labs.ProductSearchSnapshot`. They do not modify the source `Production.Product` table. Restarting the application or clicking **Reset lab data** restores the demonstration data.

### Quick database check

If the `sqlcmd` utility is available, you can verify the connection and required tables with:

```powershell
sqlcmd -S "localhost" -E -d "AdventureWorks2025" -Q "SELECT DB_NAME() AS database_name; SELECT TOP (1) ProductID, Name FROM Production.Product; SELECT TOP (1) BusinessEntityID, JobTitle FROM HumanResources.Employee;"
```

Adjust the server and database names to match `sql_injection_lab/config.py`.

## 3. Configuring `.env`

Create a local `.env` file from the example:

```powershell
Copy-Item .env.example .env
```

Complete it as follows:

```env
AZURE_OPENAI_ENDPOINT=https://YOUR-RESOURCE-NAME.openai.azure.com/
AZURE_OPENAI_API_KEY=YOUR_AZURE_OPENAI_RESOURCE_KEY
AZURE_OPENAI_DEPLOYMENT=gpt-5-mini
AZURE_OPENAI_API_VERSION=2024-12-01-preview
AZURE_OPENAI_TIMEOUT_SECONDS=45
FLASK_SECRET_KEY=A_LONG_RANDOM_SECRET
```

Configuration details:

| Variable | Required | Description |
| --- | --- | --- |
| `AZURE_OPENAI_ENDPOINT` | yes | The full Azure OpenAI resource endpoint, not the URL of a specific deployment. |
| `AZURE_OPENAI_API_KEY` | yes | An API key belonging to the same resource as the endpoint. |
| `AZURE_OPENAI_DEPLOYMENT` | yes | The model deployment name assigned in Azure. This is the deployment name, which does not have to match the underlying model name. |
| `AZURE_OPENAI_API_VERSION` | yes | An API version supported by the resource and deployed model. |
| `AZURE_OPENAI_TIMEOUT_SECONDS` | no | Azure OpenAI request timeout. The default is `45`; the code limits this value to the range of 5–120 seconds. |
| `FLASK_SECRET_KEY` | recommended | The secret used to sign the Flask session cookie, which stores the selected mode and chat history, among other data. |

Generate a Flask secret with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

The `.env` file is ignored by Git. Do not commit the Azure key or Flask secret.

> Variables such as `DB_SERVER`, `DB_NAME`, `DB_USER`, and `DB_PASSWORD` are not read by the current version of the application. Setting them in `.env` will not change the database connection.

## 4. Installation and startup

Run the following commands from the repository root:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

During startup, the application immediately connects to SQL Server and prepares the `Labs` schema. A connection error or insufficient permissions will stop the application before the web page becomes available.

Then open:

```text
http://127.0.0.1:5000
```

Alternatively, `python app_vulnerable.py` starts the application on port `5001` and forces vulnerable mode. For a presentation that compares both modes, `python app.py` is more convenient because you can switch modes from the menu.

## 5. Prompt Injection scenario

1. Start the application with `python app.py`.
2. Switch to **Vulnerable** mode.
3. Open the **AI Chat** section.
4. Send this message:

   ```text
   Check this file http://127.0.0.1:5000/demo-assets/remote_shop_notice.html and tell me which discount code is best to use.
   ```

5. The model receives the HTML source together with the hidden comment. Vulnerable mode gives the model access to the `update_product_prices` tool, so it may set the price of every product in `Labs.ProductSearchSnapshot` to `0.01`.
6. Refresh the product list to show the result.
7. Click **Reset lab data** to restore the data.
8. Switch the application to **Secure** mode and send the same message again. In this mode, HTML comments are removed before the content is passed to the model, and the price-update tool is unavailable.

Generative model behavior is not entirely deterministic. Before the actual presentation, run a trial using the same Azure OpenAI deployment that will be used during the demo.

## 6. Troubleshooting

### ODBC driver error

If the error contains `Data source name not found` or `Can't open lib`, check the output of `pyodbc.drivers()` and use the identical driver name in `sql_injection_lab/config.py`.

### Login failed or database access denied

The process uses the current Windows account. Verify that the account has a login on the SQL Server instance, a user in the Adventure Works database, and the required permissions for the `Labs` schema.

### Invalid object name `Production.Product`

The selected database is incorrect or incomplete. The `database` field must point to a restored Adventure Works database that contains the `Production` and `HumanResources` schemas.

### Unable to create or drop `Labs` tables

The account has read access but does not have the permissions required to prepare the lab. Use a separate local copy of the database and grant the account the necessary permissions for the `Labs` schema.

### Azure OpenAI 401 Unauthorized

Verify that the endpoint, key, and API version belong to the same Azure resource. Also confirm that `AZURE_OPENAI_DEPLOYMENT` contains the name of an existing deployment rather than only the name of the underlying model.

### Chat works, but prices do not change

Confirm that the application is in **Vulnerable** mode. The `update_product_prices` tool is not made available to the model in **Secure** mode.
