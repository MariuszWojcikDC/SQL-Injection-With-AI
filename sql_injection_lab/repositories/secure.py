from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from ..config import DATABASE_CONFIG
from .labs_support import LabsBootstrapper

LIST_PRODUCTS_QUERY = text(
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
    WHERE s.product_status = N'Available'
      AND (:search_text IS NULL OR s.name LIKE :search_pattern)
    ORDER BY s.name ASC;
    """
)

GET_PRODUCT_QUERY = text(
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
    WHERE s.product_id = :product_id
      AND s.product_status = N'Available';
    """
)


class ProductRepository:
    def __init__(self, engine: Engine | None = None):
        self.engine = engine or create_engine(
            DATABASE_CONFIG.to_sqlalchemy_url(),
            future=True,
            pool_pre_ping=True,
        )
        self._bootstrapper = LabsBootstrapper(self.engine)

    def ensure_lab_assets(self) -> None:
        self._bootstrapper.ensure_assets()

    def preview_search_products(self, search_text: str = "", culture_id: str = "en") -> tuple[str, dict[str, Any]]:
        _ = culture_id
        self.ensure_lab_assets()
        search_text = search_text.strip()
        params = {
            "search_text": search_text if search_text else None,
            "search_pattern": f"%{search_text}%" if search_text else None,
        }
        return LIST_PRODUCTS_QUERY.text.strip(), params

    def search_products(self, search_text: str = "", culture_id: str = "en") -> list[dict[str, Any]]:
        _ = culture_id
        self.ensure_lab_assets()
        search_text = search_text.strip()
        params = {
            "search_text": search_text if search_text else None,
            "search_pattern": f"%{search_text}%" if search_text else None,
        }

        with self.engine.connect() as connection:
            rows = connection.execute(LIST_PRODUCTS_QUERY, params).fetchall()

        return [dict(row._mapping) for row in rows]

    def get_product(self, product_id: int, culture_id: str = "en") -> dict[str, Any] | None:
        _ = culture_id
        self.ensure_lab_assets()

        with self.engine.connect() as connection:
            row = connection.execute(GET_PRODUCT_QUERY, {"product_id": product_id}).fetchone()
        if row is None:
            return None

        return dict(row._mapping)
