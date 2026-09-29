import unittest

from sqlalchemy import create_engine

from sql_injection_lab.app_factory import format_sql_markup, format_sql_params_markup
from sql_injection_lab.repositories.secure import ProductRepository
from sql_injection_lab.repositories.vulnerable import ProductRepositoryVulnerable


class TestSqlPreview(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine("sqlite+pysqlite:///:memory:", future=True)

    def test_safe_preview_uses_parameters(self) -> None:
        repository = ProductRepository(engine=self.engine)
        sql, params = repository.preview_search_products("Road")

        self.assertNotIn("TOP 100", sql)
        self.assertIn(":search_pattern", sql)
        self.assertIn("s.product_status", sql)
        self.assertIn("AS product_status", sql)
        self.assertIn("s.product_status = N'Available'", sql)
        self.assertNotIn("NULLIF(LTRIM(RTRIM(s.product_status))", sql)
        self.assertEqual(params["search_text"], "Road")
        self.assertEqual(params["search_pattern"], "%Road%")

    def test_unsafe_preview_inlines_user_input(self) -> None:
        repository = ProductRepositoryVulnerable(engine=self.engine)
        sql, params = repository.preview_search_products_unsafe("Road")

        self.assertIn("LIKE '%Road%'", sql)
        self.assertIn("s.product_status", sql)
        self.assertIn("AS product_status", sql)
        self.assertIn("s.product_status = N'Available'", sql)
        self.assertNotIn("NULLIF(LTRIM(RTRIM(s.product_status))", sql)
        self.assertTrue(sql.startswith("SELECT\n        CAST(s.product_id AS INT)"))
        self.assertEqual(params["table"], "Labs.ProductSearchSnapshot")

    def test_sql_preview_removes_shared_query_indentation(self) -> None:
        formatted = str(
            format_sql_markup(
                """
                SELECT
                    s.product_id
                FROM Labs.ProductSearchSnapshot AS s;
                """
            )
        )

        self.assertTrue(formatted.startswith('<span class="sql-keyword">SELECT</span>\n    s.product_id'))
        self.assertIn('\n<span class="sql-keyword">FROM</span>', formatted)

    def test_parameter_values_use_a_separate_non_bold_style(self) -> None:
        formatted = str(format_sql_params_markup('{"search_text": "Road"}'))

        self.assertIn('class="sql-param-text">"search_text"</span>', formatted)
        self.assertIn('class="sql-param-value">', formatted)
