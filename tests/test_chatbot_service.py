import unittest
from decimal import Decimal
from typing import Any

from sql_injection_lab.services.chatbot import ChatbotService, LabsQueryGuard, extract_output_text


REMOTE_HTML_URL = "http://127.0.0.1:5000/demo-assets/remote_shop_notice.html"


class TestLabsQueryGuard(unittest.TestCase):
    def test_allows_read_only_select_in_labs(self) -> None:
        query = "SELECT TOP 5 * FROM Labs.AttackLog ORDER BY log_id DESC"
        self.assertEqual(LabsQueryGuard.validate(query), query)

    def test_rejects_non_labs_schema(self) -> None:
        with self.assertRaisesRegex(ValueError, "schema Labs"):
            LabsQueryGuard.validate("SELECT TOP 1 * FROM Production.Product")

    def test_rejects_write_query(self) -> None:
        with self.assertRaisesRegex(ValueError, "SELECT/CTE"):
            LabsQueryGuard.validate(
                "INSERT INTO Labs.AttackLog(action_name, injected_text, note) VALUES ('a','b','c')"
            )

    def test_rejects_semicolon(self) -> None:
        with self.assertRaisesRegex(ValueError, "Semicolon"):
            LabsQueryGuard.validate("SELECT * FROM Labs.AttackLog;")


class TestExtractOutputText(unittest.TestCase):
    def test_prefers_output_text_field(self) -> None:
        payload = {"output_text": "  done  "}
        self.assertEqual(extract_output_text(payload), "done")

    def test_reads_output_message_chunks(self) -> None:
        payload = {
            "output": [
                {
                    "type": "message",
                    "content": [
                        {"type": "output_text", "text": "First line"},
                        {"type": "output_text", "text": "Second line"},
                    ],
                }
            ]
        }
        self.assertEqual(extract_output_text(payload), "First line\nSecond line")


class DummyResponsesClient:
    def create_chat_completion(self, *_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("This test should not call Azure OpenAI.")


class StubRepository:
    def __init__(self) -> None:
        self.last_update: dict[str, Any] | None = None

    def update_product_prices(self, new_price: float, product_name: str | None = None) -> dict[str, Any]:
        self.last_update = {"new_price": new_price, "product_name": product_name}
        return {
            "new_price": new_price,
            "scope": "all" if not product_name else "filtered_by_name",
            "product_name": product_name,
            "affected_rows": 5,
            "updated_products_preview": [],
        }


class TestChatbotToolAvailability(unittest.TestCase):
    def test_secure_tools_do_not_expose_mutation_tool(self) -> None:
        tool_names = [tool["function"]["name"] for tool in ChatbotService.tools(allow_mutations=False)]
        self.assertNotIn("update_product_prices", tool_names)
        self.assertIn("fetch_remote_html", tool_names)

    def test_vulnerable_tools_expose_mutation_tool(self) -> None:
        tool_names = [tool["function"]["name"] for tool in ChatbotService.tools(allow_mutations=True)]
        self.assertIn("update_product_prices", tool_names)
        self.assertIn("fetch_remote_html", tool_names)

    def test_update_tool_dispatch_only_in_mutation_mode(self) -> None:
        repository = StubRepository()
        service = ChatbotService(repository=repository, responses_client=DummyResponsesClient())

        denied = service._dispatch_tool(
            "update_product_prices",
            {"new_price": 1},
            allow_mutations=False,
        )
        self.assertFalse(denied["ok"])

        accepted = service._dispatch_tool(
            "update_product_prices",
            {"new_price": 1},
            allow_mutations=True,
        )
        self.assertTrue(accepted["ok"])
        self.assertIsNotNone(repository.last_update)
        if repository.last_update is None:
            self.fail("Expected update call to be captured.")
        self.assertEqual(repository.last_update["new_price"], 1.0)

    def test_remote_html_tool_secure_mode_masks_hidden_comments(self) -> None:
        service = ChatbotService(repository=StubRepository(), responses_client=DummyResponsesClient())
        result = service._dispatch_tool(
            "fetch_remote_html",
            {"url": REMOTE_HTML_URL},
            allow_mutations=False,
        )
        self.assertTrue(result["ok"])
        self.assertFalse(result["includes_hidden_comments"])
        self.assertIn("hidden_comment_count", result)
        self.assertEqual(result["url"], REMOTE_HTML_URL)
        self.assertNotIn("REMOTE_PROMPT_INJECTION_DEMO", result["content"])

    def test_remote_html_tool_vulnerable_mode_exposes_hidden_comments(self) -> None:
        service = ChatbotService(repository=StubRepository(), responses_client=DummyResponsesClient())
        result = service._dispatch_tool(
            "fetch_remote_html",
            {"url": REMOTE_HTML_URL, "include_hidden_comments": True},
            allow_mutations=True,
        )
        self.assertTrue(result["ok"])
        self.assertTrue(result["includes_hidden_comments"])
        self.assertIn("REMOTE_PROMPT_INJECTION_DEMO", result["content"])

    def test_remote_html_tool_rejects_an_unapproved_url(self) -> None:
        service = ChatbotService(repository=StubRepository(), responses_client=DummyResponsesClient())
        result = service._dispatch_tool(
            "fetch_remote_html",
            {"url": "https://example.com/notice.html"},
            allow_mutations=False,
        )
        self.assertFalse(result["ok"])
        self.assertIn("simulated remote HTML URL", result["error"])

    def test_chat_serializes_decimal_tool_result(self) -> None:
        class DecimalRepository:
            def update_product_prices(self, new_price: float, product_name: str | None = None) -> dict[str, Any]:
                return {
                    "new_price": new_price,
                    "scope": "all",
                    "product_name": product_name,
                    "affected_rows": 1,
                    "updated_products_preview": [
                        {"product_id": 1, "name": "Road-150", "list_price": Decimal("1.00")}
                    ],
                }

            def log_chat_exchange(self, _user_message: str, _assistant_message: str) -> None:
                return None

            def run_labs_query(self, _sql_query: str, limit: int = 20) -> dict[str, Any]:
                return {"limit": limit, "row_count": 0, "rows": [], "truncated": False, "query": ""}

            def list_product_candidates(self, _limit: int = 80) -> list[dict[str, Any]]:
                return []

        class TwoStepResponseClient:
            def __init__(self) -> None:
                self._step = 0

            def create_chat_completion(self, *_args: Any, **_kwargs: Any) -> Any:
                self._step += 1
                if self._step == 1:
                    return {
                        "choices": [
                            {
                                "message": {
                                    "content": None,
                                    "tool_calls": [
                                        {
                                            "id": "call_1",
                                            "type": "function",
                                            "function": {
                                                "name": "update_product_prices",
                                                "arguments": '{"new_price": 1}',
                                            },
                                        }
                                    ],
                                }
                            }
                        ]
                    }
                return {"choices": [{"message": {"content": "Prices updated."}}]}

        service = ChatbotService(
            repository=DecimalRepository(),
            responses_client=TwoStepResponseClient(),
        )
        result = service.chat(
            user_message="Set all prices to 1",
            history=[],
            allow_mutations=True,
        )
        self.assertEqual(result["answer"], "Prices updated.")
        self.assertEqual(result["used_tools"], ["update_product_prices"])


if __name__ == "__main__":
    unittest.main()



