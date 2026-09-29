import json
import os
import re
import traceback
from pathlib import Path
from textwrap import dedent
from time import perf_counter
from typing import Any

from flask import Flask, abort, redirect, render_template, request, send_from_directory, session, url_for
from markupsafe import Markup, escape
from sqlalchemy.exc import SQLAlchemyError

from .services import ChatbotService

SQL_KEYWORDS = (
    "select",
    "from",
    "where",
    "and",
    "or",
    "like",
    "order",
    "by",
    "as",
    "cast",
    "top",
    "null",
    "insert",
    "into",
    "values",
    "union",
    "all",
    "if",
    "waitfor",
    "delay",
    "substring",
    "db_name",
    "getdate",
    "int",
    "date",
    "datetime2",
    "decimal",
)
SQL_KEYWORD_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(keyword) for keyword in SQL_KEYWORDS) + r")\b",
    re.IGNORECASE,
)
SQL_PARAM_CLASS_MAP = {
    "search_pattern": "sql-param-pattern",
    "search_text": "sql-param-text",
}
SQL_PARAM_PLACEHOLDER_PATTERN = re.compile(
    r":(" + "|".join(re.escape(param_name) for param_name in SQL_PARAM_CLASS_MAP) + r")\b"
)


def style_sql_code_segment(sql_fragment: str) -> str:
    styled = escape(sql_fragment)
    styled = re.sub(r"(\[[^\]]+\])", r'<span class="sql-identifier">\1</span>', str(styled))
    styled = SQL_KEYWORD_PATTERN.sub(
        lambda match: f'<span class="sql-keyword">{match.group(0).upper()}</span>',
        styled,
    )
    styled = SQL_PARAM_PLACEHOLDER_PATTERN.sub(
        lambda match: (
            f'<span class="{SQL_PARAM_CLASS_MAP.get(match.group(1), "sql-param-generic")}">'
            f":{match.group(1)}</span>"
        ),
        styled,
    )
    return styled


def format_sql_params_markup(params_text: str) -> Markup:
    if not params_text:
        return Markup("")

    try:
        parsed = json.loads(params_text)
    except json.JSONDecodeError:
        return Markup(escape(params_text))

    if not isinstance(parsed, dict):
        return Markup(escape(params_text))

    lines = ["{"]
    items = list(parsed.items())
    for index, (key, value) in enumerate(items):
        css_class = SQL_PARAM_CLASS_MAP.get(str(key), "sql-param-generic")
        serialized_value = json.dumps(value, ensure_ascii=False, default=str)
        trailing_comma = "," if index < len(items) - 1 else ""
        lines.append(
            "  "
            f'<span class="{css_class}">"{escape(str(key))}"</span>: '
            f'<span class="sql-param-value">{escape(serialized_value)}</span>{trailing_comma}'
        )
    lines.append("}")
    return Markup("\n".join(lines))


def format_sql_markup(sql_text: str, injected_text: str | None = None) -> Markup:
    if not sql_text:
        return Markup("")

    # Queries are declared in indented triple-quoted strings. Remove only that
    # shared source indentation so SELECT clauses keep their intended layout.
    sql_text = dedent(sql_text).strip()
    normalized_injected_text = (injected_text or "").strip()
    injection_start = sql_text.find(normalized_injected_text) if normalized_injected_text else -1
    injection_end = injection_start + len(normalized_injected_text) if injection_start >= 0 else -1
    comment_start = -1
    if injection_start >= 0:
        comment_start = sql_text.find("--", injection_start)

    if comment_start >= 0:
        before_comment = sql_text[:comment_start]
        comment_fragment = sql_text[comment_start:]

        html = ""
        if injection_start >= 0:
            before_injection = before_comment[:injection_start]
            injected_code = before_comment[injection_start:]
            html += style_sql_code_segment(before_injection)
            if injected_code:
                html += f'<span class="sql-injection">{style_sql_code_segment(injected_code)}</span>'
        else:
            html += style_sql_code_segment(before_comment)

        html += f'<span class="sql-comment">{escape(comment_fragment)}</span>'
        return Markup(html)

    if injection_start >= 0:
        before_injection = sql_text[:injection_start]
        injected_code = sql_text[injection_start:injection_end]
        after_injection = sql_text[injection_end:]
        return Markup(
            f"{style_sql_code_segment(before_injection)}"
            f"<span class=\"sql-injection\">{style_sql_code_segment(injected_code)}</span>"
            f"{style_sql_code_segment(after_injection)}"
        )

    return Markup(style_sql_code_segment(sql_text))


def create_app(secure_repository, vulnerable_repository) -> Flask:
    app = Flask(__name__)
    app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")
    secure_mode = "SECURE"
    vulnerable_mode = "VULNERABLE"
    secure_chatbot_service = ChatbotService(engine=secure_repository.engine)
    vulnerable_chatbot_service = ChatbotService(engine=vulnerable_repository.engine)

    @app.get("/demo-assets/remote_shop_notice.html")
    def remote_shop_notice() -> Any:
        demo_assets_directory = Path(__file__).resolve().parent / "demo_assets"
        return send_from_directory(demo_assets_directory, "remote_shop_notice.html")

    def trim_chat_history(history: list[dict[str, Any]], max_messages: int = 12) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for entry in history:
            if not isinstance(entry, dict):
                continue
            role = str(entry.get("role", "")).strip().lower()
            content = str(entry.get("content", "")).strip()
            if role not in {"user", "assistant"}:
                continue
            if not content:
                continue

            normalized_entry: dict[str, Any] = {"role": role, "content": content}
            if role == "assistant":
                response_time_ms = entry.get("response_time_ms")
                if isinstance(response_time_ms, (int, float)):
                    normalized_entry["response_time_ms"] = round(float(response_time_ms), 2)

            normalized.append(normalized_entry)
        return normalized[-max_messages:]

    def format_exception_details(exc: BaseException) -> str:
        return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))

    def format_params(params: dict[str, Any]) -> str:
        return json.dumps(params, indent=2, ensure_ascii=False, default=str, sort_keys=True)

    def sqli_simulation_message(search_text: str) -> str | None:
        trimmed = search_text.strip()
        if not trimmed:
            return None

        lowered = trimmed.lower()
        suspicious_markers = [
            "'" if "'" in trimmed else None,
            '"' if '"' in trimmed else None,
            "--" if "--" in trimmed else None,
            "/*" if "/*" in trimmed else None,
            "*/" if "*/" in trimmed else None,
            ";" if ";" in trimmed else None,
            "union" if "union" in lowered else None,
            "select" if "select" in lowered else None,
            " or " if " or " in lowered else None,
            " and " if " and " in lowered else None,
        ]
        suspicious_markers = [marker for marker in suspicious_markers if marker]
        if not suspicious_markers:
            return None

        marker_list = ", ".join(suspicious_markers[:6])
        suffix = "..." if len(suspicious_markers) > 6 else ""
        return (
            "Warning: your input contains characters/keywords commonly used in SQL Injection "
            f"({marker_list}{suffix}). In vulnerable mode this can change SQL logic or expose data "
            "outside the intended table."
        )

    def get_app_mode() -> str:
        mode = str(session.get("app_mode", secure_mode)).upper()
        if mode not in {secure_mode, vulnerable_mode}:
            mode = secure_mode
        return mode

    def is_vulnerable_mode() -> bool:
        return get_app_mode() == vulnerable_mode

    def get_repository():
        return vulnerable_repository if is_vulnerable_mode() else secure_repository

    def get_chatbot_service() -> ChatbotService:
        return vulnerable_chatbot_service if is_vulnerable_mode() else secure_chatbot_service

    def map_database_error(exc: SQLAlchemyError) -> tuple[str, str | None]:
        app_mode = get_app_mode()
        app.logger.exception("Database error in %s mode", app_mode)
        if is_vulnerable_mode():
            return (
                f"Database error (intentionally exposed): {exc}",
                format_exception_details(exc),
            )
        return (
            "Could not load data from the database. "
            "Check your connection settings in db_config.py.",
            None,
        )

    @app.context_processor
    def inject_mode():
        app_mode = get_app_mode()
        return {"app_mode": app_mode, "is_vulnerable": is_vulnerable_mode()}

    @app.template_filter("format_sql")
    def format_sql_filter(sql_text: str, injected_text: str = "", highlight_injection: bool = False) -> Markup:
        return format_sql_markup(sql_text, injected_text if highlight_injection else None)

    @app.template_filter("format_sql_params")
    def format_sql_params_filter(params_text: str) -> Markup:
        return format_sql_params_markup(params_text)

    @app.post("/mode")
    def set_mode():
        requested_mode = str(request.form.get("mode", "")).upper()
        if requested_mode not in {secure_mode, vulnerable_mode}:
            requested_mode = secure_mode

        session["app_mode"] = requested_mode

        next_url = request.form.get("next", "").strip()
        if not next_url.startswith("/"):
            next_url = url_for("index")

        return redirect(next_url)

    @app.post("/chat")
    def chat():
        user_message = request.form.get("message", "").strip()
        next_url = request.form.get("next", "").strip()
        if not next_url.startswith("/"):
            next_url = url_for("index")

        if not user_message:
            session["chat_error"] = "Chat message cannot be empty."
            return redirect(f"{next_url}#chatbot")

        history_raw = session.get("chat_history", [])
        history = history_raw if isinstance(history_raw, list) else []
        allow_mutations = is_vulnerable_mode()
        repository_for_mode = get_repository()

        try:
            repository_for_mode.ensure_lab_assets()

            started_at = perf_counter()
            chat_result = get_chatbot_service().chat(
                user_message=user_message,
                history=history,
                allow_mutations=allow_mutations,
            )
            elapsed_ms = round((perf_counter() - started_at) * 1000, 2)
            answer = str(chat_result.get("answer", "")).strip()
            updated_history = history + [
                {"role": "user", "content": user_message},
                {"role": "assistant", "content": answer, "response_time_ms": elapsed_ms},
            ]
            session["chat_history"] = trim_chat_history(updated_history)
            session.pop("chat_error", None)
        except (RuntimeError, ValueError, SQLAlchemyError) as exc:
            app.logger.exception("Chatbot request failed: %s", exc)
            if is_vulnerable_mode():
                session["chat_error"] = f"Chatbot error (intentionally exposed): {exc}"
            else:
                session["chat_error"] = (
                    "Chatbot is unavailable. Check AZURE_OPENAI_* values in your local environment or .env file."
                )
        except Exception as exc:  # pragma: no cover - defensive fallback for unexpected runtime errors
            app.logger.exception("Unexpected chatbot runtime failure: %s", exc)
            if is_vulnerable_mode():
                session["chat_error"] = f"Unexpected chatbot error (intentionally exposed): {exc}"
            else:
                session["chat_error"] = "Unexpected chatbot error. Check application logs."

        return redirect(f"{next_url}#chatbot")

    @app.post("/chat/reset")
    def reset_chat():
        next_url = request.form.get("next", "").strip()
        if not next_url.startswith("/"):
            next_url = url_for("index")

        session.pop("chat_history", None)
        session.pop("chat_error", None)
        return redirect(f"{next_url}#chatbot")

    @app.post("/lab/reset")
    def reset_lab():
        if not is_vulnerable_mode():
            return redirect(url_for("index"))

        next_url = request.form.get("next", "").strip()
        if not next_url.startswith("/"):
            next_url = url_for("index")

        try:
            vulnerable_repository.reset_lab_data()
            session["lab_status"] = "reset-ok"
        except SQLAlchemyError as exc:
            app.logger.exception("Could not reset vulnerable lab data: %s", exc)
            session["lab_status"] = "reset-error"

        return redirect(next_url)

    @app.route("/", methods=["GET", "POST"])
    def index():
        if request.method == "POST":
            query = request.form.get("q", "").strip()
        else:
            query = ""
        lab_status = str(session.pop("lab_status", "")).strip().lower()
        error_message = None
        error_details = None
        training_warning = None
        unsafe_sql = None
        unsafe_params = None
        safe_sql = None
        safe_params = None
        simulation_warning = None
        lab_examples: list[dict[str, str]] = vulnerable_repository.lab_payload_examples()
        lab_info_message = None
        lab_guardrail_message = None
        time_based_probe_result: dict[str, Any] | None = None
        chat_history_raw = session.get("chat_history", [])
        chat_history = trim_chat_history(chat_history_raw if isinstance(chat_history_raw, list) else [])
        chat_error = str(session.pop("chat_error", "")).strip() or None

        if is_vulnerable_mode():
            training_warning = (
                "Training mode: this page demonstrates SQL Injection impact in a controlled lab scope. "
                "Only Labs.ProductSearchSnapshot and Labs.EmployeeSnapshot actions are executed. "
                "A controlled single-request time-based DB_NAME() probe demo is also available. "
                "Error-based demo intentionally exposes full database exception details in the UI. "
                "OR 1=1 bypass exposes products hidden by the normal availability filter."
            )
            simulation_warning = sqli_simulation_message(query)
            if lab_status == "reset-ok":
                lab_info_message = "Lab data reset completed."
            elif lab_status == "reset-error":
                lab_guardrail_message = "Lab reset failed. Check DB permissions for schema Labs."

            actions = vulnerable_repository.detect_lab_actions(query)
            if query and actions["bypass_filter"]:
                lab_info_message = "Detected bypass payload pattern: product-name filtering was intentionally bypassed."
            elif query and actions["insert_product_snapshot"]:
                lab_info_message = (
                    "Detected INSERT payload pattern: a controlled row was written to Labs.ProductSearchSnapshot "
                    "and appended to results."
                )
            elif query and actions["union_employee_snapshot"]:
                lab_info_message = (
                    "Detected Labs.EmployeeSnapshot UNION payload pattern: controlled rows from "
                    "Labs.EmployeeSnapshot were appended."
                )
            elif query and actions["force_db_error"]:
                lab_info_message = (
                    "Detected error-based payload pattern: this request intentionally triggers a database exception. "
                    "In vulnerable mode full DB error details will be exposed in the UI."
                )
            elif query and actions["time_based_delay"]:
                probe = vulnerable_repository.extract_time_based_probe(query)
                if probe:
                    lab_info_message = (
                        "Detected time-based blind payload pattern: "
                        "character inference is based on response delay for "
                        f"DB_NAME() position {probe['position']} with candidate '{probe['character']}'."
                    )
                else:
                    lab_info_message = (
                        "Detected time-based blind payload pattern: character inference is based on response delay."
                    )
                try:
                    time_based_probe_result = vulnerable_repository.run_single_time_based_probe(query)
                    elapsed_ms = time_based_probe_result.get("elapsed_ms")
                    if time_based_probe_result.get("is_delayed"):
                        lab_info_message = (
                            f"Time-based probe delayed response to about {elapsed_ms} ms: "
                            "condition likely TRUE."
                        )
                    else:
                        lab_info_message = (
                            f"Time-based probe returned in about {elapsed_ms} ms: "
                            "condition likely FALSE."
                        )
                except SQLAlchemyError as exc:
                    app.logger.exception("Could not run time-based DB_NAME probe demo: %s", exc)
                    error_message, error_details = map_database_error(exc)
                except ValueError as exc:
                    app.logger.warning("Time-based probe payload parse error: %s", exc)
                    lab_guardrail_message = "Time-based payload was not recognized."
            elif query and actions["insert_log"]:
                lab_info_message = "Detected INSERT payload pattern: a controlled lab write action was recorded."
            elif query and actions["suspicious"]:
                lab_guardrail_message = (
                    "Lab guardrail: this demo executes only patterns targeting "
                    "Labs.ProductSearchSnapshot/Labs.EmployeeSnapshot "
                    "or recognized time-based/error-based probe patterns."
                )

        try:
            unsafe_sql, unsafe_params_raw = vulnerable_repository.preview_search_products_unsafe(query)
            unsafe_params = format_params(unsafe_params_raw)
        except Exception as exc:  # pragma: no cover - defensive preview fallback
            app.logger.exception("Could not build unsafe SQL preview: %s", exc)
            unsafe_sql = None
            unsafe_params = None

        try:
            safe_sql, safe_params_raw = secure_repository.preview_search_products(query)
            safe_params = format_params(safe_params_raw)
        except SQLAlchemyError as exc:
            app.logger.exception("Could not build safe SQL preview: %s", exc)
            safe_sql = None
            safe_params = None

        repository = get_repository()
        try:
            products = repository.search_products(query)
        except SQLAlchemyError as exc:
            products = []
            error_message, error_details = map_database_error(exc)

        return render_template(
            "index.html",
            products=products,
            query=query,
            error_message=error_message,
            error_details=error_details,
            training_warning=training_warning,
            unsafe_sql=unsafe_sql,
            unsafe_params=unsafe_params,
            safe_sql=safe_sql,
            safe_params=safe_params,
            simulation_warning=simulation_warning,
            lab_examples=lab_examples,
            lab_info_message=lab_info_message,
            lab_guardrail_message=lab_guardrail_message,
            time_based_probe_result=time_based_probe_result,
            chat_history=chat_history,
            chat_error=chat_error,
        )

    @app.route("/product/<int:product_id>")
    def product_detail(product_id: int):
        repository = get_repository()
        try:
            product = repository.get_product(product_id)
        except SQLAlchemyError as exc:
            if is_vulnerable_mode():
                error_message, error_details = map_database_error(exc)
                return (
                    render_template(
                        "error.html",
                        message=error_message,
                        error_details=error_details,
                    ),
                    500,
                )
            abort(500)

        if not product:
            abort(404)

        return render_template("product_detail.html", product=product)

    @app.errorhandler(404)
    def not_found(_error):
        return render_template(
            "error.html",
            message="Product was not found.",
            error_details=None,
        ), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        app_mode = get_app_mode()
        app.logger.exception("Unhandled server error in %s mode", app_mode)
        if is_vulnerable_mode():
            return (
                render_template(
                    "error.html",
                    message=f"Unhandled server error (intentionally exposed): {error}",
                    error_details=format_exception_details(error),
                ),
                500,
            )
        return (
            render_template(
                "error.html",
                message=(
                    "An application or database error occurred. "
                    "Check configuration and SQL Server availability."
                ),
                error_details=None,
            ),
            500,
        )

    return app


