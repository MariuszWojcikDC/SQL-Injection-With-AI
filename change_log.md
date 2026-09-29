# Changelog

All notable changes to this project are documented in this file.

The format follows the spirit of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), with entries grouped by change type. This project does not currently use semantic version tags, so entries are identified by date and title.

## 2026-06-13 - Rework product lab data, status filtering, and table UX

### Added

- Added `product_status` to `Labs.ProductSearchSnapshot`.
- Added supported product status values:
  - `Available`,
  - `Unavailable`,
  - `Pending release`.
- Added a `Status` column to the product list.
- Added product status to the product details page.
- Added 25 extra lab products with `Unavailable` or `Pending release` status.
- Added a six-digit `product_id` constraint for `Labs.ProductSearchSnapshot`.
- Added `product_status` to chatbot semantic search results.
- Added client-side product table sorting by:
  - `ID`,
  - `Name`,
  - `Price`,
  - `Status`,
  - `Description`.
- Added table sorting styles and direction indicators.
- Added SQL preview test coverage for status filtering and simplified status SQL.

### Changed

- Lab data is now recreated from scratch on application startup.
- Lab bootstrap now runs during Flask app creation instead of waiting for the first product search.
- `Reset lab data` now recreates and reseeds all lab tables from scratch.
- Product seed data now creates exactly:
  - 100 products with `Available` status,
  - 25 products with non-`Available` status.
- Product IDs in `Labs.ProductSearchSnapshot` are normalized to six-digit values.
- Secure mode now shows only products with `Available` status.
- Vulnerable mode now shows `Available` products by default, while the `OR 1=1` demo exposes products in other statuses.
- Product-status SQL filters now use direct comparison:

```sql
s.product_status = N'Available'
```

- Updated the controlled `INSERT` SQL Injection payload to include `product_status`.
- Updated README to document the new lab bootstrap behavior, seeded status mix, and six-digit product IDs.

### Fixed

- Fixed product status showing as `not available` in product details.
- Fixed secure-mode product count being capped by `TOP 100`.
- Fixed vulnerable-mode product list being artificially trimmed to 20 rows.
- Fixed the `OR 1=1` demo so the visible product count changes when hidden status rows are exposed.
- Removed unnecessary defensive `COALESCE(NULLIF(LTRIM(RTRIM(...))))` logic for `product_status`.
- Removed `TOP 100` from product-list queries where it blocked accurate counts and the SQL Injection demo.

## 2026-06-12 - Document Flask secret key

### Added

- Documented the required `FLASK_SECRET_KEY` environment value in README.
- Added instructions for generating a local Flask secret key.
- Clarified local `.env` usage and the requirement not to commit local secrets.

## 2026-06-12 - Initial commit

### Added

- Added Flask application entrypoints:
  - `app.py`,
  - `app_vulnerable.py`.
- Added application factory and route handling in `sql_injection_lab/app_factory.py`.
- Added SQL Server configuration support in `sql_injection_lab/config.py`.
- Added secure and vulnerable product repositories:
  - `sql_injection_lab/repositories/secure.py`,
  - `sql_injection_lab/repositories/vulnerable.py`.
- Added Labs schema bootstrap/support logic in `sql_injection_lab/repositories/labs_support.py`.
- Added product list, product details, base layout, and error templates.
- Added full UI styling in `sql_injection_lab/static/styles.css`.
- Added controlled SQL Injection demo flows:
  - tautology/filter bypass,
  - controlled product insert,
  - controlled employee `UNION` leak,
  - time-based blind probe,
  - error-based database exception exposure.
- Added Azure OpenAI chatbot service with:
  - Labs query tool,
  - semantic product search,
  - product price update tool in vulnerable mode,
  - remote markdown prompt-injection demo support.
- Added demo markdown asset with hidden prompt-injection content.
- Added project documentation in README.
- Added environment and dependency files:
  - `.env.example`,
  - `.gitignore`,
  - `requirements.txt`,
  - pre-commit and detect-secrets baseline files.
- Added initial tests for:
  - vulnerable lab controls,
  - SQL preview behavior,
  - chatbot service/tool behavior.
