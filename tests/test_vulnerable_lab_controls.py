import unittest

from sql_injection_lab.repositories.vulnerable import ProductRepositoryVulnerable


class TestVulnerableLabControls(unittest.TestCase):
    def test_bypass_payload_detection(self) -> None:
        actions = ProductRepositoryVulnerable.detect_lab_actions("' OR 1=1 --")

        self.assertTrue(actions["bypass_filter"])
        self.assertTrue(actions["suspicious"])

    def test_insert_payload_detection_for_product_snapshot(self) -> None:
        payload = (
            "'; INSERT INTO [Labs].[ProductSearchSnapshot] "
            "(product_id,name,list_price,standard_cost,sell_start_date,product_status,description,created_at) "
            "VALUES (900001,'Injected Product',1,1,'2026-01-01','Pending release','Injected via SQLi',GETDATE()) --"
        )

        actions = ProductRepositoryVulnerable.detect_lab_actions(payload)

        self.assertTrue(actions["insert_product_snapshot"])
        self.assertFalse(actions["insert_log"])

    def test_union_payload_detection_for_employee_snapshot_pattern(self) -> None:
        payload = (
            "' UNION ALL SELECT [BusinessEntityID],[LoginID],[SickLeaveHours],"
            "[VacationHours],[BirthDate],[JobTitle] FROM [Labs].[EmployeeSnapshot] --"
        )

        actions = ProductRepositoryVulnerable.detect_lab_actions(payload)

        self.assertTrue(actions["union_employee_snapshot"])
        self.assertFalse(actions["insert_product_snapshot"])
        self.assertFalse(actions["insert_log"])

    def test_insert_payload_detection_is_scoped_to_lab_log(self) -> None:
        payload = (
            "'; INSERT INTO [Labs].[AttackLog] (action_name, injected_text, note) "
            "VALUES ('Injected write', 'demo payload', 'executed from search box') --"
        )

        actions = ProductRepositoryVulnerable.detect_lab_actions(payload)

        self.assertTrue(actions["insert_log"])
        self.assertFalse(actions["insert_product_snapshot"])
        self.assertFalse(actions["union_employee_snapshot"])
        self.assertFalse(actions["time_based_delay"])

    def test_time_based_payload_detection(self) -> None:
        payload = "'; IF(SUBSTRING((SELECT DB_NAME()),1,1)='a') WAITFOR DELAY '00:00:01.000' --"

        actions = ProductRepositoryVulnerable.detect_lab_actions(payload)
        probe = ProductRepositoryVulnerable.extract_time_based_probe(payload)

        self.assertTrue(actions["time_based_delay"])
        self.assertTrue(actions["suspicious"])
        self.assertFalse(actions["insert_product_snapshot"])
        self.assertFalse(actions["union_employee_snapshot"])
        self.assertIsNotNone(probe)
        if probe is None:
            self.fail("Expected time-based probe data.")
        self.assertEqual(probe["position"], 1)
        self.assertEqual(probe["character"], "a")

    def test_error_based_payload_detection(self) -> None:
        payload = "'; SELECT CAST(N'SQLI_DEMO_ERROR' AS INT) --"

        actions = ProductRepositoryVulnerable.detect_lab_actions(payload)

        self.assertTrue(actions["force_db_error"])
        self.assertTrue(actions["suspicious"])
        self.assertFalse(actions["time_based_delay"])

    def test_payload_examples_include_all_demo_scenarios(self) -> None:
        examples = ProductRepositoryVulnerable.lab_payload_examples()
        titles = [entry["title"] for entry in examples]

        self.assertIn("Tautology SQL Injection: filter bypass (OR 1=1)", titles)
        self.assertIn(
            "Stacked-query SQL Injection: controlled INSERT into Labs.ProductSearchSnapshot",
            titles,
        )
        self.assertIn("UNION-based SQL Injection: controlled data leak from Labs.EmployeeSnapshot", titles)
        self.assertIn(
            "Time-based blind SQL Injection: infer DB_NAME() one character by response delay",
            titles,
        )
        self.assertIn("Error-based SQL Injection: force DB exception and leak details", titles)
        self.assertNotIn("Controlled INSERT impact (Labs.AttackLog)", titles)


if __name__ == "__main__":
    unittest.main()
