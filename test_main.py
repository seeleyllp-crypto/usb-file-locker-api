import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from urllib import error, request

import main as api


TEST_SIGNING_SECRET = "vaultlink-regression-test-signing-secret"
TEST_ADMIN_TOKEN = "vaultlink-regression-test-admin-token"


def sample_report():
    return {
        "exported_at_utc": "2026-07-10T22:00:00Z",
        "defender_status": {
            "available": True,
            "AntivirusEnabled": True,
            "forbidden": "SECRET_DEFENDER_FIELD",
            "LastQuickScanSource": "SECRET_SCAN_SOURCE",
        },
        "usb_file_locker_audit": {
            "valid": True,
            "verification": "SECRET_VERIFICATION_FIELD",
            "events": [
                {
                    "sequence": 1,
                    "time_utc": "2026-07-10T22:00:00Z",
                    "event_id": "event-001",
                    "action": "lock",
                    "result": "success",
                    "hash": "a" * 64,
                    "previous_hash": "0" * 64,
                    "full_path": "C:/Private/secret.txt",
                    "file_contents": "SECRET_FILE_CONTENT",
                },
                {
                    "sequence": 2,
                    "time_utc": "2026-07-10T22:01:00Z",
                    "event_id": "SECRET-EVENT-ID",
                    "action": "SECRET_ACTION_FIELD",
                    "result": "success",
                    "hash": "b" * 64,
                    "previous_hash": "a" * 64,
                },
            ],
        },
        "pc_safety_check_audit": {
            "valid": True,
            "verification": "Valid",
            "events": [],
        },
        "password": "SECRET_PASSWORD_FIELD",
        "limitations": ["SECRET_LIMITATION_FIELD"],
    }


class VaultLinkApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old_signing_secret = os.environ.get("LICENSE_SIGNING_SECRET")
        cls.old_admin_token = os.environ.get("LICENSE_ADMIN_TOKEN")
        os.environ["LICENSE_SIGNING_SECRET"] = TEST_SIGNING_SECRET
        os.environ["LICENSE_ADMIN_TOKEN"] = TEST_ADMIN_TOKEN
        cls.server = api.ThreadingHTTPServer(("127.0.0.1", 0), api.ApiHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=5)
        if cls.old_signing_secret is None:
            os.environ.pop("LICENSE_SIGNING_SECRET", None)
        else:
            os.environ["LICENSE_SIGNING_SECRET"] = cls.old_signing_secret
        if cls.old_admin_token is None:
            os.environ.pop("LICENSE_ADMIN_TOKEN", None)
        else:
            os.environ["LICENSE_ADMIN_TOKEN"] = cls.old_admin_token

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="vaultlink_api_test_")
        api.AUDIT_EXPORT_DIR = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def call(self, path, method="GET", payload=None, raw_body=None, headers=None):
        request_headers = dict(headers or {})
        if payload is not None:
            raw_body = json.dumps(payload).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        req = request.Request(
            self.base_url + path,
            data=raw_body,
            headers=request_headers,
            method=method,
        )
        try:
            with request.urlopen(req, timeout=10) as response:
                body = response.read()
                return response.status, json.loads(body.decode("utf-8")) if body else {}
        except error.HTTPError as exc:
            try:
                body = exc.read()
                return exc.code, json.loads(body.decode("utf-8")) if body else {}
            finally:
                exc.close()

    def issue_and_activate(self, plan_id="personal-plus", machine_id="TEST-MACHINE"):
        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={"plan_id": plan_id, "customer_label": "Regression test"},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)
        status, activated = self.call(
            "/api/v1/licenses/activate",
            method="POST",
            payload={
                "license_key": issued["license_key"],
                "machine_id": machine_id,
                "machine_name": "Test PC",
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(activated["active"])
        return issued, activated

    def upload_report(self, issued, activated, machine_id="TEST-MACHINE"):
        return self.call(
            "/api/v1/audit-exports",
            method="POST",
            payload={
                "license_key": issued["license_key"],
                "receipt": activated["receipt"],
                "machine_id": machine_id,
                "app_version": "test",
                "report": sample_report(),
            },
        )

    def test_license_issue_activate_verify_and_header_only_admin(self):
        status, denied = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={"plan_id": "family-safety", "admin_token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")

        issued, activated = self.issue_and_activate("family-safety")
        self.assertTrue(issued["license_key"].startswith("vlk1."))
        self.assertTrue(activated["receipt"].startswith("vlr1."))

        status, verified = self.call(
            "/api/v1/licenses/verify",
            method="POST",
            payload={
                "license_key": issued["license_key"],
                "receipt": activated["receipt"],
                "machine_id": "TEST-MACHINE",
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(verified["active"])

        status, wrong_machine = self.call(
            "/api/v1/licenses/verify",
            method="POST",
            payload={
                "license_key": issued["license_key"],
                "receipt": activated["receipt"],
                "machine_id": "OTHER-MACHINE",
            },
        )
        self.assertEqual(status, 200)
        self.assertFalse(wrong_machine["active"])
        self.assertEqual(wrong_machine["status"], "wrong_machine")

    def test_audit_export_strips_private_fields_and_uses_bearer_token(self):
        issued, activated = self.issue_and_activate("personal-plus")
        status, uploaded = self.upload_report(issued, activated)
        self.assertEqual(status, 201)
        self.assertNotIn("token=", uploaded["download_path"])

        status, denied = self.call(uploaded["download_path"])
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")

        status, downloaded = self.call(
            uploaded["download_path"],
            headers={"Authorization": f"Bearer {uploaded['download_token']}"},
        )
        self.assertEqual(status, 200)
        event = downloaded["report"]["usb_file_locker_audit"]["events"][0]
        self.assertEqual(
            set(event),
            {"sequence", "time_utc", "event_id", "action", "result", "hash", "previous_hash"},
        )
        unknown_event = downloaded["report"]["usb_file_locker_audit"]["events"][1]
        self.assertEqual(unknown_event["action"], "unknown_action")
        self.assertRegex(unknown_event["event_id"], r"^[0-9a-f]{16}$")
        serialized = json.dumps(downloaded)
        for forbidden in (
            "SECRET_FILE_CONTENT",
            "SECRET_PASSWORD_FIELD",
            "SECRET_DEFENDER_FIELD",
            "SECRET_SCAN_SOURCE",
            "SECRET_VERIFICATION_FIELD",
            "SECRET_ACTION_FIELD",
            "SECRET-EVENT-ID",
            "SECRET_LIMITATION_FIELD",
            "C:/Private/secret.txt",
        ):
            self.assertNotIn(forbidden, serialized)

        token = uploaded["download_token"]
        tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
        status, denied = self.call(
            uploaded["download_path"],
            headers={"Authorization": f"Bearer {tampered}"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")

    def test_starter_plan_cannot_upload_audit_report(self):
        issued, activated = self.issue_and_activate("starter")
        status, denied = self.upload_report(issued, activated)
        self.assertEqual(status, 403)
        self.assertIn("does not include", denied["message"])

    def test_route_limits_content_type_and_unknown_route(self):
        oversized = b'{' + b'"padding":"' + (b"x" * api.MAX_LICENSE_JSON_BODY_BYTES) + b'"}'
        status, response = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            raw_body=oversized,
            headers={
                "Content-Type": "application/json",
                "X-License-Admin-Token": TEST_ADMIN_TOKEN,
            },
        )
        self.assertEqual(status, 413)
        self.assertEqual(response["error"], "request_too_large")

        status, response = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            raw_body=b"plan_id=family-safety",
            headers={
                "Content-Type": "text/plain",
                "X-License-Admin-Token": TEST_ADMIN_TOKEN,
            },
        )
        self.assertEqual(status, 415)
        self.assertEqual(response["error"], "unsupported_media_type")

        status, response = self.call(
            "/api/v1/not-a-route",
            method="POST",
            payload={"anything": True},
        )
        self.assertEqual(status, 404)
        self.assertEqual(response["error"], "not_found")

    def test_download_rejects_damaged_stored_identity(self):
        issued, activated = self.issue_and_activate("personal-plus")
        status, uploaded = self.upload_report(issued, activated)
        self.assertEqual(status, 201)
        stored_path = api.audit_export_path(uploaded["export_id"])
        stored = json.loads(stored_path.read_text(encoding="utf-8"))
        stored["source"]["machine_hash"] = "0" * 16
        stored_path.write_text(json.dumps(stored), encoding="utf-8")

        status, denied = self.call(
            uploaded["download_path"],
            headers={"Authorization": f"Bearer {uploaded['download_token']}"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")

    def test_field_and_token_length_limits(self):
        status, response = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={"plan_id": "family-safety", "customer_label": "x" * 161},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 400)
        self.assertIn("160", response["message"])

        with self.assertRaisesRegex(ValueError, "too large"):
            api.verify_token("vlk1." + ("x" * api.MAX_SIGNED_TOKEN_CHARS), api.LICENSE_KEY_PREFIX)

    def test_all_seven_ranks_are_public_and_ordered(self):
        status, response = self.call("/api/v1/ranks")
        self.assertEqual(status, 200)
        self.assertEqual(response["count"], 7)
        items = response["items"]
        self.assertEqual(
            [item["id"] for item in items],
            [
                "starter",
                "home",
                "personal-plus",
                "family-safety",
                "small-office",
                "family-office",
                "pro-baseline",
            ],
        )
        self.assertEqual([item["rank"] for item in items], list(range(1, 8)))
        self.assertEqual(items[1]["price_label"], "$10-$25")
        self.assertEqual(items[5]["price_max_usd"], 3000)
        self.assertIsNone(items[6]["price_max_usd"])
        self.assertIn("pro-baseline-pack", items[6]["entitlements"])
        self.assertGreater(len(items[6]["entitlements"]), len(items[5]["entitlements"]))

    def test_legacy_plan_ids_issue_equivalent_canonical_ranks(self):
        expected = {
            "plus": "personal-plus",
            "pro": "family-safety",
            "signature": "small-office",
        }
        for legacy_id, canonical_id in expected.items():
            with self.subTest(legacy_id=legacy_id):
                status, response = self.call(
                    "/api/v1/licenses/issue",
                    method="POST",
                    payload={"plan_id": legacy_id},
                    headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
                )
                self.assertEqual(status, 201)
                self.assertEqual(response["license"]["plan_id"], canonical_id)
                self.assertEqual(response["plan"]["id"], canonical_id)


if __name__ == "__main__":
    unittest.main(verbosity=2)
