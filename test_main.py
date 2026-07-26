import base64
import json
import hashlib
import os
import tempfile
import threading
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib import error, request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import main as api


TEST_SIGNING_SECRET = "vaultlink-regression-test-signing-secret"
TEST_ADMIN_TOKEN = "vaultlink-regression-test-admin-token"
TEST_UPDATE_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"vaultlink-regression-update-key").digest())
TEST_UPDATE_PUBLIC_KEY_RAW = TEST_UPDATE_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
TEST_UPDATE_PUBLIC_KEY_B64 = base64.urlsafe_b64encode(TEST_UPDATE_PUBLIC_KEY_RAW).decode("ascii").rstrip("=")
TEST_UPDATE_SIGNING_KEY_ID = "vaultlink-test-key"


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
        self.old_update_public_key = api.UPDATE_SIGNING_PUBLIC_KEY_B64
        self.old_update_key_id = api.UPDATE_SIGNING_KEY_ID
        api.UPDATE_SIGNING_PUBLIC_KEY_B64 = TEST_UPDATE_PUBLIC_KEY_B64
        api.UPDATE_SIGNING_KEY_ID = TEST_UPDATE_SIGNING_KEY_ID
        api.AUDIT_EXPORT_DIR = Path(self.temp_dir.name)
        api.LICENSE_STATE_DIR = Path(self.temp_dir.name) / "license_state"
        api.UPDATE_DIR = Path(self.temp_dir.name) / "updates"
        api.UPDATE_MANIFEST_PATH = api.UPDATE_DIR / "windows-manifest.json"
        api.ACCOUNT_LOGIN_FAILURES.clear()
        api.ACCOUNT_REGISTER_ATTEMPTS.clear()
        api.ACCOUNT_AVAILABILITY_CHECKS.clear()
        self._default_license_account_id = ""

    def tearDown(self):
        api.UPDATE_SIGNING_PUBLIC_KEY_B64 = self.old_update_public_key
        api.UPDATE_SIGNING_KEY_ID = self.old_update_key_id
        self.temp_dir.cleanup()

    def default_license_account_id(self):
        if self._default_license_account_id:
            return self._default_license_account_id
        registered = api.register_account(
            {
                "username": "license_test_customer",
                "password": "Safe-Test-Account-4092!",
            },
            remote_key="license-test-fixture",
        )
        self._default_license_account_id = registered["account"]["account_id"]
        return self._default_license_account_id

    def call(self, path, method="GET", payload=None, raw_body=None, headers=None, auto_account=True):
        request_headers = dict(headers or {})
        if (
            auto_account
            and path == "/api/v1/licenses/issue"
            and method == "POST"
            and isinstance(payload, dict)
            and not payload.get("account_id")
        ):
            payload = dict(payload)
            payload["account_id"] = self.default_license_account_id()
        if payload is not None:
            raw_body = json.dumps(payload).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        for attempt in range(2):
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
            except (ConnectionAbortedError, ConnectionResetError):
                if attempt:
                    raise

    def call_bytes(self, path, headers=None):
        req = request.Request(self.base_url + path, headers=dict(headers or {}), method="GET")
        try:
            with request.urlopen(req, timeout=10) as response:
                return response.status, dict(response.headers.items()), response.read()
        except error.HTTPError as exc:
            try:
                return exc.code, dict(exc.headers.items()), exc.read()
            finally:
                exc.close()

    def publish_test_update(self):
        api.UPDATE_DIR.mkdir(parents=True, exist_ok=True)
        package = api.UPDATE_DIR / "VaultLink-Windows-9999.1.zip"
        package.write_bytes(b"PK-test-signed-update-package")
        manifest = {
            "schema_version": 1,
            "product": "USB File Locker",
            "platform": "windows-source",
            "version": "9999.1",
            "minimum_supported_version": "2026.07.10",
            "published_at_utc": "2026-07-11T15:00:00Z",
            "package_filename": package.name,
            "download_path": "/api/v1/updates/windows/download",
            "sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
            "size_bytes": package.stat().st_size,
            "signing_key_id": api.UPDATE_SIGNING_KEY_ID,
            "notes": ["Regression update"],
            "preserves_local_app_data": True,
        }
        signature = TEST_UPDATE_PRIVATE_KEY.sign(api.canonical_update_manifest_bytes(manifest))
        manifest["signature"] = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        api.UPDATE_MANIFEST_PATH.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest, package

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

    def upload_report(self, issued, activated, machine_id="TEST-MACHINE", report=None):
        return self.call(
            "/api/v1/audit-exports",
            method="POST",
            payload={
                "license_key": issued["license_key"],
                "receipt": activated["receipt"],
                "machine_id": machine_id,
                "app_version": "test",
                "report": report or sample_report(),
            },
        )

    def test_support_redactor_is_published_as_a_privacy_safe_customer_companion(self):
        self.assertEqual(api.API_VERSION, "0.68.0")
        product = api.product_payload()
        self.assertIn("support_redactor.py", product["desktop_scripts"])
        companion = next(item for item in api.COMPANION_APPS if item["script"] == "support_redactor.py")
        self.assertEqual(companion["name"], "Support Redactor")
        self.assertIn("without automatic upload", companion["purpose"])
        self.assertTrue(
            {
                "support_redactor_copy",
                "support_redactor_load",
                "support_redactor_open",
                "support_redactor_paste",
                "support_redactor_run",
                "support_redactor_save",
            }.issubset(api.ALLOWED_AUDIT_ACTIONS)
        )

    def test_download_verification_is_published_without_file_upload_actions(self):
        product = api.product_payload()
        self.assertIn("download_verification_center.py", product["desktop_scripts"])
        companion = next(
            item for item in api.COMPANION_APPS
            if item["script"] == "download_verification_center.py"
        )
        self.assertEqual(companion["name"], "Download Verification Center")
        self.assertIn("locally sealed receipts", companion["purpose"])
        self.assertIn("inspect or compare one sanitized prior receipt", companion["purpose"])
        self.assertIn("bounded non-recursive aggregate receipt-folder audit", companion["purpose"])
        self.assertIn("single local review window", companion["purpose"])
        self.assertIn("scrollable small-screen review surface", companion["purpose"])
        self.assertIn("bounded row and review-ID consumption", companion["purpose"])
        self.assertIn("cancellable search debounce", companion["purpose"])
        self.assertIn("keyboard review controls", companion["purpose"])
        self.assertIn("fixed active-view indicator without query text", companion["purpose"])
        self.assertIn("stable empty and complete states", companion["purpose"])
        self.assertIn("visible and pending queue positions", companion["purpose"])
        self.assertIn("priority-level and session-state filtering", companion["purpose"])
        self.assertIn("privacy-safe fixed guidance and aggregate summary copy", companion["purpose"])
        self.assertIn("review-and-next", companion["purpose"])
        self.assertIn("Ctrl+Enter review-and-next", companion["purpose"])
        self.assertIn("Ctrl+Z undo", companion["purpose"])
        self.assertIn("bounded bulk-visible review or reopen marks", companion["purpose"])
        self.assertIn("100-action one-step bulk undo", companion["purpose"])
        self.assertIn("aggregate completion progress with a determinate bar", companion["purpose"])
        self.assertIn("aggregate level breakdown", companion["purpose"])
        self.assertIn("visible pending and reviewed counts", companion["purpose"])
        self.assertIn("failure-first navigation", companion["purpose"])
        self.assertIn("forward and reverse pending navigation", companion["purpose"])
        self.assertIn("search text", companion["purpose"])
        self.assertIn("active-view state", companion["purpose"])
        self.assertIn("queue positions", companion["purpose"])
        self.assertIn("clipboard text", companion["purpose"])
        self.assertIn("delayed-callback state", companion["purpose"])
        self.assertIn("review IDs", companion["purpose"])
        self.assertIn("action history", companion["purpose"])
        self.assertIn("bulk mark state", companion["purpose"])
        self.assertIn("session state", companion["purpose"])
        self.assertIn("progress", companion["purpose"])
        self.assertIn("selected positions", companion["purpose"])
        self.assertIn("visible counts", companion["purpose"])
        self.assertIn("selections", companion["purpose"])
        self.assertIn("level filters", companion["purpose"])
        self.assertIn("guidance state", companion["purpose"])
        self.assertIn("summary contents", companion["purpose"])
        self.assertIn("without extracting", companion["purpose"])
        self.assertIn("uploading", companion["purpose"])
        self.assertTrue(
            {
                "download_verify_audit_receipt_folder",
                "download_verify_clear_receipt_folder_review",
                "download_verify_copy_hash",
                "download_verify_copy_review_guidance",
                "download_verify_copy_review_summary",
                "download_verify_copy_receipt_inspection",
                "download_verify_copy_summary",
                "download_verify_compare_receipt",
                "download_verify_defender",
                "download_verify_export",
                "download_verify_export_comparison",
                "download_verify_export_receipt_folder_audit",
                "download_verify_inspect_receipt",
                "download_verify_open",
                "download_verify_run",
                "download_verify_select",
                "download_verify_view_receipt_folder_review",
            }.issubset(api.ALLOWED_AUDIT_ACTIONS)
        )
        self.assertFalse(
            any(
                "download_verify_upload" in action or "download_verify_execute" in action
                for action in api.ALLOWED_AUDIT_ACTIONS
            )
        )

    def test_public_shop_publishes_only_valid_hosted_checkout_links(self):
        env_names = [*api.SHOP_CHECKOUT_ENV_BY_PLAN.values(), "SHOP_CHECKOUT_ALLOWED_HOSTS"]
        previous = {name: os.environ.get(name) for name in env_names}
        try:
            for name in env_names:
                os.environ.pop(name, None)

            status, shop = self.call("/api/v1/shop")
            self.assertEqual(status, 200)
            self.assertEqual(shop["count"], 7)
            self.assertEqual(shop["configured_count"], 0)
            self.assertFalse(shop["ready"])
            self.assertFalse(shop["card_data_collected_by_vaultlink"])
            self.assertTrue(all(not item["checkout_available"] for item in shop["items"]))

            status, _headers, page = self.call_bytes("/shop")
            page_text = page.decode("utf-8")
            self.assertEqual(status, 200)
            self.assertIn("VaultLink Shop", page_text)
            self.assertEqual(page_text.count("NOT ON SALE YET"), 7)

            os.environ["SHOP_CHECKOUT_STARTER_URL"] = "https://buy.stripe.com/test_vaultlink_starter"
            os.environ["SHOP_CHECKOUT_HOME_URL"] = "http://buy.stripe.com/test_insecure"
            os.environ["SHOP_CHECKOUT_PERSONAL_PLUS_URL"] = "https://buy.stripe.com.evil.example/test_spoofed"
            os.environ["SHOP_CHECKOUT_FAMILY_SAFETY_URL"] = "https://buy.stripe.com/test_fragment#secret"
            os.environ["SHOP_CHECKOUT_SMALL_OFFICE_URL"] = "https://owner@buy.stripe.com/test_userinfo"
            os.environ["SHOP_CHECKOUT_FAMILY_OFFICE_URL"] = "https://buy.stripe.com:444/test_port"
            os.environ["SHOP_CHECKOUT_PRO_BASELINE_URL"] = "https://buy.stripe.com/"

            status, shop = self.call("/api/v1/shop")
            self.assertEqual(status, 200)
            self.assertEqual(shop["configured_count"], 1)
            starter = next(item for item in shop["items"] if item["id"] == "starter")
            self.assertTrue(starter["checkout_available"])
            self.assertEqual(starter["checkout_url"], os.environ["SHOP_CHECKOUT_STARTER_URL"])
            self.assertTrue(
                all(
                    not item["checkout_available"]
                    for item in shop["items"]
                    if item["id"] != "starter"
                )
            )

            status, health = self.call("/health")
            self.assertEqual(status, 200)
            self.assertEqual(health["shop_checkout_links_configured"], 1)
            self.assertFalse(health["shop_card_data_collected_by_vaultlink"])

            status, dashboard = self.call(
                "/api/v1/admin/dashboard",
                headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
            )
            self.assertEqual(status, 200)
            self.assertEqual(dashboard["shop"]["configured"], 1)
            self.assertEqual(dashboard["shop"]["total"], 7)
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def test_anonymous_plan_advisor_and_comparison(self):
        status, recommendation = self.call(
            "/api/v1/shop/recommend",
            method="POST",
            payload={
                "audience": "personal",
                "priorities": ["private-vault"],
                "max_budget_usd": 50,
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(recommendation["fit"], "full")
        self.assertEqual(recommendation["recommended"]["id"], "personal-plus")
        serialized_recommendation = json.dumps(recommendation)
        self.assertNotIn("customer_email", serialized_recommendation)
        self.assertNotIn("license_key", serialized_recommendation)
        self.assertNotIn("machine_id", serialized_recommendation)
        self.assertNotIn("payment_method", serialized_recommendation)

        status, partial = self.call(
            "/api/v1/shop/recommend",
            method="POST",
            payload={
                "audience": "family",
                "priorities": ["family-safety"],
                "max_budget_usd": 50,
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(partial["fit"], "partial")
        self.assertEqual(partial["recommended"]["id"], "personal-plus")
        self.assertEqual(partial["target"]["id"], "family-safety")

        status, comparison = self.call(
            "/api/v1/shop/compare",
            method="POST",
            payload={"plan_ids": ["starter", "personal-plus"]},
        )
        self.assertEqual(status, 200)
        self.assertEqual(comparison["count"], 2)
        self.assertEqual(comparison["highest_rank"]["id"], "personal-plus")
        self.assertIn("personal-vault", comparison["entitlement_ids"])
        starter = next(item for item in comparison["items"] if item["id"] == "starter")
        plus = next(item for item in comparison["items"] if item["id"] == "personal-plus")
        self.assertFalse(starter["entitlement_matrix"]["personal-vault"])
        self.assertTrue(plus["entitlement_matrix"]["personal-vault"])

        status, bad_comparison = self.call(
            "/api/v1/shop/compare",
            method="POST",
            payload={"plan_ids": ["starter"]},
        )
        self.assertEqual(status, 400)
        self.assertEqual(bad_comparison["error"], "bad_request")

        status, _headers, page = self.call_bytes("/shop")
        page_text = page.decode("utf-8")
        self.assertEqual(status, 200)
        self.assertIn("Plan Advisor", page_text)
        self.assertIn("COMPARE SELECTED", page_text)
        self.assertIn("/api/v1/shop/recommend", page_text)
        self.assertIn("/api/v1/shop/compare", page_text)

    def test_customer_license_preview_is_read_only_and_private(self):
        self.assertEqual(len(api.RANK_EXCLUSIVE_TOOLS), 35)
        self.assertEqual(len({item["id"] for item in api.RANK_EXCLUSIVE_TOOLS}), 35)
        for rank in range(1, 8):
            self.assertEqual(sum(item["rank"] == rank for item in api.RANK_EXCLUSIVE_TOOLS), 5)
        self.assertTrue(all(len(item["checklist"]) == 4 for item in api.RANK_EXCLUSIVE_TOOLS))

        expires_at = api.format_utc(datetime.now(timezone.utc) + timedelta(days=45))
        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={
                "plan_id": "family-safety",
                "customer_label": "PRIVATE-CUSTOMER-4581",
                "customer_email": "private-4581@example.test",
                "license_note": "PRIVATE-NOTE-4581",
                "max_devices": 4,
                "expires_at_utc": expires_at,
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)
        key = issued["license_key"]
        license_id = issued["license"]["license_id"]
        self.assertEqual(api.active_device_count(license_id), 0)

        status, preview = self.call(
            "/api/v1/licenses/preview",
            method="POST",
            payload={"license_key": key},
        )
        self.assertEqual(status, 200)
        self.assertEqual(preview["status"], "active")
        self.assertTrue(preview["does_not_activate"])
        self.assertEqual(preview["plan"]["id"], "family-safety")
        self.assertEqual(preview["rank_progress"], {"current": 4, "maximum": 7, "percent": 57})
        self.assertEqual(preview["device_usage"]["active"], 0)
        self.assertEqual(preview["device_usage"]["maximum"], 4)
        self.assertEqual(preview["device_usage"]["available"], 4)
        self.assertTrue(preview["device_usage"]["identities_excluded"])
        self.assertEqual(preview["next_rank"]["id"], "small-office")
        self.assertGreaterEqual(len(preview["customer_actions"]), 3)
        self.assertEqual(api.active_device_count(license_id), 0)
        serialized = json.dumps(preview)
        self.assertNotIn("PRIVATE-CUSTOMER-4581", serialized)
        self.assertNotIn("private-4581@example.test", serialized)
        self.assertNotIn("PRIVATE-NOTE-4581", serialized)
        self.assertNotIn(key, serialized)

        status, upgrades = self.call(
            "/api/v1/licenses/upgrade-options",
            method="POST",
            payload={"license_key": key},
        )
        self.assertEqual(status, 200)
        self.assertEqual(upgrades["current_plan"]["id"], "family-safety")
        self.assertEqual(upgrades["count"], 3)
        self.assertFalse(upgrades["highest_rank_reached"])
        self.assertEqual(upgrades["items"][0]["plan"]["id"], "small-office")
        self.assertGreater(upgrades["items"][0]["added_entitlement_count"], 0)
        serialized_upgrades = json.dumps(upgrades)
        self.assertNotIn("PRIVATE-CUSTOMER-4581", serialized_upgrades)
        self.assertNotIn("private-4581@example.test", serialized_upgrades)
        self.assertNotIn("PRIVATE-NOTE-4581", serialized_upgrades)
        self.assertNotIn(key, serialized_upgrades)

        status, rank_tools = self.call(
            "/api/v1/licenses/rank-tools",
            method="POST",
            payload={"license_key": key},
        )
        self.assertEqual(status, 200)
        self.assertTrue(rank_tools["active"])
        self.assertEqual(rank_tools["current_rank"], 4)
        self.assertEqual(rank_tools["unlocked_count"], 20)
        self.assertEqual(rank_tools["current_rank_exclusive_count"], 5)
        self.assertEqual(rank_tools["locked_count"], 15)
        self.assertEqual(rank_tools["total_checklist_steps"], 80)
        self.assertIn("Recovery", rank_tools["categories"])
        self.assertIn("Security", rank_tools["categories"])
        self.assertEqual(len(rank_tools["items"]), 20)
        self.assertEqual(len(rank_tools["current_rank_items"]), 5)
        self.assertTrue(all(item["rank"] <= 4 for item in rank_tools["items"]))
        self.assertTrue(all(item["rank"] == 4 for item in rank_tools["current_rank_items"]))
        self.assertTrue(all(item.get("checklist") for item in rank_tools["items"]))
        self.assertTrue(all(item.get("category") for item in rank_tools["items"]))
        self.assertTrue(all(item.get("estimated_minutes") for item in rank_tools["items"]))
        self.assertTrue(all("checklist" not in item for item in rank_tools["locked_previews"]))
        serialized_rank_tools = json.dumps(rank_tools)
        self.assertNotIn("PRIVATE-CUSTOMER-4581", serialized_rank_tools)
        self.assertNotIn("private-4581@example.test", serialized_rank_tools)
        self.assertNotIn("PRIVATE-NOTE-4581", serialized_rank_tools)
        self.assertNotIn(key, serialized_rank_tools)

        self.publish_test_update()
        status, checkup = self.call(
            "/api/v1/licenses/customer-checkup",
            method="POST",
            payload={"license_key": key, "app_version": "2026.07.12.8"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(checkup["overall"], "check")
        self.assertEqual(len(checkup["items"]), 6)
        self.assertEqual(sum(checkup["counts"].values()), 6)
        self.assertEqual(checkup["attention_count"], checkup["counts"]["check"] + checkup["counts"]["action"])
        update_item = next(item for item in checkup["items"] if item["id"] == "update")
        self.assertEqual(update_item["severity"], "check")
        self.assertEqual(update_item["title"], "Update available")
        self.assertIn("not an antivirus scan", " ".join(checkup["limitations"]).lower())
        serialized_checkup = json.dumps(checkup)
        self.assertNotIn("PRIVATE-CUSTOMER-4581", serialized_checkup)
        self.assertNotIn("private-4581@example.test", serialized_checkup)
        self.assertNotIn("PRIVATE-NOTE-4581", serialized_checkup)
        self.assertNotIn(key, serialized_checkup)

        status, support_guide = self.call(
            "/api/v1/licenses/support-guide",
            method="POST",
            payload={"license_key": key, "category": "update"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(support_guide["guide_id"], "GUIDE-UPDATE")
        self.assertEqual(support_guide["category"], "update")
        self.assertEqual(len(support_guide["steps"]), 5)
        self.assertTrue(support_guide["signed_update"]["published"])
        self.assertEqual(support_guide["signed_update"]["version"], "9999.1")
        self.assertEqual(len(support_guide["signed_update"]["sha256"]), 64)
        self.assertIn("does not upload", support_guide["local_file_verification"])
        serialized_guide = json.dumps(support_guide)
        self.assertNotIn("PRIVATE-CUSTOMER-4581", serialized_guide)
        self.assertNotIn("private-4581@example.test", serialized_guide)
        self.assertNotIn("PRIVATE-NOTE-4581", serialized_guide)
        self.assertNotIn(key, serialized_guide)

        status, timeline = self.call(
            "/api/v1/licenses/timeline",
            method="POST",
            payload={"license_key": key},
        )
        self.assertEqual(status, 200)
        self.assertTrue(timeline["does_not_activate"])
        self.assertEqual(timeline["plan"]["id"], "family-safety")
        self.assertGreaterEqual(timeline["event_count"], 4)
        self.assertTrue(timeline["renewal_reminder"]["available"])
        self.assertEqual(timeline["renewal_reminder"]["advance_days"], 30)
        self.assertEqual(timeline["renewal_reminder"]["expires_at_utc"], expires_at)
        self.assertGreaterEqual(timeline["days_remaining"], 44)
        self.assertTrue(any(item["id"] == "expiration" for item in timeline["items"]))
        self.assertEqual(api.active_device_count(license_id), 0)
        serialized_timeline = json.dumps(timeline)
        self.assertNotIn("PRIVATE-CUSTOMER-4581", serialized_timeline)
        self.assertNotIn("private-4581@example.test", serialized_timeline)
        self.assertNotIn("PRIVATE-NOTE-4581", serialized_timeline)
        self.assertNotIn(key, serialized_timeline)

        status, bad_guide = self.call(
            "/api/v1/licenses/support-guide",
            method="POST",
            payload={"license_key": key, "category": "send-all-files"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(bad_guide["error"], "bad_request")

        status, bad_checkup = self.call(
            "/api/v1/licenses/customer-checkup",
            method="POST",
            payload={"license_key": key, "app_version": "x" * 81},
        )
        self.assertEqual(status, 400)
        self.assertEqual(bad_checkup["error"], "bad_request")

        status, _limited = self.call(
            "/api/v1/licenses/limit",
            method="POST",
            payload={"license_key": key, "hours": 1, "reason": "Rank tool regression test."},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        status, limited_tools = self.call(
            "/api/v1/licenses/rank-tools",
            method="POST",
            payload={"license_key": key},
        )
        self.assertEqual(status, 200)
        self.assertFalse(limited_tools["active"])
        self.assertEqual(limited_tools["license_status"], "limited")
        self.assertEqual(limited_tools["items"], [])
        status, _unlimited = self.call(
            "/api/v1/licenses/unlimit",
            method="POST",
            payload={"license_key": key},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)

        status, _revoked = self.call(
            "/api/v1/licenses/revoke",
            method="POST",
            payload={"license_key": key},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        status, preview = self.call(
            "/api/v1/licenses/preview",
            method="POST",
            payload={"license_key": key},
        )
        self.assertEqual(status, 200)
        self.assertEqual(preview["status"], "revoked")
        self.assertFalse(preview["active"])
        status, blocked_tools = self.call(
            "/api/v1/licenses/rank-tools",
            method="POST",
            payload={"license_key": key},
        )
        self.assertEqual(status, 200)
        self.assertFalse(blocked_tools["active"])
        self.assertEqual(blocked_tools["unlocked_count"], 0)
        self.assertEqual(blocked_tools["items"], [])
        self.assertEqual(blocked_tools["locked_count"], 35)
        self.assertTrue(blocked_tools["recovery_always_available"])

        status, pro_issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={"plan_id": "pro-baseline"},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)
        status, pro_tools = self.call(
            "/api/v1/licenses/rank-tools",
            method="POST",
            payload={"license_key": pro_issued["license_key"]},
        )
        self.assertEqual(status, 200)
        self.assertEqual(pro_tools["current_rank"], 7)
        self.assertEqual(pro_tools["unlocked_count"], 35)
        self.assertEqual(pro_tools["current_rank_exclusive_count"], 5)
        self.assertEqual(pro_tools["locked_count"], 0)

        status, _headers, page = self.call_bytes("/customer")
        page_text = page.decode("utf-8")
        self.assertEqual(status, 200)
        self.assertIn("Customer License Center", page_text)
        self.assertIn("/api/v1/licenses/preview", page_text)
        self.assertIn("/api/v1/licenses/upgrade-options", page_text)
        self.assertIn("/api/v1/licenses/rank-tools", page_text)
        self.assertIn("/api/v1/licenses/customer-checkup", page_text)
        self.assertIn("/api/v1/licenses/support-guide", page_text)
        self.assertIn("/api/v1/licenses/timeline", page_text)
        self.assertIn("COPY SUMMARY", page_text)
        self.assertIn("EXPORT JSON", page_text)
        self.assertIn("COPY RANK TOOLS", page_text)
        self.assertIn("EXPORT RANK PACK", page_text)
        self.assertIn("Rank-exclusive tools", page_text)
        self.assertIn("SEARCH UNLOCKED TOOLS", page_text)
        self.assertIn("RESET PROGRESS", page_text)
        self.assertIn("checklist steps complete in this session", page_text)
        self.assertIn("Installed app version", page_text)
        self.assertIn("Customer Checkup", page_text)
        self.assertIn("CURRENT RANK ONLY", page_text)
        self.assertIn("INCOMPLETE ONLY", page_text)
        self.assertIn("FAVORITES ONLY", page_text)
        self.assertIn("NEXT INCOMPLETE", page_text)
        self.assertIn("IMPORT RANK PACK", page_text)
        self.assertIn("Support Guide", page_text)
        self.assertIn("Signed Update Verifier", page_text)
        self.assertIn("CHOOSE UPDATE ZIP", page_text)
        self.assertIn("COPY GUIDE", page_text)
        self.assertIn("EXPORT GUIDE", page_text)
        self.assertIn("License Timeline", page_text)
        self.assertIn("COPY TIMELINE", page_text)
        self.assertIn("EXPORT TIMELINE", page_text)
        self.assertIn("ADD RENEWAL REMINDER", page_text)
        self.assertIn("Higher ranks", page_text)
        self.assertIn("without activating", page_text.lower())

    def test_customer_workspace_and_owner_experience_are_private_and_complete(self):
        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={
                "plan_id": "small-office",
                "customer_label": "WORKSPACE-PRIVATE-CUSTOMER-8821",
                "customer_email": "workspace-8821@example.test",
                "license_note": "WORKSPACE-PRIVATE-NOTE-8821",
                "max_devices": 5,
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)
        license_key = issued["license_key"]

        status, workspace = self.call(
            "/api/v1/licenses/customer-workspace",
            method="POST",
            payload={"license_key": license_key, "app_version": "2026.07.14.2"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(workspace["workspace_schema_version"], 4)
        self.assertTrue(workspace["does_not_activate"])
        self.assertTrue(workspace["cannot_control_customer_pc"])
        self.assertEqual(workspace["summary"]["plan"]["rank"], 5)
        self.assertEqual(workspace["summary"]["device_usage"]["active"], 0)
        self.assertEqual(workspace["rank_tools"]["unlocked_count"], 25)
        self.assertEqual(workspace["action_center"]["count"], 9)
        self.assertEqual(
            sum(workspace["action_center"]["counts"].values()),
            workspace["action_center"]["count"],
        )
        self.assertEqual(len(workspace["quick_links"]), 17)
        self.assertTrue(any(item["path"] == "/decision" for item in workspace["quick_links"]))
        self.assertTrue(any(item["path"] == "/QNA" for item in workspace["quick_links"]))
        self.assertTrue(any(item["path"] == "/maintenance" for item in workspace["quick_links"]))
        self.assertTrue(any(item["path"] == "/retention" for item in workspace["quick_links"]))
        self.assertTrue(any(item["path"] == "/data-control" for item in workspace["quick_links"]))
        self.assertTrue(any(item["path"] == "/recovery-kit" for item in workspace["quick_links"]))
        self.assertTrue(any(item["path"] == "/backup-verification" for item in workspace["quick_links"]))
        self.assertTrue(any(item["path"] == "/recovery-drills" for item in workspace["quick_links"]))
        self.assertTrue(any(item["path"] == "/incident-response" for item in workspace["quick_links"]))
        self.assertTrue(any(item["path"] == "/diagnostics" for item in workspace["quick_links"]))
        self.assertTrue(any(item["path"] == "/trust" for item in workspace["quick_links"]))
        self.assertEqual(len(workspace["support_categories"]), 6)
        self.assertGreaterEqual(workspace["workspace_score"]["score"], 0)
        self.assertLessEqual(workspace["workspace_score"]["score"], 100)
        self.assertEqual(workspace["workspace_score"]["maximum"], 100)
        self.assertEqual(len(workspace["workspace_score"]["factors"]), 6)
        self.assertEqual(set(workspace["success_plan"]), {"today", "this_week", "this_month"})
        self.assertEqual(
            sum(len(items) for items in workspace["success_plan"].values()),
            workspace["action_center"]["count"],
        )
        self.assertEqual(workspace["benefit_map"]["current_rank"]["rank"], 5)
        self.assertGreater(workspace["benefit_map"]["unlocked_count"], 0)
        self.assertIsNotNone(workspace["benefit_map"]["next_rank"])
        self.assertFalse(workspace["support_pack"]["attachments_included"])
        self.assertTrue(workspace["support_pack"]["safe_to_share_after_review"])
        self.assertEqual(len(workspace["recovery_card"]["steps"]), 8)
        self.assertFalse(workspace["recovery_card"]["contains_key_material"])
        self.assertFalse(workspace["recovery_card"]["contains_customer_identity"])
        self.assertEqual(workspace["next_best_action"]["position"], 1)
        self.assertEqual(workspace["next_best_action"]["total_actions"], workspace["action_center"]["count"])
        self.assertEqual(len(workspace["readiness_lanes"]), 4)
        self.assertEqual(sum(item["maximum"] for item in workspace["readiness_lanes"]), 100)
        self.assertEqual(len(workspace["weekly_routine"]["items"]), 7)
        self.assertEqual(len(workspace["help_center"]["items"]), 6)
        self.assertTrue(workspace["help_center"]["free_text_not_included"])
        self.assertEqual(len(workspace["privacy_guarantees"]), 6)
        self.assertEqual(workspace["customer_snapshot"]["weekly_step_count"], 7)
        self.assertEqual(
            sum(item["count"] for item in workspace["entitlement_categories"]),
            workspace["benefit_map"]["unlocked_count"],
        )
        self.assertEqual(len(workspace["journey_map"]["stages"]), 5)
        self.assertFalse(workspace["journey_map"]["server_tracks_completion"])
        self.assertEqual(workspace["seat_planner"]["active"], 0)
        self.assertEqual(workspace["seat_planner"]["available"], 5)
        self.assertFalse(workspace["seat_planner"]["device_identity_included"])
        self.assertTrue(workspace["seat_planner"]["does_not_reserve_or_activate"])
        self.assertEqual(workspace["support_readiness"]["total"], 5)
        self.assertEqual(len(workspace["support_readiness"]["items"]), 5)
        self.assertEqual(len(workspace["ninety_day_plan"]["phases"]), 4)
        self.assertEqual(len(workspace["customer_glossary"]), 10)
        self.assertFalse(workspace["change_digest"]["changes_customer_pc"])
        self.assertEqual(workspace["customer_snapshot"]["journey_stage_count"], 5)
        self.assertEqual(workspace["customer_snapshot"]["glossary_term_count"], 10)
        self.assertEqual(api.active_device_count(issued["license"]["license_id"]), 0)
        serialized_workspace = json.dumps(workspace)
        for private_value in (
            "WORKSPACE-PRIVATE-CUSTOMER-8821",
            "workspace-8821@example.test",
            "WORKSPACE-PRIVATE-NOTE-8821",
            issued["license"]["license_id"],
            license_key,
        ):
            self.assertNotIn(private_value, serialized_workspace)

        status, rejected = self.call(
            "/api/v1/licenses/customer-workspace",
            method="POST",
            payload={"license_key": license_key, "upload_files": True},
        )
        self.assertEqual(status, 400)
        self.assertEqual(rejected["error"], "bad_request")

        status, rejected = self.call(
            "/api/v1/licenses/customer-workspace",
            method="POST",
            payload={"license_key": license_key, "app_version": "C:/private/customer-file.txt"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(rejected["error"], "bad_request")

        status, _headers, page = self.call_bytes("/workspace")
        self.assertEqual(status, 200)
        workspace_page = page.decode("utf-8")
        self.assertIn("VaultLink Customer Workspace", workspace_page)
        self.assertIn("/api/v1/licenses/customer-workspace", workspace_page)
        self.assertIn("LOAD WORKSPACE", workspace_page)
        self.assertIn("Priority Action Plan", workspace_page)
        self.assertIn("EXPORT SAFE JSON", workspace_page)
        self.assertIn("EXPORT SUPPORT PACK", workspace_page)
        self.assertIn("EXPORT RECOVERY CARD", workspace_page)
        self.assertIn("30-Day Success Plan", workspace_page)
        self.assertIn("Benefit Map", workspace_page)
        self.assertNotIn("localStorage", workspace_page)

        status, denied = self.call("/api/v1/admin/customer-experience")
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")
        status, experience = self.call(
            "/api/v1/admin/customer-experience",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(experience["experience_schema_version"], 2)
        self.assertEqual(len(experience["rank_coverage"]), 7)
        self.assertEqual(len(experience["customer_surfaces"]), 18)
        self.assertTrue(any(item["path"] == "/decision" for item in experience["customer_surfaces"]))
        self.assertTrue(any(item["path"] == "/QNA" for item in experience["customer_surfaces"]))
        self.assertTrue(any(item["path"] == "/maintenance" for item in experience["customer_surfaces"]))
        self.assertTrue(any(item["path"] == "/retention" for item in experience["customer_surfaces"]))
        self.assertTrue(any(item["path"] == "/data-control" for item in experience["customer_surfaces"]))
        self.assertTrue(any(item["path"] == "/recovery-kit" for item in experience["customer_surfaces"]))
        self.assertTrue(any(item["path"] == "/backup-verification" for item in experience["customer_surfaces"]))
        self.assertTrue(any(item["path"] == "/recovery-drills" for item in experience["customer_surfaces"]))
        self.assertEqual(len(experience["actions"]), 8)
        self.assertEqual(experience["metrics"]["total_licenses"], 1)
        self.assertGreaterEqual(experience["experience_score"]["score"], 0)
        self.assertLessEqual(experience["experience_score"]["score"], 100)
        self.assertEqual(len(experience["customer_journey"]), 5)
        self.assertEqual(
            set(experience["renewal_health"]),
            {"expiring_7_days", "expiring_30_days", "no_expiration", "expired"},
        )
        self.assertEqual(experience["surface_summary"]["total"], 18)
        serialized_experience = json.dumps(experience)
        for private_value in (
            "WORKSPACE-PRIVATE-CUSTOMER-8821",
            "workspace-8821@example.test",
            "WORKSPACE-PRIVATE-NOTE-8821",
            issued["license"]["license_id"],
            license_key,
        ):
            self.assertNotIn(private_value, serialized_experience)

        status, _headers, owner_page = self.call_bytes("/owner/customers")
        self.assertEqual(status, 200)
        owner_text = owner_page.decode("utf-8")
        self.assertIn("Customer Experience Console", owner_text)
        self.assertIn("/api/v1/admin/customer-experience", owner_text)
        self.assertIn("EXPORT RANK CSV", owner_text)
        self.assertIn("EXPORT JOURNEY CSV", owner_text)
        self.assertIn("Customer Journey", owner_text)
        self.assertIn("Renewal Health", owner_text)

    def test_customer_answers_are_fixed_searchable_and_collect_nothing(self):
        status, payload = self.call("/api/v1/customer-answers")
        self.assertEqual(status, 200)
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["api_version"], "0.68.0")
        self.assertEqual(payload["category_count"], 6)
        self.assertEqual(payload["count"], 30)
        self.assertEqual(set(payload["category_counts"].values()), {5})
        self.assertFalse(payload["accepts_customer_questions"])
        self.assertFalse(payload["collects_customer_data"])
        self.assertEqual(payload["search_storage"], "current_browser_tab_only")
        self.assertEqual(payload["saved_answer_storage"], "current_browser_tab_only")

        category_ids = {item["id"] for item in payload["categories"]}
        answer_ids = [item["id"] for item in payload["items"]]
        self.assertEqual(len(answer_ids), len(set(answer_ids)))
        allowed_paths = {
            "/backup-verification",
            "/customer",
            "/data-control",
            "/diagnostics",
            "/incident-response",
            "/maintenance",
            "/readiness",
            "/recovery-kit",
            "/retention",
            "/shop",
            "/status",
            "/trust",
            "/update",
        }
        for item in payload["items"]:
            self.assertEqual(
                set(item),
                {
                    "id",
                    "category_id",
                    "question",
                    "answer",
                    "steps",
                    "target_path",
                    "target_label",
                    "tags",
                },
            )
            self.assertIn(item["category_id"], category_ids)
            self.assertIn(item["target_path"], allowed_paths)
            self.assertGreaterEqual(len(item["steps"]), 3)
            self.assertTrue(item["question"].endswith("?"))
            self.assertTrue(item["answer"])

        for path in ("/QNA", "/qna", "/answers"):
            page_status, headers, page = self.call_bytes(path)
            self.assertEqual(page_status, 200)
            self.assertIn("text/html", headers["Content-Type"])
            page_text = page.decode("utf-8")
            self.assertIn("VaultLink Customer Answers", page_text)
            self.assertIn("/api/v1/customer-answers", page_text)
            self.assertIn("Search customer answers", page_text)
            self.assertIn("SAVED ONLY", page_text)
            self.assertIn("EXPORT SAVED PACK", page_text)
            self.assertIn("PRINT VISIBLE", page_text)
            self.assertIn("this browser tab", page_text)
            self.assertNotIn("localStorage", page_text)
            self.assertNotIn("sessionStorage", page_text)

        health_status, health = self.call("/health")
        self.assertEqual(health_status, 200)
        self.assertTrue(health["customer_answers_enabled"])

    def test_customer_decision_wizard_has_complete_fixed_branches_and_collects_nothing(self):
        status, payload = self.call("/api/v1/customer-decisions")
        self.assertEqual(status, 200)
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["api_version"], "0.68.0")
        self.assertEqual(payload["scenario_count"], 10)
        self.assertEqual(payload["decision_count"], 30)
        self.assertEqual(payload["outcome_count"], 40)
        self.assertEqual(payload["choice_storage"], "current_browser_tab_only")
        self.assertFalse(payload["accepts_free_form_input"])
        self.assertFalse(payload["collects_customer_data"])
        self.assertFalse(payload["controls_customer_pc"])

        scenarios = payload["scenarios"]
        nodes = payload["nodes"]
        outcomes = payload["outcomes"]
        scenario_ids = {item["id"] for item in scenarios}
        node_map = {item["id"]: item for item in nodes}
        outcome_map = {item["id"]: item for item in outcomes}
        self.assertEqual(len(scenario_ids), 10)
        self.assertEqual(len(node_map), 30)
        self.assertEqual(len(outcome_map), 40)
        self.assertEqual(sum(len(item["steps"]) for item in outcomes), 160)

        allowed_paths = {
            "/QNA",
            "/backup-verification",
            "/customer",
            "/diagnostics",
            "/incident-response",
            "/maintenance",
            "/readiness",
            "/recovery-drills",
            "/recovery-kit",
            "/retention",
            "/status",
            "/trust",
            "/update",
        }
        for scenario in scenarios:
            self.assertEqual(
                set(scenario),
                {"id", "title", "summary", "start_node_id", "max_decisions"},
            )
            self.assertEqual(scenario["max_decisions"], 3)
            self.assertIn(scenario["start_node_id"], node_map)
            self.assertEqual(
                sum(item["scenario_id"] == scenario["id"] for item in nodes),
                3,
            )
            self.assertEqual(
                sum(item["scenario_id"] == scenario["id"] for item in outcomes),
                4,
            )

        for node in nodes:
            self.assertEqual(
                set(node),
                {"id", "scenario_id", "question", "explanation", "yes", "no"},
            )
            self.assertIn(node["scenario_id"], scenario_ids)
            self.assertTrue(node["question"].endswith("?"))
            for answer in ("yes", "no"):
                target = node[answer]
                self.assertEqual(set(target), {"target_type", "target_id"})
                self.assertIn(target["target_type"], {"node", "outcome"})
                target_map = node_map if target["target_type"] == "node" else outcome_map
                self.assertIn(target["target_id"], target_map)

        for outcome in outcomes:
            self.assertEqual(
                set(outcome),
                {
                    "id",
                    "scenario_id",
                    "title",
                    "priority",
                    "summary",
                    "steps",
                    "target_path",
                    "target_label",
                    "warning",
                },
            )
            self.assertIn(outcome["scenario_id"], scenario_ids)
            self.assertIn(outcome["priority"], {"normal", "watch", "urgent"})
            self.assertEqual(len(outcome["steps"]), 4)
            self.assertIn(outcome["target_path"], allowed_paths)
            self.assertTrue(outcome["warning"])

        reached_nodes = set()
        reached_outcomes = set()

        def walk(target_type, target_id):
            if target_type == "outcome":
                reached_outcomes.add(target_id)
                return
            if target_id in reached_nodes:
                return
            reached_nodes.add(target_id)
            node = node_map[target_id]
            walk(node["yes"]["target_type"], node["yes"]["target_id"])
            walk(node["no"]["target_type"], node["no"]["target_id"])

        for scenario in scenarios:
            walk("node", scenario["start_node_id"])
        self.assertEqual(reached_nodes, set(node_map))
        self.assertEqual(reached_outcomes, set(outcome_map))

        for path in ("/decision", "/wizard"):
            page_status, headers, page = self.call_bytes(path)
            self.assertEqual(page_status, 200)
            self.assertIn("text/html", headers["Content-Type"])
            page_text = page.decode("utf-8")
            self.assertIn("VaultLink Recovery Decision Wizard", page_text)
            self.assertIn("/api/v1/customer-decisions", page_text)
            self.assertIn("BACK ONE ANSWER", page_text)
            self.assertIn("EXPORT ACTION PLAN", page_text)
            self.assertIn("current browser tab", page_text)
            self.assertNotIn("localStorage", page_text)
            self.assertNotIn("sessionStorage", page_text)
            self.assertNotIn("<input", page_text)

        health_status, health = self.call("/health")
        self.assertEqual(health_status, 200)
        self.assertTrue(health["customer_decision_wizard_enabled"])

    def test_public_and_owner_trust_centers_are_scored_private_and_protected(self):
        manifest, _package = self.publish_test_update()
        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={
                "plan_id": "personal-plus",
                "customer_label": "TRUST-PRIVATE-CUSTOMER-4401",
                "customer_email": "trust-4401@example.test",
                "license_note": "TRUST-PRIVATE-NOTE-4401",
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)

        status, public = self.call("/api/v1/trust-center")
        self.assertEqual(status, 200)
        self.assertEqual(public["trust_schema_version"], 1)
        self.assertEqual(public["score"]["maximum"], 100)
        self.assertEqual(len(public["checks"]), 10)
        self.assertTrue(public["safe_to_export"])
        self.assertFalse(public["customer_records_included"])
        self.assertTrue(public["signed_release"]["ready"])
        self.assertEqual(public["signed_release"]["version"], manifest["version"])
        self.assertEqual(public["signed_release"]["checks"]["ed25519_signature"], "passed")
        self.assertEqual(public["signed_release"]["checks"]["package_sha256"], "passed")
        self.assertEqual(len(public["data_boundaries"]), 3)
        self.assertEqual(len(public["cryptography"]), 4)
        self.assertEqual(len(public["recovery_steps"]), 5)
        public_text = json.dumps(public)
        for private_value in (
            "TRUST-PRIVATE-CUSTOMER-4401",
            "trust-4401@example.test",
            "TRUST-PRIVATE-NOTE-4401",
            issued["license"]["license_id"],
            issued["license_key"],
            TEST_ADMIN_TOKEN,
            TEST_SIGNING_SECRET,
        ):
            self.assertNotIn(private_value, public_text)

        status, headers, page = self.call_bytes("/trust")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        page_text = page.decode("utf-8")
        self.assertIn("VaultLink Trust Center", page_text)
        self.assertIn("/api/v1/trust-center", page_text)
        self.assertIn("EXPORT SAFE JSON", page_text)
        self.assertIn("Data Boundaries", page_text)
        self.assertNotIn("localStorage", page_text)

        status, denied = self.call("/api/v1/admin/trust-center")
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")
        status, owner = self.call(
            "/api/v1/admin/trust-center",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(owner["trust_schema_version"], 1)
        self.assertEqual(owner["score"]["maximum"], 100)
        self.assertEqual(len(owner["checks"]), 14)
        self.assertEqual(owner["score"]["total"], 14)
        self.assertEqual(
            owner["score"]["passed"] + len(owner["actions"]),
            owner["score"]["total"],
        )
        self.assertGreaterEqual(len(owner["category_summary"]), 6)
        owner_text = json.dumps(owner)
        for private_value in (
            "TRUST-PRIVATE-CUSTOMER-4401",
            "trust-4401@example.test",
            "TRUST-PRIVATE-NOTE-4401",
            issued["license"]["license_id"],
            issued["license_key"],
            TEST_ADMIN_TOKEN,
            TEST_SIGNING_SECRET,
        ):
            self.assertNotIn(private_value, owner_text)

        status, _headers, owner_page = self.call_bytes("/owner/trust")
        self.assertEqual(status, 200)
        owner_page_text = owner_page.decode("utf-8")
        self.assertIn("VaultLink Trust Operations", owner_page_text)
        self.assertIn("/api/v1/admin/trust-center", owner_page_text)
        self.assertIn("EXPORT SAFE JSON", owner_page_text)
        self.assertIn("Required Owner Actions", owner_page_text)
        self.assertNotIn("localStorage", owner_page_text)

        status, health = self.call("/health")
        self.assertEqual(status, 200)
        self.assertTrue(health["public_trust_center_enabled"])
        self.assertTrue(health["owner_trust_center_enabled"])
        status, product = self.call("/api/v1/product")
        self.assertEqual(status, 200)
        self.assertIn("trust_recovery_center.py", product["desktop_scripts"])
        status, plans = self.call("/api/v1/plans")
        self.assertEqual(status, 200)
        starter = next(item for item in plans["items"] if item["id"] == "starter")
        self.assertIn("trust-recovery-center", starter["entitlements"])

    def test_public_diagnostics_guide_is_fixed_private_and_session_only(self):
        manifest, _package = self.publish_test_update()
        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={
                "plan_id": "starter",
                "customer_label": "DIAGNOSTICS-PRIVATE-CUSTOMER-8821",
                "customer_email": "diagnostics-8821@example.test",
                "license_note": "DIAGNOSTICS-PRIVATE-NOTE-8821",
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)

        status, guide = self.call("/api/v1/diagnostics-guide")
        self.assertEqual(status, 200)
        self.assertEqual(guide["diagnostics_schema_version"], 1)
        self.assertEqual(guide["category_count"], 8)
        self.assertEqual(guide["step_count"], 40)
        self.assertEqual(len(guide["categories"]), 8)
        self.assertTrue(all(len(category["steps"]) == 5 for category in guide["categories"]))
        self.assertEqual(
            {category["id"] for category in guide["categories"]},
            {
                "app-start",
                "usb-key",
                "unlock",
                "licensing",
                "updates",
                "performance",
                "audit-security",
                "backup-recovery",
            },
        )
        self.assertFalse(guide["accepts_free_text"])
        self.assertFalse(guide["accepts_files"])
        self.assertEqual(guide["session_progress_storage"], "current_browser_tab_only")
        self.assertFalse(guide["customer_records_included"])
        self.assertTrue(guide["signed_release"]["ready"])
        self.assertEqual(guide["signed_release"]["version"], manifest["version"])
        serialized = json.dumps(guide)
        for private_value in (
            "DIAGNOSTICS-PRIVATE-CUSTOMER-8821",
            "diagnostics-8821@example.test",
            "DIAGNOSTICS-PRIVATE-NOTE-8821",
            issued["license"]["license_id"],
            issued["license_key"],
            TEST_ADMIN_TOKEN,
            TEST_SIGNING_SECRET,
        ):
            self.assertNotIn(private_value, serialized)

        status, headers, page = self.call_bytes("/diagnostics")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        page_text = page.decode("utf-8")
        self.assertIn("VaultLink Diagnostics Center", page_text)
        self.assertIn("/api/v1/diagnostics-guide", page_text)
        self.assertIn("Guided troubleshooting", page_text)
        self.assertIn("EXPORT SAFE JSON", page_text)
        self.assertIn("this browser tab", page_text)
        self.assertNotIn("localStorage", page_text)
        self.assertNotIn("sessionStorage", page_text)
        status, _headers, favicon = self.call_bytes("/favicon.ico")
        self.assertEqual(status, 204)
        self.assertEqual(favicon, b"")

        status, health = self.call("/health")
        self.assertEqual(status, 200)
        self.assertTrue(health["diagnostics_center_enabled"])
        status, product = self.call("/api/v1/product")
        self.assertEqual(status, 200)
        self.assertIn("diagnostics_center.py", product["desktop_scripts"])
        status, plans = self.call("/api/v1/plans")
        self.assertEqual(status, 200)
        starter = next(item for item in plans["items"] if item["id"] == "starter")
        self.assertIn("diagnostics-center", starter["entitlements"])
        status, docs = self.call("/docs")
        self.assertEqual(status, 200)
        self.assertTrue(any(item["path"] == "/diagnostics" for item in docs["routes"]))
        self.assertTrue(any(item["path"] == "/api/v1/diagnostics-guide" for item in docs["routes"]))

    def test_public_incident_guide_is_fixed_private_and_session_only(self):
        manifest, _package = self.publish_test_update()
        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={
                "plan_id": "starter",
                "customer_label": "INCIDENT-PRIVATE-CUSTOMER-9321",
                "customer_email": "incident-9321@example.test",
                "license_note": "INCIDENT-PRIVATE-NOTE-9321",
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)

        status, guide = self.call("/api/v1/incident-guide")
        self.assertEqual(status, 200)
        self.assertEqual(guide["incident_schema_version"], 1)
        self.assertEqual(guide["api_version"], api.API_VERSION)
        self.assertEqual(guide["playbook_count"], 12)
        self.assertEqual(guide["step_count"], 72)
        self.assertEqual(len(guide["playbooks"]), 12)
        self.assertTrue(all(len(playbook["steps"]) == 6 for playbook in guide["playbooks"]))
        self.assertEqual(
            {playbook["id"] for playbook in guide["playbooks"]},
            {
                "defender-alert",
                "account-risk",
                "lost-usb",
                "unlock-failure",
                "unknown-behavior",
                "update-integrity",
                "device-loss",
                "phishing-message",
                "ransomware-warning",
                "exposed-secret",
                "browser-change",
                "backup-failure",
            },
        )
        self.assertFalse(guide["accepts_free_text"])
        self.assertFalse(guide["accepts_files"])
        self.assertFalse(guide["customer_records_included"])
        self.assertEqual(guide["session_progress_storage"], "current_browser_tab_only")
        self.assertTrue(guide["signed_release"]["ready"])
        self.assertEqual(guide["signed_release"]["version"], manifest["version"])
        serialized = json.dumps(guide)
        for private_value in (
            "INCIDENT-PRIVATE-CUSTOMER-9321",
            "incident-9321@example.test",
            "INCIDENT-PRIVATE-NOTE-9321",
            issued["license"]["license_id"],
            issued["license_key"],
            TEST_ADMIN_TOKEN,
            TEST_SIGNING_SECRET,
        ):
            self.assertNotIn(private_value, serialized)

        status, headers, page = self.call_bytes("/incident-response")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        page_text = page.decode("utf-8")
        self.assertIn("VaultLink Incident Response", page_text)
        self.assertIn("/api/v1/incident-guide", page_text)
        self.assertIn("Respond without exposing secrets", page_text)
        self.assertIn("EXPORT SAFE JSON", page_text)
        self.assertIn("COPY NEXT STEP", page_text)
        self.assertIn("PRINT CHECKLIST", page_text)
        self.assertIn("current tab", page_text)
        self.assertNotIn("localStorage", page_text)
        self.assertNotIn("sessionStorage", page_text)

        status, health = self.call("/health")
        self.assertEqual(status, 200)
        self.assertTrue(health["incident_response_center_enabled"])
        status, product = self.call("/api/v1/product")
        self.assertEqual(status, 200)
        self.assertIn("incident_response_center.py", product["desktop_scripts"])
        status, plans = self.call("/api/v1/plans")
        self.assertEqual(status, 200)
        starter = next(item for item in plans["items"] if item["id"] == "starter")
        self.assertIn("incident-response-center", starter["entitlements"])
        status, docs = self.call("/docs")
        self.assertEqual(status, 200)
        self.assertTrue(any(item["path"] == "/incident-response" for item in docs["routes"]))
        self.assertTrue(any(item["path"] == "/api/v1/incident-guide" for item in docs["routes"]))

    def test_public_recovery_drills_are_fixed_private_and_current_tab_only(self):
        manifest, _package = self.publish_test_update()
        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={
                "plan_id": "starter",
                "customer_label": "DRILL-PRIVATE-CUSTOMER-4418",
                "customer_email": "drill-4418@example.test",
                "license_note": "DRILL-PRIVATE-NOTE-4418",
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)

        status, guide = self.call("/api/v1/recovery-drills")
        self.assertEqual(status, 200)
        self.assertEqual(guide["recovery_drill_schema_version"], 1)
        self.assertEqual(guide["api_version"], api.API_VERSION)
        self.assertEqual(guide["drill_count"], 16)
        self.assertEqual(guide["step_count"], 80)
        self.assertEqual(len(guide["drills"]), 16)
        self.assertTrue(all(len(drill["steps"]) == 5 for drill in guide["drills"]))
        self.assertEqual(guide["categories"], ["Backup", "Continuity", "Evidence", "Recovery", "Security"])
        self.assertEqual(
            {drill["id"] for drill in guide["drills"]},
            {
                "key-recovery",
                "unlock-roundtrip",
                "app-data-backup",
                "locked-file-backup",
                "device-replacement",
                "update-rollback",
                "offline-continuity",
                "family-handoff",
                "owner-succession",
                "business-outage",
                "account-recovery",
                "phishing-response",
                "ransomware-isolation",
                "device-loss",
                "audit-integrity",
                "privacy-safe-support",
            },
        )
        self.assertFalse(guide["accepts_free_text"])
        self.assertFalse(guide["accepts_files"])
        self.assertFalse(guide["accepts_progress"])
        self.assertFalse(guide["customer_records_included"])
        self.assertEqual(guide["session_progress_storage"], "current_browser_tab_only")
        self.assertEqual(guide["desktop_history_storage"], "local_hash_chained_coarse_results_only")
        self.assertTrue(guide["signed_release"]["ready"])
        self.assertEqual(guide["signed_release"]["version"], manifest["version"])
        serialized = json.dumps(guide)
        for private_value in (
            "DRILL-PRIVATE-CUSTOMER-4418",
            "drill-4418@example.test",
            "DRILL-PRIVATE-NOTE-4418",
            issued["license"]["license_id"],
            issued["license_key"],
            TEST_ADMIN_TOKEN,
            TEST_SIGNING_SECRET,
        ):
            self.assertNotIn(private_value, serialized)

        status, headers, page = self.call_bytes("/recovery-drills")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        page_text = page.decode("utf-8")
        self.assertIn("VaultLink Recovery Drills", page_text)
        self.assertIn("/api/v1/recovery-drills", page_text)
        self.assertIn("Practice recovery before it matters", page_text)
        self.assertIn("MARK NEXT", page_text)
        self.assertIn("MARK ALL", page_text)
        self.assertIn("RANDOM DRILL", page_text)
        self.assertIn("COPY NEXT STEP", page_text)
        self.assertIn("EXPORT SAFE JSON", page_text)
        self.assertIn("current tab", page_text)
        self.assertNotIn("localStorage", page_text)
        self.assertNotIn("sessionStorage", page_text)
        self.assertNotIn("<textarea", page_text)

        status, health = self.call("/health")
        self.assertEqual(status, 200)
        self.assertTrue(health["recovery_drill_center_enabled"])
        status, product = self.call("/api/v1/product")
        self.assertEqual(status, 200)
        self.assertIn("recovery_drill_center.py", product["desktop_scripts"])
        status, plans = self.call("/api/v1/plans")
        self.assertEqual(status, 200)
        starter = next(item for item in plans["items"] if item["id"] == "starter")
        self.assertIn("recovery-drill-center", starter["entitlements"])
        status, docs = self.call("/docs")
        self.assertEqual(status, 200)
        self.assertTrue(any(item["path"] == "/recovery-drills" for item in docs["routes"]))
        self.assertTrue(any(item["path"] == "/api/v1/recovery-drills" for item in docs["routes"]))

    def test_public_backup_verification_is_fixed_private_and_current_tab_only(self):
        manifest, _package = self.publish_test_update()
        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={
                "plan_id": "starter",
                "customer_label": "BACKUP-PRIVATE-CUSTOMER-7741",
                "customer_email": "backup-7741@example.test",
                "license_note": "BACKUP-PRIVATE-NOTE-7741",
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)

        status, guide = self.call("/api/v1/backup-verification")
        self.assertEqual(status, 200)
        self.assertEqual(guide["backup_verification_schema_version"], 1)
        self.assertEqual(guide["api_version"], api.API_VERSION)
        self.assertEqual(guide["plan_count"], 12)
        self.assertEqual(guide["step_count"], 60)
        self.assertEqual(len(guide["plans"]), 12)
        self.assertTrue(all(len(plan["steps"]) == 5 for plan in guide["plans"]))
        self.assertEqual(
            guide["categories"],
            ["App Data", "Application", "Business", "Devices", "Keys", "Locked Data", "People", "Recovery", "Security"],
        )
        self.assertEqual(
            {plan["id"] for plan in guide["plans"]},
            {
                "master-key-copies",
                "optional-pin-custody",
                "locked-file-copies",
                "app-data-backup",
                "audit-evidence",
                "signed-app-rollback",
                "new-device-recovery",
                "lost-device-continuity",
                "family-handoff",
                "small-office-continuity",
                "ransomware-safe-backups",
                "full-restore-rehearsal",
            },
        )
        self.assertEqual(
            [item["id"] for item in guide["restore_objectives"]],
            ["15-minutes", "1-hour", "4-hours", "1-day", "3-days"],
        )
        self.assertEqual(guide["copy_targets"], [1, 2, 3, 4, 5])
        self.assertFalse(guide["accepts_free_text"])
        self.assertFalse(guide["accepts_files"])
        self.assertFalse(guide["accepts_paths"])
        self.assertFalse(guide["accepts_progress"])
        self.assertFalse(guide["customer_records_included"])
        self.assertEqual(guide["session_progress_storage"], "current_browser_tab_only")
        self.assertEqual(guide["desktop_checkpoint_storage"], "local_hash_chained_fixed_ids_and_coarse_totals_only")
        self.assertTrue(guide["signed_release"]["ready"])
        self.assertEqual(guide["signed_release"]["version"], manifest["version"])
        serialized = json.dumps(guide)
        for private_value in (
            "BACKUP-PRIVATE-CUSTOMER-7741",
            "backup-7741@example.test",
            "BACKUP-PRIVATE-NOTE-7741",
            issued["license"]["license_id"],
            issued["license_key"],
            TEST_ADMIN_TOKEN,
            TEST_SIGNING_SECRET,
        ):
            self.assertNotIn(private_value, serialized)

        status, headers, page = self.call_bytes("/backup-verification")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        page_text = page.decode("utf-8")
        self.assertIn("VaultLink Backup Verification", page_text)
        self.assertIn("/api/v1/backup-verification", page_text)
        self.assertIn("Know what restores first", page_text)
        self.assertIn("MARK NEXT", page_text)
        self.assertIn("MARK ALL", page_text)
        self.assertIn("RANDOM PLAN", page_text)
        self.assertIn("COPY RESTORE ORDER", page_text)
        self.assertIn("EXPORT SAFE JSON", page_text)
        self.assertIn('lines.join("\\n")', page_text)
        self.assertIn("current tab", page_text)
        self.assertNotIn("localStorage", page_text)
        self.assertNotIn("sessionStorage", page_text)
        self.assertNotIn("<textarea", page_text)
        self.assertNotIn('type="file"', page_text)

        status, health = self.call("/health")
        self.assertEqual(status, 200)
        self.assertTrue(health["backup_verification_center_enabled"])
        status, product = self.call("/api/v1/product")
        self.assertEqual(status, 200)
        self.assertIn("backup_verification_center.py", product["desktop_scripts"])
        status, plans = self.call("/api/v1/plans")
        self.assertEqual(status, 200)
        starter = next(item for item in plans["items"] if item["id"] == "starter")
        self.assertIn("backup-verification-center", starter["entitlements"])
        status, docs = self.call("/docs")
        self.assertEqual(status, 200)
        self.assertTrue(any(item["path"] == "/backup-verification" for item in docs["routes"]))
        self.assertTrue(any(item["path"] == "/api/v1/backup-verification" for item in docs["routes"]))

    def test_public_recovery_kit_is_fixed_private_and_current_tab_only(self):
        manifest, _package = self.publish_test_update()
        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={
                "plan_id": "starter",
                "customer_label": "KIT-PRIVATE-CUSTOMER-5512",
                "customer_email": "kit-5512@example.test",
                "license_note": "KIT-PRIVATE-NOTE-5512",
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)

        status, guide = self.call("/api/v1/recovery-kit")
        self.assertEqual(status, 200)
        self.assertEqual(guide["recovery_kit_schema_version"], 1)
        self.assertEqual(guide["api_version"], api.API_VERSION)
        self.assertEqual(guide["profile_count"], 5)
        self.assertEqual(guide["section_count"], 10)
        self.assertEqual(guide["item_count"], 50)
        self.assertEqual(guide["runbook_count"], 5)
        self.assertEqual(guide["runbook_step_count"], 30)
        self.assertTrue(all(len(section["items"]) == 5 for section in guide["sections"]))
        self.assertTrue(all(len(runbook["steps"]) == 6 for runbook in guide["runbooks"]))
        self.assertEqual(
            guide["categories"],
            ["Access", "Application", "Data", "Evidence", "People", "Recovery", "Response", "Service"],
        )
        self.assertEqual(
            {item["id"] for item in guide["profiles"]},
            {"personal-pc", "family-handoff", "travel-device", "small-office", "high-assurance"},
        )
        self.assertEqual(
            {item["id"] for item in guide["runbooks"]},
            {"replacement-pc", "lost-master-usb", "suspected-malware", "unlock-failure", "service-outage"},
        )
        self.assertEqual(guide["review_intervals"], [7, 14, 30, 60, 90])
        self.assertFalse(guide["accepts_free_text"])
        self.assertFalse(guide["accepts_files"])
        self.assertFalse(guide["accepts_paths"])
        self.assertFalse(guide["accepts_progress"])
        self.assertFalse(guide["accepts_contacts"])
        self.assertFalse(guide["customer_records_included"])
        self.assertEqual(guide["session_progress_storage"], "current_browser_tab_only")
        self.assertEqual(guide["desktop_snapshot_storage"], "local_hash_chained_fixed_ids_scores_totals_interval_and_time_only")
        self.assertTrue(guide["signed_release"]["ready"])
        self.assertEqual(guide["signed_release"]["version"], manifest["version"])
        serialized = json.dumps(guide)
        for private_value in (
            "KIT-PRIVATE-CUSTOMER-5512",
            "kit-5512@example.test",
            "KIT-PRIVATE-NOTE-5512",
            issued["license"]["license_id"],
            issued["license_key"],
            TEST_ADMIN_TOKEN,
            TEST_SIGNING_SECRET,
        ):
            self.assertNotIn(private_value, serialized)

        status, headers, page = self.call_bytes("/recovery-kit")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        page_text = page.decode("utf-8")
        self.assertIn("VaultLink Recovery Kit", page_text)
        self.assertIn("/api/v1/recovery-kit", page_text)
        self.assertIn("Prepare before the first hour", page_text)
        self.assertIn("MARK NEXT", page_text)
        self.assertIn("MARK SECTION", page_text)
        self.assertIn("RANDOM SECTION", page_text)
        self.assertIn("COPY RUNBOOK", page_text)
        self.assertIn("CALENDAR", page_text)
        self.assertIn("EXPORT SAFE JSON", page_text)
        self.assertIn('lines.join("\\n")', page_text)
        self.assertIn('join("\\r\\n")', page_text)
        self.assertIn("current browser tab", page_text)
        self.assertNotIn("localStorage", page_text)
        self.assertNotIn("sessionStorage", page_text)
        self.assertNotIn("<textarea", page_text)
        self.assertNotIn('type="file"', page_text)

        status, health = self.call("/health")
        self.assertEqual(status, 200)
        self.assertTrue(health["recovery_kit_builder_enabled"])
        status, product = self.call("/api/v1/product")
        self.assertEqual(status, 200)
        self.assertIn("recovery_kit_builder.py", product["desktop_scripts"])
        status, plans = self.call("/api/v1/plans")
        self.assertEqual(status, 200)
        starter = next(item for item in plans["items"] if item["id"] == "starter")
        self.assertIn("recovery-kit-builder", starter["entitlements"])
        status, docs = self.call("/docs")
        self.assertEqual(status, 200)
        self.assertTrue(any(item["path"] == "/recovery-kit" for item in docs["routes"]))
        self.assertTrue(any(item["path"] == "/api/v1/recovery-kit" for item in docs["routes"]))

    def test_public_maintenance_is_fixed_private_and_current_tab_only(self):
        manifest, _package = self.publish_test_update()
        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={
                "plan_id": "starter",
                "customer_label": "MAINTENANCE-PRIVATE-CUSTOMER-8241",
                "customer_email": "maintenance-8241@example.test",
                "license_note": "MAINTENANCE-PRIVATE-NOTE-8241",
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)

        status, guide = self.call("/api/v1/maintenance-guide")
        self.assertEqual(status, 200)
        self.assertTrue(guide["ok"])
        self.assertEqual(guide["maintenance_schema_version"], 2)
        self.assertEqual(guide["api_version"], api.API_VERSION)
        self.assertEqual(guide["category_count"], 8)
        self.assertEqual(guide["task_count"], 32)
        self.assertEqual(guide["routine_count"], 6)
        self.assertEqual(guide["planning_horizon_count"], 4)
        self.assertEqual(guide["cadence_days"], [7, 14, 30, 60, 90])
        self.assertEqual(len(guide["categories"]), 8)
        self.assertEqual(len(guide["tasks"]), 32)
        self.assertEqual(len(guide["routines"]), 6)
        self.assertEqual(
            guide["planning_horizons"],
            [
                {"id": "all", "label": "All cadence", "maximum_cadence_days": 0},
                {"id": "weekly", "label": "Weekly focus", "maximum_cadence_days": 7},
                {"id": "monthly", "label": "Thirty-day focus", "maximum_cadence_days": 30},
                {"id": "quarterly", "label": "Ninety-day focus", "maximum_cadence_days": 90},
            ],
        )
        self.assertEqual(
            guide["schedule_scoring"],
            {
                "purpose": "reminder_coverage_only",
                "weights": {"current": 100, "due-soon": 65, "overdue": 15, "not-started": 0},
                "minimum": 0,
                "maximum": 100,
                "security_health_claim": False,
            },
        )
        self.assertEqual(len({item["id"] for item in guide["categories"]}), 8)
        self.assertEqual(len({item["id"] for item in guide["tasks"]}), 32)
        self.assertEqual(len({item["id"] for item in guide["routines"]}), 6)
        category_ids = {item["id"] for item in guide["categories"]}
        task_ids = {item["id"] for item in guide["tasks"]}
        for category_id in category_ids:
            self.assertEqual(sum(item["category_id"] == category_id for item in guide["tasks"]), 4)
        self.assertTrue(all(item["category_id"] in category_ids for item in guide["tasks"]))
        self.assertTrue(all(item["cadence_days"] in guide["cadence_days"] for item in guide["tasks"]))
        self.assertTrue(all(set(item["task_ids"]).issubset(task_ids) for item in guide["routines"]))
        full = next(item for item in guide["routines"] if item["id"] == "full-maintenance")
        self.assertEqual(set(full["task_ids"]), task_ids)
        self.assertEqual(guide["browser_receipt_field_count"], 16)
        self.assertEqual(
            set(guide["browser_receipt_fields"]),
            {
                "schema_version",
                "report_type",
                "generated_at_utc",
                "api_version",
                "service_mode",
                "signed_desktop_version",
                "selected_category_id",
                "selected_routine_id",
                "selected_horizon_id",
                "reviewed_task_ids",
                "reviewed_count",
                "task_count",
                "review_percent",
                "reviewed_category_count",
                "reviewed_routine_count",
                "privacy_notice",
            },
        )
        for field in (
            "accepts_free_text",
            "accepts_files",
            "accepts_paths",
            "accepts_progress",
            "accepts_local_results",
            "accepts_completion_history",
            "accepts_reminders",
            "accepts_snapshots",
            "accepts_schedule_scores",
            "accepts_maintenance_commands",
            "remote_maintenance_allowed",
            "customer_records_included",
        ):
            self.assertFalse(guide[field])
        self.assertEqual(guide["progress_storage"], "current_browser_tab_only")
        self.assertEqual(len(guide["privacy_boundaries"]), 4)
        self.assertEqual(len(guide["limitations"]), 4)
        self.assertTrue(guide["signed_release"]["ready"])
        self.assertEqual(guide["signed_release"]["version"], manifest["version"])
        serialized = json.dumps(guide)
        for private_value in (
            "MAINTENANCE-PRIVATE-CUSTOMER-8241",
            "maintenance-8241@example.test",
            "MAINTENANCE-PRIVATE-NOTE-8241",
            issued["license"]["license_id"],
            issued["license_key"],
            TEST_ADMIN_TOKEN,
            TEST_SIGNING_SECRET,
        ):
            self.assertNotIn(private_value, serialized)

        status, headers, page = self.call_bytes("/maintenance")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        page_text = page.decode("utf-8")
        self.assertIn("VaultLink Security Maintenance", page_text)
        self.assertIn("/api/v1/maintenance-guide", page_text)
        self.assertIn("REVIEW NEXT", page_text)
        self.assertIn("REVIEW PRIORITY 5", page_text)
        self.assertIn("REVIEW ROUTINE", page_text)
        self.assertIn("REVIEW VISIBLE", page_text)
        self.assertIn("CALENDAR", page_text)
        self.assertIn("EXPORT JSON", page_text)
        self.assertIn('id="horizon"', page_text)
        self.assertIn('id="categoryCoverage"', page_text)
        self.assertIn('id="routineCoverage"', page_text)
        self.assertIn('id="priorityQueue"', page_text)
        self.assertIn("vaultlink-browser-maintenance-review.json", page_text)
        self.assertIn("vaultlink-maintenance-plan.ics", page_text)
        self.assertIn("current tab", page_text)
        self.assertNotIn("localStorage", page_text)
        self.assertNotIn("sessionStorage", page_text)
        self.assertNotIn("<textarea", page_text)
        self.assertNotIn('type="file"', page_text)

        status, health = self.call("/health")
        self.assertEqual(status, 200)
        self.assertTrue(health["security_maintenance_center_enabled"])
        status, product = self.call("/api/v1/product")
        self.assertEqual(status, 200)
        self.assertIn("security_maintenance_center.py", product["desktop_scripts"])
        status, features = self.call("/api/v1/features")
        self.assertEqual(status, 200)
        self.assertTrue(any(item["id"] == "security-maintenance-center" for item in features["items"]))
        status, companions = self.call("/api/v1/companions")
        self.assertEqual(status, 200)
        self.assertTrue(any(item["script"] == "security_maintenance_center.py" for item in companions["items"]))
        status, plans = self.call("/api/v1/plans")
        self.assertEqual(status, 200)
        starter = next(item for item in plans["items"] if item["id"] == "starter")
        self.assertIn("security-maintenance-center", starter["entitlements"])
        status, docs = self.call("/docs")
        self.assertEqual(status, 200)
        self.assertTrue(any(item["path"] == "/maintenance" for item in docs["routes"]))
        self.assertTrue(any(item["path"] == "/api/v1/maintenance-guide" for item in docs["routes"]))
        self.assertTrue(
            {
                "maintenance_center_open",
                "maintenance_center_refresh",
                "maintenance_task_complete",
                "maintenance_task_reopen",
                "maintenance_routine_complete",
                "maintenance_history_export",
                "maintenance_calendar_export",
                "maintenance_summary_copy",
                "maintenance_online_open",
                "maintenance_report_export",
                "maintenance_trusted_tool_open",
                "maintenance_snapshot_save",
                "maintenance_snapshot_compare",
                "maintenance_archive_export",
            }.issubset(api.ALLOWED_AUDIT_ACTIONS)
        )

    def test_public_retention_is_fixed_private_and_current_tab_only(self):
        manifest, _package = self.publish_test_update()
        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={
                "plan_id": "starter",
                "customer_label": "RETENTION-PRIVATE-CUSTOMER-6621",
                "customer_email": "retention-6621@example.test",
                "license_note": "RETENTION-PRIVATE-NOTE-6621",
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)

        status, guide = self.call("/api/v1/retention-guide")
        self.assertEqual(status, 200)
        self.assertTrue(guide["ok"])
        self.assertEqual(guide["retention_schema_version"], 1)
        self.assertEqual(guide["api_version"], api.API_VERSION)
        self.assertEqual(guide["area_count"], 8)
        self.assertEqual(guide["policy_count"], 5)
        self.assertEqual(guide["practice_count"], 10)
        self.assertEqual(guide["cleanup_step_count"], 5)
        self.assertEqual(len(guide["areas"]), 8)
        self.assertEqual(len(guide["policies"]), 5)
        self.assertEqual(len(guide["practices"]), 10)
        self.assertEqual(len(guide["cleanup_flow"]), 5)
        self.assertEqual(len({item["id"] for item in guide["areas"]}), 8)
        self.assertEqual(len({item["id"] for item in guide["practices"]}), 10)
        self.assertEqual(
            {item["id"] for item in guide["policies"]},
            {"cleanup-eligible", "preserve", "source-center-only", "owner-only", "not-inventoried"},
        )
        self.assertEqual(guide["browser_receipt_field_count"], 11)
        self.assertEqual(
            set(guide["browser_receipt_fields"]),
            {
                "schema_version",
                "report_type",
                "generated_at_utc",
                "api_version",
                "service_mode",
                "signed_desktop_version",
                "selected_policy",
                "reviewed_practice_ids",
                "reviewed_count",
                "practice_count",
                "privacy_notice",
            },
        )
        for field in (
            "accepts_free_text",
            "accepts_files",
            "accepts_paths",
            "accepts_inventory",
            "accepts_progress",
            "accepts_cleanup_commands",
            "accepts_local_results",
            "remote_cleanup_allowed",
            "customer_records_included",
        ):
            self.assertFalse(guide[field])
        self.assertEqual(guide["progress_storage"], "current_browser_tab_only")
        self.assertEqual(len(guide["privacy_boundaries"]), 4)
        self.assertEqual(len(guide["limitations"]), 3)
        self.assertTrue(guide["signed_release"]["ready"])
        self.assertEqual(guide["signed_release"]["version"], manifest["version"])
        serialized = json.dumps(guide)
        for private_value in (
            "RETENTION-PRIVATE-CUSTOMER-6621",
            "retention-6621@example.test",
            "RETENTION-PRIVATE-NOTE-6621",
            issued["license"]["license_id"],
            issued["license_key"],
            TEST_ADMIN_TOKEN,
            TEST_SIGNING_SECRET,
        ):
            self.assertNotIn(private_value, serialized)

        status, headers, page = self.call_bytes("/retention")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        page_text = page.decode("utf-8")
        self.assertIn("VaultLink Storage & Retention", page_text)
        self.assertIn("/api/v1/retention-guide", page_text)
        self.assertIn("REVIEW NEXT", page_text)
        self.assertIn("REVIEW ALL", page_text)
        self.assertIn("COPY PLAN", page_text)
        self.assertIn("EXPORT SAFE JSON", page_text)
        self.assertIn("vaultlink-browser-retention-review.json", page_text)
        self.assertIn("current tab", page_text)
        self.assertNotIn("localStorage", page_text)
        self.assertNotIn("sessionStorage", page_text)
        self.assertNotIn("<textarea", page_text)
        self.assertNotIn('type="file"', page_text)

        status, health = self.call("/health")
        self.assertEqual(status, 200)
        self.assertTrue(health["storage_retention_center_enabled"])
        status, product = self.call("/api/v1/product")
        self.assertEqual(status, 200)
        self.assertIn("storage_retention_center.py", product["desktop_scripts"])
        status, features = self.call("/api/v1/features")
        self.assertEqual(status, 200)
        self.assertTrue(any(item["id"] == "storage-retention-center" for item in features["items"]))
        status, companions = self.call("/api/v1/companions")
        self.assertEqual(status, 200)
        self.assertTrue(any(item["script"] == "storage_retention_center.py" for item in companions["items"]))
        status, plans = self.call("/api/v1/plans")
        self.assertEqual(status, 200)
        starter = next(item for item in plans["items"] if item["id"] == "starter")
        self.assertIn("storage-retention-center", starter["entitlements"])
        status, docs = self.call("/docs")
        self.assertEqual(status, 200)
        self.assertTrue(any(item["path"] == "/retention" for item in docs["routes"]))
        self.assertTrue(any(item["path"] == "/api/v1/retention-guide" for item in docs["routes"]))
        self.assertTrue(
            {
                "retention_center_open",
                "retention_center_refresh",
                "retention_temp_cleanup",
                "retention_receipt_save",
                "retention_summary_copy",
                "retention_export_json",
                "retention_export_text",
                "retention_online_open",
            }.issubset(api.ALLOWED_AUDIT_ACTIONS)
        )

    def test_public_data_control_is_fixed_private_and_current_tab_only(self):
        manifest, _package = self.publish_test_update()
        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={
                "plan_id": "starter",
                "customer_label": "DATA-PRIVATE-CUSTOMER-7781",
                "customer_email": "data-7781@example.test",
                "license_note": "DATA-PRIVATE-NOTE-7781",
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)

        status, data_map = self.call("/api/v1/data-map")
        self.assertEqual(status, 200)
        self.assertTrue(data_map["ok"])
        self.assertEqual(data_map["data_control_schema_version"], 1)
        self.assertEqual(data_map["api_version"], api.API_VERSION)
        self.assertEqual(data_map["scope_count"], 5)
        self.assertEqual(data_map["class_count"], 14)
        self.assertEqual(data_map["flow_step_count"], 6)
        self.assertEqual(len(data_map["scopes"]), 5)
        self.assertEqual(len(data_map["data_classes"]), 14)
        self.assertEqual(len(data_map["flow_steps"]), 6)
        self.assertEqual(len({item["id"] for item in data_map["scopes"]}), 5)
        self.assertEqual(len({item["id"] for item in data_map["data_classes"]}), 14)
        self.assertTrue(
            all(item["scope_id"] in {scope["id"] for scope in data_map["scopes"]} for item in data_map["data_classes"])
        )
        self.assertEqual(len(data_map["receipt_schema_fields"]), 11)
        for field in (
            "accepts_free_text",
            "accepts_files",
            "accepts_paths",
            "accepts_inventory",
            "accepts_progress",
            "accepts_contacts",
            "customer_records_included",
        ):
            self.assertFalse(data_map[field])
        self.assertEqual(data_map["session_progress_storage"], "current_browser_tab_only")
        self.assertEqual(data_map["desktop_inventory_boundary"], "exact_known_vaultlink_app_data_metadata_only")
        self.assertGreaterEqual(len(data_map["privacy_boundaries"]), 4)
        self.assertGreaterEqual(len(data_map["limitations"]), 3)
        self.assertTrue(data_map["signed_release"]["ready"])
        self.assertEqual(data_map["signed_release"]["version"], manifest["version"])
        serialized = json.dumps(data_map)
        for private_value in (
            "DATA-PRIVATE-CUSTOMER-7781",
            "data-7781@example.test",
            "DATA-PRIVATE-NOTE-7781",
            issued["license"]["license_id"],
            issued["license_key"],
            TEST_ADMIN_TOKEN,
            TEST_SIGNING_SECRET,
        ):
            self.assertNotIn(private_value, serialized)

        status, headers, page = self.call_bytes("/data-control")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        page_text = page.decode("utf-8")
        self.assertIn("VaultLink Data Control", page_text)
        self.assertIn("/api/v1/data-map", page_text)
        self.assertIn("REVIEW NEXT", page_text)
        self.assertIn("REVIEW VISIBLE", page_text)
        self.assertIn("COPY RECEIPT", page_text)
        self.assertIn("EXPORT SAFE JSON", page_text)
        self.assertIn("vaultlink-browser-data-map-receipt.json", page_text)
        self.assertIn("current tab", page_text)
        self.assertNotIn("localStorage", page_text)
        self.assertNotIn("sessionStorage", page_text)
        self.assertNotIn("<textarea", page_text)
        self.assertNotIn('type="file"', page_text)

        status, health = self.call("/health")
        self.assertEqual(status, 200)
        self.assertTrue(health["data_control_center_enabled"])
        status, product = self.call("/api/v1/product")
        self.assertEqual(status, 200)
        self.assertIn("local_data_control_center.py", product["desktop_scripts"])
        status, plans = self.call("/api/v1/plans")
        self.assertEqual(status, 200)
        starter = next(item for item in plans["items"] if item["id"] == "starter")
        self.assertIn("data-control-center", starter["entitlements"])
        status, docs = self.call("/docs")
        self.assertEqual(status, 200)
        self.assertTrue(any(item["path"] == "/data-control" for item in docs["routes"]))
        self.assertTrue(any(item["path"] == "/api/v1/data-map" for item in docs["routes"]))

    def test_owner_command_center_has_exactly_fifty_private_safe_insights(self):
        status, denied = self.call("/api/v1/admin/insights")
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")

        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={
                "plan_id": "personal-plus",
                "customer_label": "UNIQUE-CUSTOMER-LABEL-7392",
                "customer_email": "unique-7392@example.test",
                "license_note": "UNIQUE-OWNER-NOTE-7392",
                "max_devices": 2,
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)
        self.assertIn("license_key", issued)

        status, report = self.call(
            "/api/v1/admin/insights",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(report["count"], 50)
        self.assertEqual(len(report["items"]), 50)
        self.assertEqual(len({item["id"] for item in report["items"]}), 50)
        self.assertIn("Licensing", report["categories"])
        self.assertIn("Operations", report["categories"])
        serialized = json.dumps(report)
        self.assertNotIn("UNIQUE-CUSTOMER-LABEL-7392", serialized)
        self.assertNotIn("unique-7392@example.test", serialized)
        self.assertNotIn("UNIQUE-OWNER-NOTE-7392", serialized)
        self.assertNotIn(issued["license_key"], serialized)

        status, _headers, page = self.call_bytes("/owner/insights")
        self.assertEqual(status, 200)
        page_text = page.decode("utf-8")
        self.assertIn("Owner Command Center", page_text)
        self.assertIn("Showing 0 of 50", page_text)
        self.assertIn("EXPORT JSON", page_text)
        self.assertIn("EXPORT CSV", page_text)

    def test_owner_maintenance_operations_are_fixed_protected_and_private(self):
        self.publish_test_update()
        status, denied = self.call("/api/v1/admin/maintenance-operations")
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")

        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={
                "plan_id": "personal-plus",
                "customer_label": "OPERATIONS-PRIVATE-CUSTOMER-9017",
                "customer_email": "operations-9017@example.test",
                "license_note": "OPERATIONS-PRIVATE-NOTE-9017",
                "max_devices": 2,
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)

        status, report = self.call(
            "/api/v1/admin/maintenance-operations",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(report["operations_schema_version"], 3)
        self.assertEqual(report["api_version"], api.API_VERSION)
        self.assertEqual(report["check_count"], 40)
        self.assertEqual(len(report["checks"]), 40)
        self.assertEqual(len({item["id"] for item in report["checks"]}), 40)
        self.assertEqual(len(report["categories"]), 8)
        self.assertEqual(len(report["category_summary"]), 8)
        self.assertTrue(all(item["total"] == 5 for item in report["category_summary"]))
        self.assertTrue(all(0 <= item["score"] <= 100 for item in report["category_summary"]))
        self.assertTrue(all(str(item["owner_path"]).startswith("/") for item in report["category_summary"]))
        self.assertEqual(report["score"]["total"], 40)
        self.assertEqual(
            report["score"]["passed"] + report["score"]["actions"],
            report["score"]["total"],
        )
        self.assertEqual(report["metrics"]["total_surfaces"], 18)
        self.assertEqual(len(report["customer_surfaces"]), 18)
        self.assertEqual(len(report["storage_matrix"]), 5)
        self.assertEqual(
            set(report["severity_summary"]),
            {"complete", "critical", "high", "medium", "low"},
        )
        self.assertEqual(sum(report["severity_summary"].values()), 40)
        self.assertEqual(len(report["watch_metrics"]), 10)
        self.assertEqual(len({item["id"] for item in report["watch_metrics"]}), 10)
        self.assertEqual(len(report["review_windows"]), 4)
        self.assertTrue(all(len(item["steps"]) == 4 for item in report["review_windows"]))
        self.assertEqual(len(report["owner_shortcuts"]), 8)
        self.assertEqual(len(report["approval_gates"]), 6)
        self.assertEqual(sum(item["total"] for item in report["approval_gates"]), 40)
        gate_check_ids = [check_id for item in report["approval_gates"] for check_id in item["check_ids"]]
        self.assertEqual(len(gate_check_ids), 40)
        self.assertEqual(len(set(gate_check_ids)), 40)
        self.assertEqual(set(gate_check_ids), {item["id"] for item in report["checks"]})
        self.assertTrue(all(item["outcome"] in {"clear", "review", "blocked"} for item in report["approval_gates"]))
        self.assertTrue(all(0 <= item["score"] <= 100 for item in report["approval_gates"]))
        self.assertEqual(len(report["review_lanes"]), 5)
        self.assertEqual(report["review_lanes"][0]["id"], "all-actions")
        self.assertEqual(len(report["decision_queue"]), len(report["runbook"]))
        self.assertEqual(report["review_lanes"][0]["action_count"], len(report["decision_queue"]))
        self.assertEqual(
            [item["id"] for item in report["decision_queue"]],
            [item["id"] for item in report["runbook"]],
        )
        self.assertTrue(all("all-actions" in item["lane_ids"] for item in report["decision_queue"]))
        self.assertTrue(all(item["suggested_review_minutes"] in {15, 60, 1440, 10080} for item in report["decision_queue"]))
        self.assertLessEqual(len(report["briefing"]["top_action_ids"]), 5)
        self.assertIn(report["briefing"]["customer_impact"], {"none", "watch", "high"})
        self.assertEqual(report["report_contract"]["fixed_check_count"], 40)
        self.assertEqual(report["report_contract"]["fixed_category_count"], 8)
        self.assertEqual(report["report_contract"]["approval_gate_count"], 6)
        self.assertEqual(report["report_contract"]["review_lane_count"], 5)
        self.assertEqual(report["report_contract"]["decision_queue_source"], "failed_checks_only")
        self.assertEqual(report["report_contract"]["change_tracking"], "current_tab_only")
        self.assertEqual(report["report_contract"]["review_session_state"], "current_tab_only")
        self.assertEqual(report["report_contract"]["handoff_export"], "browser_generated_fixed_fields")
        self.assertFalse(report["report_contract"]["accepts_free_text"])
        self.assertFalse(report["report_contract"]["accepts_files"])
        self.assertTrue(all(str(item["owner_path"]).startswith("/") for item in report["checks"]))
        self.assertTrue(report["safe_to_export"])
        self.assertFalse(report["customer_records_included"])
        self.assertFalse(report["customer_maintenance_history_included"])
        self.assertTrue(report["cannot_control_customer_pc"])
        serialized = json.dumps(report)
        for private_value in (
            "OPERATIONS-PRIVATE-CUSTOMER-9017",
            "operations-9017@example.test",
            "OPERATIONS-PRIVATE-NOTE-9017",
            issued["license"]["license_id"],
            issued["license_key"],
            TEST_ADMIN_TOKEN,
            TEST_SIGNING_SECRET,
        ):
            self.assertNotIn(private_value, serialized)

        status, headers, page = self.call_bytes("/owner/operations")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        page_text = page.decode("utf-8")
        self.assertIn("Owner Maintenance Operations", page_text)
        self.assertIn("40 fixed readiness checks", page_text)
        self.assertIn("/api/v1/admin/maintenance-operations", page_text)
        self.assertIn("EXPORT SAFE JSON", page_text)
        self.assertIn("EXPORT CHECKS CSV", page_text)
        self.assertIn("Daily Owner Briefing", page_text)
        self.assertIn("Change Watch", page_text)
        self.assertIn("Domain Scorecards", page_text)
        self.assertIn("Maintenance Window Planner", page_text)
        self.assertIn("Approval Gates", page_text)
        self.assertIn("Owner Review Session", page_text)
        self.assertIn("FOCUS NEXT", page_text)
        self.assertIn("MARK LANE REVIEWED", page_text)
        self.assertIn("EXPORT HANDOFF", page_text)
        self.assertIn("AUTO REFRESH 60S", page_text)
        self.assertIn("EXPORT TEXT", page_text)
        self.assertIn("SHA-256 RECEIPT", page_text)
        self.assertIn("EXPORT CALENDAR", page_text)
        self.assertIn('id="token" type="password"', page_text)
        self.assertNotIn("localStorage", page_text)
        self.assertNotIn("sessionStorage", page_text)
        self.assertNotIn("<textarea", page_text)
        self.assertNotIn('type="file"', page_text)

        status, health = self.call("/health")
        self.assertEqual(status, 200)
        self.assertTrue(health["owner_maintenance_operations_enabled"])
        self.assertEqual(health["owner_operations_schema_version"], 3)
        self.assertTrue(health["owner_operations_change_watch_enabled"])
        self.assertTrue(health["owner_operations_review_planner_enabled"])
        self.assertTrue(health["owner_operations_evidence_receipt_enabled"])
        self.assertTrue(health["owner_operations_approval_gates_enabled"])
        self.assertTrue(health["owner_operations_review_session_enabled"])
        self.assertTrue(health["owner_operations_handoff_export_enabled"])
        status, docs = self.call("/docs")
        self.assertEqual(status, 200)
        documented_paths = {item["path"] for item in docs["routes"]}
        self.assertIn("/owner/operations", documented_paths)
        self.assertIn("/api/v1/admin/maintenance-operations", documented_paths)
        status, _headers, owner_page = self.call_bytes("/owner")
        self.assertEqual(status, 200)
        self.assertIn("/owner/operations", owner_page.decode("utf-8"))

    def test_rank_targeted_owner_announcements_and_admin_controls(self):
        status, denied = self.call(
            "/api/v1/admin/announcements/create",
            method="POST",
            payload={"title": "No token", "message": "This must be rejected."},
        )
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")

        issued_starter, activated_starter = self.issue_and_activate("starter", "NEWS-STARTER-PC")
        issued_plus, activated_plus = self.issue_and_activate("personal-plus", "NEWS-PLUS-PC")
        starter_auth = {
            "license_key": issued_starter["license_key"],
            "receipt": activated_starter["receipt"],
            "machine_id": "NEWS-STARTER-PC",
            "app_version": "2026.07.12.4",
        }
        plus_auth = {
            "license_key": issued_plus["license_key"],
            "receipt": activated_plus["receipt"],
            "machine_id": "NEWS-PLUS-PC",
            "app_version": "2026.07.12.4",
        }

        def publish(**payload):
            response_status, response = self.call(
                "/api/v1/admin/announcements/create",
                method="POST",
                payload=payload,
                headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
            )
            self.assertEqual(response_status, 201)
            return response["announcement"]

        all_ranks = publish(
            severity="info",
            title="Welcome to Owner News",
            message="This read-only message is available to every active license.",
            minimum_rank=1,
        )
        rank_three = publish(
            severity="update",
            title="Personal Plus update",
            message="This notice is limited to Rank 3 and above.",
            minimum_rank=3,
        )
        scheduled = publish(
            severity="maintenance",
            title="Scheduled maintenance",
            message="This notice should remain hidden until its start time.",
            minimum_rank=1,
            starts_at_utc="2099-01-01T00:00:00Z",
        )
        self.assertFalse(scheduled["active"])

        status, starter_news = self.call(
            "/api/v1/announcements/mine",
            method="POST",
            payload=starter_auth,
        )
        self.assertEqual(status, 200)
        self.assertEqual([item["announcement_id"] for item in starter_news["items"]], [all_ranks["announcement_id"]])
        self.assertEqual(starter_news["plan_rank"], 1)

        status, plus_news = self.call(
            "/api/v1/announcements/mine",
            method="POST",
            payload=plus_auth,
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            {item["announcement_id"] for item in plus_news["items"]},
            {all_ranks["announcement_id"], rank_three["announcement_id"]},
        )
        self.assertEqual(plus_news["plan_rank"], 3)

        status, inventory = self.call(
            "/api/v1/admin/announcements",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(inventory["count"], 3)
        self.assertEqual(inventory["active_count"], 2)

        status, dashboard = self.call(
            "/api/v1/admin/dashboard",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(dashboard["announcements"]["active"], 2)

        status, deleted = self.call(
            "/api/v1/admin/announcements/delete",
            method="POST",
            payload={"announcement_id": rank_three["announcement_id"]},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertTrue(deleted["deleted"])

        status, rejected = self.call(
            "/api/v1/admin/announcements/create",
            method="POST",
            payload={
                "title": "Expired notice",
                "message": "This expiration is already in the past.",
                "expires_at_utc": "2000-01-01T00:00:00Z",
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 400)
        self.assertEqual(rejected["error"], "bad_request")

        status, _headers, owner_page = self.call_bytes("/owner")
        self.assertEqual(status, 200)
        owner_text = owner_page.decode("utf-8")
        self.assertIn("Owner Announcements", owner_text)
        self.assertIn("publishAnnouncement", owner_text)
        self.assertIn("statAnnouncements", owner_text)
        self.assertIn("Giveaway License", owner_text)
        self.assertIn("issueGiveaway", owner_text)
        self.assertIn("Client Release Adoption", owner_text)
        self.assertIn("Customer Pages", owner_text)
        self.assertIn("50-Point Owner Command Center", owner_text)
        self.assertIn("/owner/insights", owner_text)
        self.assertIn("Signed Release Test", owner_text)
        self.assertIn("testRelease", owner_text)
        self.assertIn(api.LEGAL_DOCUMENT_VERSION, owner_text)

    def test_service_status_activity_integrity_and_scoped_download(self):
        status, public_status = self.call("/api/v1/service-status")
        self.assertEqual(status, 200)
        self.assertEqual(public_status["service_status"]["mode"], "normal")

        expires_at = api.format_utc(datetime.now(timezone.utc) + timedelta(days=1))
        status, denied = self.call(
            "/api/v1/admin/service-status",
            method="POST",
            payload={"mode": "maintenance", "message": "Scheduled API maintenance", "expires_at_utc": expires_at},
        )
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")

        issued, activated = self.issue_and_activate("personal-plus", "STATUS-NEWS-PC")
        status, announcement = self.call(
            "/api/v1/admin/announcements/create",
            method="POST",
            payload={
                "severity": "security",
                "title": "Security notice",
                "message": "Use the signed updater for the next release.",
                "minimum_rank": 1,
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)

        status, saved = self.call(
            "/api/v1/admin/service-status",
            method="POST",
            payload={
                "mode": "maintenance",
                "message": "Scheduled API maintenance",
                "expires_at_utc": expires_at,
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(saved["service_status"]["mode"], "maintenance")

        status, synced = self.call(
            "/api/v1/licenses/sync",
            method="POST",
            payload={
                "license_key": issued["license_key"],
                "receipt": activated["receipt"],
                "machine_id": "STATUS-NEWS-PC",
                "app_version": "2026.07.12.6",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(synced["service_status"]["mode"], "maintenance")
        self.assertEqual(synced["announcements"]["count"], 1)
        self.assertEqual(
            synced["announcements"]["items"][0]["announcement_id"],
            announcement["announcement"]["announcement_id"],
        )

        status, activity = self.call(
            "/api/v1/admin/activity",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertTrue(activity["integrity"]["valid"])
        self.assertGreaterEqual(activity["count"], 3)
        serialized = json.dumps(activity)
        self.assertNotIn(issued["license_key"], serialized)
        self.assertNotIn("Scheduled API maintenance", serialized)
        self.assertNotIn("Use the signed updater", serialized)

        status, link = self.call(
            "/api/v1/admin/activity/download-link",
            method="POST",
            payload={},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertNotIn(TEST_ADMIN_TOKEN, link["download_path"])
        status, headers, body = self.call_bytes(link["download_path"])
        self.assertEqual(status, 200)
        self.assertIn("attachment", headers.get("Content-Disposition", ""))
        exported = json.loads(body.decode("utf-8"))
        self.assertTrue(exported["integrity"]["valid"])

        path = api.api_activity_log_path()
        lines = path.read_text(encoding="utf-8").splitlines()
        damaged = json.loads(lines[0])
        damaged["action"] = "tampered_action"
        lines[0] = json.dumps(damaged, sort_keys=True, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        status, damaged_activity = self.call(
            "/api/v1/admin/activity",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertFalse(damaged_activity["integrity"]["valid"])

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

    def test_automatic_sync_reports_policy_and_enforces_revocation(self):
        issued, activated = self.issue_and_activate("personal-plus", "SYNC-PC")
        request_payload = {
            "license_key": issued["license_key"],
            "receipt": activated["receipt"],
            "machine_id": "SYNC-PC",
            "app_version": "2026.07.12.2",
        }
        status, synced = self.call(
            "/api/v1/licenses/sync",
            method="POST",
            payload=request_payload,
        )
        self.assertEqual(status, 200)
        self.assertTrue(synced["active"])
        self.assertEqual(synced["api_version"], api.API_VERSION)
        self.assertTrue(synced["sync"]["automatic"])
        self.assertEqual(synced["sync"]["recommended_interval_seconds"], api.LICENSE_SYNC_INTERVAL_SECONDS)
        self.assertEqual(len(synced["sync"]["decision_id"]), 16)
        status, devices = self.call(
            f"/api/v1/admin/licenses/{issued['license']['license_id']}/devices",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(devices["items"][0]["app_version"], "2026.07.12.2")
        self.assertTrue(devices["items"][0]["last_seen_at_utc"])

        status, revoked = self.call(
            "/api/v1/licenses/revoke",
            method="POST",
            payload={"license_key": issued["license_key"]},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertTrue(revoked["revoked"])
        status, synced = self.call(
            "/api/v1/licenses/sync",
            method="POST",
            payload=request_payload,
        )
        self.assertEqual(status, 200)
        self.assertFalse(synced["active"])
        self.assertEqual(synced["status"], "revoked")
        self.assertEqual(synced["sync"]["decision"], "revoked")

    def test_encrypted_bug_inbox_owner_actions_and_customer_reply(self):
        issued, activated = self.issue_and_activate("starter", "BUG-REPORT-PC")
        auth_payload = {
            "license_key": issued["license_key"],
            "receipt": activated["receipt"],
            "machine_id": "BUG-REPORT-PC",
            "app_version": "2026.07.12.3",
        }
        private_message = "The lock button stopped after I selected two sample files."
        status, created = self.call(
            "/api/v1/support-tickets",
            method="POST",
            payload={
                **auth_payload,
                "category": "bug",
                "subject": "Lock button stopped",
                "message": private_message,
                "steps": "Open app\nAdd two files\nClick LOCK COPY",
            },
        )
        self.assertEqual(status, 201)
        ticket_id = created["ticket"]["ticket_id"]
        self.assertTrue(ticket_id.startswith("TKT-"))
        stored_path = api.support_ticket_path(ticket_id)
        stored_text = stored_path.read_text(encoding="utf-8")
        self.assertNotIn(private_message, stored_text)
        self.assertNotIn("Lock button stopped", stored_text)
        self.assertNotIn("BUG-REPORT-PC", stored_text)
        self.assertNotIn(issued["license_key"], stored_text)

        status, mine = self.call(
            "/api/v1/support-tickets/mine",
            method="POST",
            payload=auth_payload,
        )
        self.assertEqual(status, 200)
        self.assertEqual(mine["count"], 1)
        self.assertEqual(mine["items"][0]["status"], "open")

        status, denied = self.call("/api/v1/admin/support-tickets")
        self.assertEqual(status, 403)
        status, inbox = self.call(
            "/api/v1/admin/support-tickets",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(inbox["items"][0]["message"], private_message)

        owner_reply = "Thanks. I reproduced this and am working on the fix."
        owner_note = "Regression test against multi-file queue"
        status, updated = self.call(
            "/api/v1/admin/support-tickets/action",
            method="POST",
            payload={
                "ticket_id": ticket_id,
                "status": "in_progress",
                "owner_reply": owner_reply,
                "owner_note": owner_note,
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(updated["ticket"]["status"], "in_progress")
        self.assertEqual(updated["ticket"]["owner_note"], owner_note)
        self.assertNotIn(owner_reply, stored_path.read_text(encoding="utf-8"))

        status, mine = self.call(
            "/api/v1/support-tickets/mine",
            method="POST",
            payload=auth_payload,
        )
        self.assertEqual(status, 200)
        self.assertEqual(mine["items"][0]["owner_reply"], owner_reply)
        self.assertNotIn("owner_note", mine["items"][0])

        status, dashboard = self.call(
            "/api/v1/admin/dashboard",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(dashboard["support_tickets"]["total"], 1)

        status, deleted = self.call(
            "/api/v1/admin/support-tickets/delete",
            method="POST",
            payload={"ticket_id": ticket_id},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertTrue(deleted["deleted"])
        status, mine = self.call(
            "/api/v1/support-tickets/mine",
            method="POST",
            payload=auth_payload,
        )
        self.assertEqual(status, 200)
        self.assertEqual(mine["count"], 0)

    def test_damaged_support_ticket_does_not_break_owner_dashboard(self):
        issued, activated = self.issue_and_activate("starter", "DAMAGED-TICKET-PC")
        status, created = self.call(
            "/api/v1/support-tickets",
            method="POST",
            payload={
                "license_key": issued["license_key"],
                "receipt": activated["receipt"],
                "machine_id": "DAMAGED-TICKET-PC",
                "category": "bug",
                "subject": "Damaged ticket test",
                "message": "This ticket will be damaged after it is safely encrypted.",
            },
        )
        self.assertEqual(status, 201)
        path = api.support_ticket_path(created["ticket"]["ticket_id"])
        record = json.loads(path.read_text(encoding="utf-8"))
        damaged_blob = bytearray(api.b64url_decode(record["private_blob"]))
        damaged_blob[-1] ^= 1
        record["private_blob"] = api.b64url_encode(bytes(damaged_blob))
        path.write_text(json.dumps(record), encoding="utf-8")

        status, inbox = self.call(
            "/api/v1/admin/support-tickets",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(inbox["count"], 0)
        self.assertEqual(inbox["damaged_count"], 1)
        status, dashboard = self.call(
            "/api/v1/admin/dashboard",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(dashboard["support_tickets"]["total"], 0)

    def test_license_notes_deactivation_revocation_and_restore(self):
        private_note = "Renew after family laptop setup"
        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={
                "plan_id": "family-safety",
                "customer_label": "Test customer",
                "license_note": private_note,
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)
        self.assertNotIn("license_note", issued)
        license_key = issued["license_key"]

        record_files = list((api.LICENSE_STATE_DIR / "licenses").glob("*.json"))
        self.assertEqual(len(record_files), 1)
        stored_text = record_files[0].read_text(encoding="utf-8")
        self.assertNotIn(private_note, stored_text)
        self.assertNotIn(license_key, stored_text)

        status, denied = self.call("/api/v1/admin/licenses")
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")
        status, inventory = self.call(
            "/api/v1/admin/licenses",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(inventory["count"], 1)
        self.assertEqual(inventory["items"][0]["license_note"], private_note)
        self.assertEqual(inventory["items"][0]["license_key"], license_key)

        status, activated = self.call(
            "/api/v1/licenses/activate",
            method="POST",
            payload={"license_key": license_key, "machine_id": "REMOVE-PC"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(activated["active"])
        status, deactivated = self.call(
            "/api/v1/licenses/deactivate",
            method="POST",
            payload={
                "license_key": license_key,
                "receipt": activated["receipt"],
                "machine_id": "REMOVE-PC",
                "app_version": "test",
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(deactivated["deactivated"])
        status, verification = self.call(
            "/api/v1/licenses/verify",
            method="POST",
            payload={
                "license_key": license_key,
                "receipt": activated["receipt"],
                "machine_id": "REMOVE-PC",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(verification["status"], "deactivated")

        status, reactivated = self.call(
            "/api/v1/licenses/activate",
            method="POST",
            payload={"license_key": license_key, "machine_id": "REMOVE-PC"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(reactivated["active"])
        self.assertNotEqual(reactivated["receipt"], activated["receipt"])

        status, denied = self.call(
            "/api/v1/licenses/revoke",
            method="POST",
            payload={"license_key": license_key},
        )
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")
        status, revoked = self.call(
            "/api/v1/licenses/revoke",
            method="POST",
            payload={"license_key": license_key, "revocation_note": "Customer requested removal"},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertTrue(revoked["revoked"])
        status, verification = self.call(
            "/api/v1/licenses/verify",
            method="POST",
            payload={
                "license_key": license_key,
                "receipt": reactivated["receipt"],
                "machine_id": "REMOVE-PC",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(verification["status"], "revoked")

        status, restored = self.call(
            "/api/v1/licenses/restore",
            method="POST",
            payload={"license_key": license_key},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertTrue(restored["restored"])
        status, verification = self.call(
            "/api/v1/licenses/verify",
            method="POST",
            payload={
                "license_key": license_key,
                "receipt": reactivated["receipt"],
                "machine_id": "REMOVE-PC",
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(verification["active"])

        status, noted = self.call(
            "/api/v1/licenses/note",
            method="POST",
            payload={"license_key": license_key, "license_note": "Updated private note"},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(noted["license"]["license_note"], "Updated private note")

    def test_device_limit_dashboard_and_admin_reset(self):
        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={"plan_id": "home", "max_devices": 1, "license_note": "Seat test"},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)
        key = issued["license_key"]
        current_release = "2026.07.12.7"

        status, first = self.call(
            "/api/v1/licenses/activate",
            method="POST",
            payload={
                "license_key": key,
                "machine_id": "FIRST-PC",
                "machine_name": "Private PC name",
                "app_version": current_release,
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(first["active"])
        self.assertEqual(first["device_usage"], {"active": 1, "maximum": 1})

        status, denied = self.call(
            "/api/v1/licenses/activate",
            method="POST",
            payload={"license_key": key, "machine_id": "SECOND-PC"},
        )
        self.assertEqual(status, 200)
        self.assertFalse(denied["active"])
        self.assertEqual(denied["status"], "device_limit")

        activation_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (api.LICENSE_STATE_DIR / "activations").rglob("*.json")
        )
        self.assertNotIn("FIRST-PC", activation_text)
        self.assertNotIn("Private PC name", activation_text)

        status, inventory = self.call(
            "/api/v1/admin/licenses",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(inventory["items"][0]["active_devices"], 1)

        with mock.patch.object(
            api,
            "windows_update_release_status",
            return_value={
                "ready": True,
                "version": current_release,
                "checks": {"ed25519_signature": "passed", "package_sha256": "passed"},
            },
        ):
            status, dashboard = self.call(
                "/api/v1/admin/dashboard",
                headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
            )
        self.assertEqual(status, 200)
        self.assertEqual(dashboard["licenses"]["active"], 1)
        self.assertEqual(dashboard["devices"], {"active": 1, "capacity": 1})
        self.assertEqual(dashboard["audit_exports"]["total"], 0)
        self.assertEqual(dashboard["client_health"]["active_devices"], 1)
        self.assertEqual(dashboard["client_health"]["current_release_devices"], 1)
        self.assertEqual(dashboard["client_health"]["unknown_version_devices"], 0)
        self.assertEqual(
            dashboard["client_health"]["version_counts"],
            [{"version": current_release, "devices": 1, "current_release": True}],
        )

        status, denied = self.call(
            "/api/v1/licenses/reset-devices",
            method="POST",
            payload={"license_key": key},
        )
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")

        status, reset = self.call(
            "/api/v1/licenses/reset-devices",
            method="POST",
            payload={"license_key": key},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(reset["devices_reset"], 1)
        self.assertEqual(reset["license"]["active_devices"], 0)

        status, old_receipt = self.call(
            "/api/v1/licenses/verify",
            method="POST",
            payload={"license_key": key, "receipt": first["receipt"], "machine_id": "FIRST-PC"},
        )
        self.assertEqual(status, 200)
        self.assertFalse(old_receipt["active"])
        self.assertEqual(old_receipt["status"], "reset")

        status, second = self.call(
            "/api/v1/licenses/activate",
            method="POST",
            payload={"license_key": key, "machine_id": "SECOND-PC"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(second["active"])
        self.assertEqual(second["device_usage"]["active"], 1)

    def test_owner_can_temporarily_limit_and_restore_customer_access(self):
        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={"plan_id": "personal-plus", "max_devices": 1},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)
        key = issued["license_key"]
        status, activated = self.call(
            "/api/v1/licenses/activate",
            method="POST",
            payload={"license_key": key, "machine_id": "LIMIT-PC", "app_version": "2026.07.12.8"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(activated["active"])

        status, denied = self.call(
            "/api/v1/licenses/limit",
            method="POST",
            payload={"license_key": key, "hours": 24, "reason": "Temporary account review."},
        )
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")

        status, limited = self.call(
            "/api/v1/licenses/limit",
            method="POST",
            payload={"license_key": key, "hours": 24, "reason": "Temporary account review."},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertTrue(limited["limited"])
        self.assertIn("Unlock and recovery", limited["message"])

        status, verification = self.call(
            "/api/v1/licenses/verify",
            method="POST",
            payload={
                "license_key": key,
                "receipt": activated["receipt"],
                "machine_id": "LIMIT-PC",
            },
        )
        self.assertEqual(status, 200)
        self.assertFalse(verification["active"])
        self.assertEqual(verification["status"], "limited")
        self.assertIn("Temporary account review", verification["message"])

        status, inventory = self.call(
            "/api/v1/admin/licenses",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        record = next(item for item in inventory["items"] if item["license_id"] == issued["license"]["license_id"])
        self.assertTrue(record["limited"])

        status, restored = self.call(
            "/api/v1/licenses/unlimit",
            method="POST",
            payload={"license_key": key},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertFalse(restored["limited"])
        status, verification = self.call(
            "/api/v1/licenses/verify",
            method="POST",
            payload={
                "license_key": key,
                "receipt": activated["receipt"],
                "machine_id": "LIMIT-PC",
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(verification["active"])

    def test_admin_lists_and_removes_one_anonymous_device(self):
        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={"plan_id": "family-safety", "max_devices": 2},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)
        key = issued["license_key"]
        activations = {}
        for machine_id in ("FIRST-PRIVATE-PC", "SECOND-PRIVATE-PC"):
            status, activated = self.call(
                "/api/v1/licenses/activate",
                method="POST",
                payload={"license_key": key, "machine_id": machine_id, "machine_name": machine_id},
            )
            self.assertEqual(status, 200)
            self.assertTrue(activated["active"])
            activations[machine_id] = activated

        license_id = issued["license"]["license_id"]
        status, devices = self.call(
            f"/api/v1/admin/licenses/{license_id}/devices",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(devices["active_count"], 2)
        serialized = json.dumps(devices)
        self.assertNotIn("FIRST-PRIVATE-PC", serialized)
        self.assertNotIn("SECOND-PRIVATE-PC", serialized)

        first_hash = api.anonymous_machine_hash("FIRST-PRIVATE-PC")
        status, removed = self.call(
            "/api/v1/licenses/remove-device",
            method="POST",
            payload={"license_key": key, "machine_hash": first_hash},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertTrue(removed["removed"])
        self.assertEqual(removed["license"]["active_devices"], 1)

        status, first_sync = self.call(
            "/api/v1/licenses/sync",
            method="POST",
            payload={
                "license_key": key,
                "receipt": activations["FIRST-PRIVATE-PC"]["receipt"],
                "machine_id": "FIRST-PRIVATE-PC",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(first_sync["status"], "removed")
        status, second_sync = self.call(
            "/api/v1/licenses/sync",
            method="POST",
            payload={
                "license_key": key,
                "receipt": activations["SECOND-PRIVATE-PC"]["receipt"],
                "machine_id": "SECOND-PRIVATE-PC",
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(second_sync["active"])

    def test_audit_export_strips_private_fields_and_uses_bearer_token(self):
        issued, activated = self.issue_and_activate("personal-plus")
        status, uploaded = self.upload_report(issued, activated)
        self.assertEqual(status, 201)
        self.assertNotIn("token=", uploaded["download_path"])
        self.assertEqual(uploaded["breach_summary"]["level"], "clear")

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

    def test_admin_can_list_and_download_stored_breach_reports(self):
        issued, activated = self.issue_and_activate("family-safety")
        report = sample_report()
        report["usb_file_locker_audit"]["events"].append(
            {
                "sequence": 3,
                "time_utc": "2026-07-10T22:02:00Z",
                "event_id": "0123456789abcdef",
                "action": "owner_usb_removed",
                "result": "success",
                "hash": "c" * 64,
                "previous_hash": "b" * 64,
            }
        )
        status, uploaded = self.upload_report(issued, activated, report=report)
        self.assertEqual(status, 201)
        self.assertEqual(uploaded["breach_summary"]["level"], "high")

        status, denied = self.call("/api/v1/admin/audit-exports")
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")

        status, listing = self.call(
            "/api/v1/admin/audit-exports",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(listing["count"], 1)
        item = listing["items"][0]
        self.assertEqual(item["export_id"], uploaded["export_id"])
        self.assertEqual(item["breach_summary"]["level"], "high")
        self.assertEqual(item["event_count"], 3)
        self.assertNotIn("download_token", json.dumps(listing))

        status, denied = self.call(item["download_path"])
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")

        status, downloaded = self.call(
            item["download_path"],
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(downloaded["export_id"], uploaded["export_id"])
        self.assertEqual(downloaded["breach_summary"]["level"], "high")
        serialized = json.dumps(downloaded)
        self.assertNotIn("SECRET_FILE_CONTENT", serialized)
        self.assertNotIn("C:/Private/secret.txt", serialized)

        status, denied = self.call(
            "/api/v1/admin/audit-exports/download-link",
            method="POST",
            payload={"export_id": item["export_id"]},
        )
        self.assertEqual(status, 403)
        status, link = self.call(
            "/api/v1/admin/audit-exports/download-link",
            method="POST",
            payload={"export_id": item["export_id"]},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertIn("?token=vla1.", link["download_path"])
        self.assertNotIn(TEST_ADMIN_TOKEN, link["download_path"])
        status, downloaded = self.call(link["download_path"])
        self.assertEqual(status, 200)
        self.assertEqual(downloaded["export_id"], item["export_id"])

    def test_recovery_readiness_is_fixed_private_and_not_stored(self):
        field_ids = [item["id"] for item in api.READINESS_CHECKS]
        self.assertEqual(len(field_ids), 7)
        self.assertEqual(len(set(field_ids)), 7)
        self.assertEqual(sum(item["weight"] for item in api.READINESS_CHECKS), 100)

        all_false = {field: False for field in field_ids}
        status, blocked = self.call(
            "/api/v1/readiness/check",
            method="POST",
            payload=all_false,
        )
        self.assertEqual(status, 200)
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(blocked["score"], 0)
        self.assertEqual(blocked["critical_missing_count"], 3)
        self.assertEqual(len(blocked["actions"]), 7)
        self.assertFalse(blocked["ready_for_important_data"])
        self.assertFalse(blocked["stored"])
        self.assertIn("stores nothing", blocked["privacy_notice"])

        action_answers = dict(all_false)
        for field in ("backup_current", "master_usb_tested", "test_file_roundtrip"):
            action_answers[field] = True
        status, action = self.call(
            "/api/v1/readiness/check",
            method="POST",
            payload=action_answers,
        )
        self.assertEqual(status, 200)
        self.assertEqual(action["status"], "action")
        self.assertEqual(action["score"], 55)
        self.assertEqual(action["critical_missing_count"], 0)

        review_answers = dict(action_answers)
        review_answers["recovery_copy_separate"] = True
        review_answers["pin_stored_separately"] = True
        status, review = self.call(
            "/api/v1/readiness/check",
            method="POST",
            payload=review_answers,
        )
        self.assertEqual(status, 200)
        self.assertEqual(review["status"], "review")
        self.assertEqual(review["score"], 80)
        self.assertTrue(review["ready_for_important_data"])

        all_true = {field: True for field in field_ids}
        status, ready = self.call(
            "/api/v1/readiness/check",
            method="POST",
            payload=all_true,
        )
        self.assertEqual(status, 200)
        self.assertEqual(ready["status"], "ready")
        self.assertEqual(ready["score"], 100)
        self.assertEqual(ready["completed_count"], 7)
        self.assertEqual(ready["actions"], [])

        status, unknown = self.call(
            "/api/v1/readiness/check",
            method="POST",
            payload={**all_true, "customer_name": "PRIVATE-NAME"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(unknown["error"], "bad_request")

        invalid_type = dict(all_true)
        invalid_type["backup_current"] = "yes"
        status, invalid = self.call(
            "/api/v1/readiness/check",
            method="POST",
            payload=invalid_type,
        )
        self.assertEqual(status, 400)
        self.assertEqual(invalid["error"], "bad_request")

        missing = dict(all_true)
        missing.pop("update_current")
        status, incomplete = self.call(
            "/api/v1/readiness/check",
            method="POST",
            payload=missing,
        )
        self.assertEqual(status, 400)
        self.assertEqual(incomplete["error"], "bad_request")

        status, headers, page = self.call_bytes("/readiness")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        page_text = page.decode("utf-8")
        self.assertIn("VaultLink Recovery Readiness", page_text)
        self.assertIn("/api/v1/readiness/check", page_text)
        self.assertIn("CHECK READINESS", page_text)
        self.assertIn("Prioritized Action Plan", page_text)
        self.assertIn("DOWNLOAD ACTION PLAN", page_text)
        self.assertIn("Disposable file lock and unlock tested", page_text)

    def test_signed_update_manifest_and_package_endpoints(self):
        manifest, package = self.publish_test_update()

        status, denied = self.call("/api/v1/admin/updates/windows/status")
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")
        status, release_status = self.call(
            "/api/v1/admin/updates/windows/status",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertTrue(release_status["ready"])
        self.assertEqual(release_status["checks"]["ed25519_signature"], "passed")
        self.assertEqual(release_status["checks"]["package_sha256"], "passed")

        status, response = self.call("/api/v1/updates/windows")
        self.assertEqual(status, 200)
        self.assertEqual(response["update"]["version"], manifest["version"])
        self.assertEqual(response["update"]["sha256"], manifest["sha256"])
        self.assertTrue(response["security"]["manual_install_requires_confirmation"])
        self.assertTrue(response["security"]["automatic_install_requires_local_opt_in"])
        self.assertTrue(response["security"]["below_minimum_installs_verified_update"])
        self.assertTrue(response["security"]["waits_for_active_local_task"])
        self.assertTrue(response["security"]["recovery_remains_available_on_failure"])

        status, required = self.call(
            "/api/v1/updates/windows/check",
            method="POST",
            payload={"installed_version": "2026.07.09"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(required["status"], "required")
        self.assertFalse(required["supported"])
        self.assertTrue(required["update_required"])
        self.assertTrue(required["update_available"])
        self.assertFalse(required["stored"])
        self.assertEqual(required["release"]["sha256"], manifest["sha256"])

        status, available = self.call(
            "/api/v1/updates/windows/check",
            method="POST",
            payload={"installed_version": manifest["minimum_supported_version"]},
        )
        self.assertEqual(status, 200)
        self.assertEqual(available["status"], "available")
        self.assertTrue(available["supported"])
        self.assertTrue(available["download_recommended"])

        status, current = self.call(
            "/api/v1/updates/windows/check",
            method="POST",
            payload={"installed_version": manifest["version"]},
        )
        self.assertEqual(status, 200)
        self.assertEqual(current["status"], "current")
        self.assertFalse(current["update_available"])
        self.assertFalse(current["download_recommended"])

        status, ahead = self.call(
            "/api/v1/updates/windows/check",
            method="POST",
            payload={"installed_version": "10000.0"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(ahead["status"], "ahead")

        status, invalid = self.call(
            "/api/v1/updates/windows/check",
            method="POST",
            payload={"installed_version": "version one"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(invalid["error"], "bad_request")

        status, update_headers, update_page = self.call_bytes("/update")
        self.assertEqual(status, 200)
        self.assertIn("text/html", update_headers["Content-Type"])
        update_text = update_page.decode("utf-8")
        self.assertIn("VaultLink Update Center", update_text)
        self.assertIn("/api/v1/updates/windows/check", update_text)
        self.assertIn("CHECK UPDATE", update_text)
        self.assertIn("COPY REPORT", update_text)
        self.assertIn("Local ZIP Verifier", update_text)
        self.assertIn("CHOOSE UPDATE ZIP", update_text)

        status, headers, status_page = self.call_bytes("/status")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        status_text = status_page.decode("utf-8")
        self.assertIn("Customer Status", status_text)
        self.assertIn(manifest["version"], status_text)
        self.assertNotIn(TEST_ADMIN_TOKEN, status_text)

        status, terms_headers, terms_page = self.call_bytes("/terms")
        self.assertEqual(status, 200)
        self.assertIn("text/html", terms_headers["Content-Type"])
        self.assertIn("DRAFT FOR ADULT AND LEGAL REVIEW", terms_page.decode("utf-8"))
        status, _privacy_headers, privacy_page = self.call_bytes("/privacy")
        self.assertEqual(status, 200)
        self.assertIn("Privacy Notice", privacy_page.decode("utf-8"))
        status, legal = self.call("/api/v1/legal")
        self.assertEqual(status, 200)
        self.assertTrue(legal["draft"])
        self.assertTrue(legal["adult_business_owner_review_required"])
        self.assertEqual(legal["document_version"], api.LEGAL_DOCUMENT_VERSION)

        status, headers, body = self.call_bytes("/api/v1/updates/windows/download")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/zip")
        self.assertEqual(body, package.read_bytes())

        tampered_manifest = dict(manifest)
        tampered_manifest["signature"] = ("A" if manifest["signature"][0] != "A" else "B") + manifest["signature"][1:]
        api.UPDATE_MANIFEST_PATH.write_text(json.dumps(tampered_manifest), encoding="utf-8")
        status, failed_release = self.call(
            "/api/v1/admin/updates/windows/status",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertFalse(failed_release["ready"])
        self.assertEqual(failed_release["checks"]["ed25519_signature"], "failed")
        status, invalid_signature = self.call("/api/v1/updates/windows")
        self.assertEqual(status, 503)
        self.assertEqual(invalid_signature["error"], "update_unavailable")
        api.UPDATE_MANIFEST_PATH.write_text(json.dumps(manifest), encoding="utf-8")

        package.write_bytes(b"tampered")
        status, response = self.call("/api/v1/updates/windows")
        self.assertEqual(status, 503)
        self.assertEqual(response["error"], "update_unavailable")
        status, unavailable = self.call(
            "/api/v1/updates/windows/check",
            method="POST",
            payload={"installed_version": "2026.07.10"},
        )
        self.assertEqual(status, 200)
        self.assertFalse(unavailable["published"])
        self.assertEqual(unavailable["status"], "unavailable")

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
            payload={"plan_id": "family-safety", "license_note": "x" * 2001},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 400)
        self.assertIn("2000", response["message"])

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

    def test_customer_accounts_owner_assignment_transfer_and_password_security(self):
        status, account_required = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={"plan_id": "starter"},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
            auto_account=False,
        )
        self.assertEqual(status, 400)
        self.assertIn("must create an account", account_required["message"])

        status, weak = self.call(
            "/api/v1/accounts/register",
            method="POST",
            payload={"username": "Alice_1", "password": "12345"},
        )
        self.assertEqual(status, 400)
        self.assertIn("10", weak["message"])

        status, alice = self.call(
            "/api/v1/accounts/register",
            method="POST",
            payload={"username": "Alice_1", "password": "CorrectHorse9!"},
        )
        self.assertEqual(status, 201)
        self.assertTrue(alice["created"])
        self.assertEqual(alice["account"]["username"], "Alice_1")
        self.assertFalse(alice["account"]["license"]["assigned"])
        alice_id = alice["account"]["account_id"]
        alice_token = alice["session_token"]

        account_files = list((api.LICENSE_STATE_DIR / "accounts").glob("*.json"))
        self.assertEqual(len(account_files), 1)
        stored_text = account_files[0].read_text(encoding="utf-8")
        self.assertNotIn("Alice_1", stored_text)
        self.assertNotIn("CorrectHorse9!", stored_text)
        stored = json.loads(stored_text)
        private_fields = api.decrypt_account_private_fields(stored)
        self.assertEqual(private_fields["password_algorithm"], "scrypt")
        self.assertNotEqual(private_fields["password_hash"], "CorrectHorse9!")

        status, directly_issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={
                "account_id": alice_id,
                "plan_id": "starter",
                "customer_label": "SPOOFED LABEL",
                "customer_email": "ignored@example.test",
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)
        self.assertTrue(directly_issued["account_required"])
        self.assertEqual(directly_issued["license"]["account_id"], alice_id)
        self.assertEqual(directly_issued["license"]["customer_label"], "Alice_1")
        self.assertEqual(directly_issued["license"]["customer_email"], "")
        first_license_id = directly_issued["license"]["license_id"]
        self.assertEqual(api.read_license_record(first_license_id)["account_id"], alice_id)

        status, duplicate = self.call(
            "/api/v1/accounts/register",
            method="POST",
            payload={"username": "alice_1", "password": "AnotherPass8#"},
        )
        self.assertEqual(status, 400)
        self.assertIn("not available", duplicate["message"])

        status, wrong = self.call(
            "/api/v1/accounts/login",
            method="POST",
            payload={"username": "Alice_1", "password": "WrongPassword9!"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(wrong["message"], "Username or password was incorrect.")

        status, profile = self.call(
            "/api/v1/accounts/me",
            headers={"Authorization": f"Bearer {alice_token}"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(profile["account"]["username"], "Alice_1")

        status, denied_accounts = self.call("/api/v1/admin/accounts")
        self.assertEqual(status, 403)
        self.assertEqual(denied_accounts["error"], "forbidden")
        status, accounts = self.call(
            "/api/v1/admin/accounts",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(accounts["count"], 1)
        self.assertFalse(accounts["passwords_readable"])
        self.assertNotIn("license_key", accounts["items"][0]["license"])
        self.assertNotIn("password_hash", json.dumps(accounts))

        status, assigned = self.call(
            "/api/v1/admin/accounts/assign",
            method="POST",
            payload={
                "account_id": alice_id,
                "plan_id": "family-safety",
                "max_devices": 3,
                "license_note": "Assigned in regression test",
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertTrue(assigned["assigned"])
        self.assertIn("issued_license_key", assigned)
        license_id = assigned["account"]["license"]["license_id"]
        license_key = assigned["issued_license_key"]
        self.assertEqual(api.read_license_record(first_license_id)["account_id"], "")
        self.assertEqual(api.read_license_record(license_id)["account_id"], alice_id)

        status, alice_profile = self.call(
            "/api/v1/accounts/me",
            headers={"Authorization": f"Bearer {alice_token}"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(alice_profile["account"]["license"]["rank"], 4)
        self.assertEqual(alice_profile["account"]["license"]["license_key"], license_key)
        self.assertEqual(alice_profile["account"]["license"]["max_devices"], 3)

        status, bob = self.call(
            "/api/v1/accounts/register",
            method="POST",
            payload={"username": "Bob_2", "password": "BobSecure8#"},
        )
        self.assertEqual(status, 201)
        bob_id = bob["account"]["account_id"]
        bob_token = bob["session_token"]

        status, conflict = self.call(
            "/api/v1/admin/accounts/assign",
            method="POST",
            payload={"account_id": bob_id, "license_id": license_id},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 400)
        self.assertIn("already assigned", conflict["message"])

        status, transferred = self.call(
            "/api/v1/admin/accounts/assign",
            method="POST",
            payload={"account_id": bob_id, "license_id": license_id, "transfer": True},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertTrue(transferred["transferred"])
        status, invalidated_alice = self.call(
            "/api/v1/accounts/me",
            headers={"Authorization": f"Bearer {alice_token}"},
        )
        self.assertEqual(status, 401)
        status, bob_profile = self.call(
            "/api/v1/accounts/me",
            headers={"Authorization": f"Bearer {bob_token}"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(bob_profile["account"]["license"]["license_key"], license_key)

        status, disabled = self.call(
            "/api/v1/admin/accounts/status",
            method="POST",
            payload={"account_id": bob_id, "status": "disabled"},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(disabled["account"]["status"], "disabled")
        status, blocked_bob = self.call(
            "/api/v1/accounts/me",
            headers={"Authorization": f"Bearer {bob_token}"},
        )
        self.assertEqual(status, 401)

        status, enabled = self.call(
            "/api/v1/admin/accounts/status",
            method="POST",
            payload={"account_id": bob_id, "status": "active"},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        status, relogged_bob = self.call(
            "/api/v1/accounts/login",
            method="POST",
            payload={"username": "Bob_2", "password": "BobSecure8#"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(relogged_bob["account"]["license"]["license_id"], license_id)

        status, relogged_alice = self.call(
            "/api/v1/accounts/login",
            method="POST",
            payload={"username": "Alice_1", "password": "CorrectHorse9!"},
        )
        self.assertEqual(status, 200)
        old_alice_token = relogged_alice["session_token"]
        status, changed = self.call(
            "/api/v1/accounts/change-password",
            method="POST",
            payload={
                "current_password": "CorrectHorse9!",
                "new_password": "NewSecret10$",
            },
            headers={"Authorization": f"Bearer {old_alice_token}"},
        )
        self.assertEqual(status, 200)
        self.assertNotEqual(changed["session_token"], old_alice_token)
        status, old_session = self.call(
            "/api/v1/accounts/me",
            headers={"Authorization": f"Bearer {old_alice_token}"},
        )
        self.assertEqual(status, 401)
        status, old_password = self.call(
            "/api/v1/accounts/login",
            method="POST",
            payload={"username": "Alice_1", "password": "CorrectHorse9!"},
        )
        self.assertEqual(status, 403)
        status, new_password = self.call(
            "/api/v1/accounts/login",
            method="POST",
            payload={"username": "Alice_1", "password": "NewSecret10$"},
        )
        self.assertEqual(status, 200)

        status, _headers, customer_page = self.call_bytes("/account")
        self.assertEqual(status, 200)
        self.assertIn(b"CREATE ACCOUNT", customer_page)
        self.assertIn(b"/api/v1/accounts/login", customer_page)
        status, _headers, owner_page = self.call_bytes("/owner/accounts")
        self.assertEqual(status, 200)
        self.assertIn(b"ISSUE AND ASSIGN", owner_page)
        self.assertIn(b"/api/v1/admin/accounts", owner_page)
        self.assertNotIn(TEST_ADMIN_TOKEN.encode("utf-8"), owner_page)

    def test_account_workspace_availability_expiry_and_logout_all(self):
        username = "Workspace_User_65"
        status, available = self.call(
            f"/api/v1/accounts/username-availability?username={username}"
        )
        self.assertEqual(status, 200)
        self.assertTrue(available["available"])
        self.assertEqual(available["username"], username)
        self.assertEqual(available["requirements"]["minimum_characters"], 3)

        with mock.patch.object(api, "ACCOUNT_AVAILABILITY_MAX_CHECKS", 1):
            api.account_username_availability("Rate_User_65", "rate-limit-test")
            with self.assertRaises(PermissionError):
                api.account_username_availability("Other_User_65", "rate-limit-test")

        bounded_bucket = {}
        with mock.patch.object(api, "MAX_ACCOUNT_RATE_KEYS", 2):
            for key in ("first", "second", "third"):
                self.assertTrue(
                    api.account_rate_allowed(
                        bounded_bucket,
                        key,
                        limit=10,
                        window_seconds=60,
                        consume=True,
                    )
                )
        self.assertEqual(len(bounded_bucket), 2)
        self.assertNotIn("first", bounded_bucket)

        status, invalid = self.call(
            "/api/v1/accounts/username-availability?username=ab"
        )
        self.assertEqual(status, 400)
        self.assertIn("3 to 32", invalid["message"])

        status, registered = self.call(
            "/api/v1/accounts/register",
            method="POST",
            payload={"username": username, "password": "WorkspaceSecure9!"},
        )
        self.assertEqual(status, 201)
        first_token = registered["session_token"]
        self.assertTrue(registered["session_expires_at_utc"])

        status, taken = self.call(
            f"/api/v1/accounts/username-availability?username={username.lower()}"
        )
        self.assertEqual(status, 200)
        self.assertFalse(taken["available"])

        status, second_login = self.call(
            "/api/v1/accounts/login",
            method="POST",
            payload={"username": username, "password": "WorkspaceSecure9!"},
        )
        self.assertEqual(status, 200)
        second_token = second_login["session_token"]
        self.assertNotEqual(first_token, second_token)

        status, profile = self.call(
            "/api/v1/accounts/me",
            headers={"Authorization": f"Bearer {first_token}"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            profile["session_expires_at_utc"],
            registered["session_expires_at_utc"],
        )

        status, activity = self.call(
            "/api/v1/accounts/activity",
            headers={"Authorization": f"Bearer {first_token}"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(activity["integrity"]["valid"])
        self.assertEqual(activity["integrity"]["algorithm"], "HMAC-SHA-256 hash chain")
        self.assertIn("Account created", {item["label"] for item in activity["items"]})
        self.assertIn("Successful sign-in", {item["label"] for item in activity["items"]})
        self.assertTrue(all(item["actor"] == "customer" for item in activity["items"]))
        serialized_activity = json.dumps(activity["items"])
        for forbidden in ("password", "session_token", "license_key", "machine_id"):
            self.assertNotIn(forbidden, serialized_activity)

        status, signed_out = self.call(
            "/api/v1/accounts/logout-all",
            method="POST",
            payload={},
            headers={"Authorization": f"Bearer {second_token}"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(signed_out["signed_out_all"])

        for token in (first_token, second_token):
            status, blocked = self.call(
                "/api/v1/accounts/me",
                headers={"Authorization": f"Bearer {token}"},
            )
            self.assertEqual(status, 401)
            self.assertIn("no longer valid", blocked["message"])
            status, blocked_activity = self.call(
                "/api/v1/accounts/activity",
                headers={"Authorization": f"Bearer {token}"},
            )
            self.assertEqual(status, 401)
            self.assertIn("no longer valid", blocked_activity["message"])

        status, _headers, page = self.call_bytes("/account")
        self.assertEqual(status, 200)
        self.assertIn(b"DOWNLOAD SAFE SUMMARY", page)
        self.assertIn(b"DOWNLOAD RECOVERY CARD", page)
        self.assertIn(b"Security Activity", page)
        self.assertIn(b"SIGN OUT EVERY DEVICE", page)
        self.assertIn(b"/api/v1/accounts/activity", page)
        self.assertIn(b"/api/v1/accounts/username-availability", page)
        self.assertIn(b"/api/v1/accounts/logout-all", page)
        self.assertIn(b"masked_license_key", page)
        self.assertIn(b"Your session was kept", page)
        self.assertIn(b"error.status===401||error.status===403", page)
        self.assertNotIn(b"COPY LICENSE KEY", page)
        self.assertNotIn(b'<a href="/customer"><button>', page)

    def test_account_help_inbox_is_encrypted_isolated_and_rate_limited(self):
        status, unauthorized = self.call("/api/v1/accounts/support")
        self.assertEqual(status, 401)
        self.assertEqual(unauthorized["error"], "unauthorized")
        status, unauthorized = self.call(
            "/api/v1/accounts/support",
            method="POST",
            payload={
                "category": "bug",
                "subject": "Cannot open vault",
                "message": "The vault button does not open after sign-in.",
            },
        )
        self.assertEqual(status, 401)
        self.assertEqual(unauthorized["error"], "unauthorized")

        status, first = self.call(
            "/api/v1/accounts/register",
            method="POST",
            payload={"username": "Help_User_67", "password": "HelpSecure67!"},
        )
        self.assertEqual(status, 201)
        first_token = first["session_token"]
        first_account_id = first["account"]["account_id"]
        private_subject = "Cannot open personal vault"
        private_message = "The personal vault button stays disabled after I sign in."
        status, created = self.call(
            "/api/v1/accounts/support",
            method="POST",
            payload={
                "category": "bug",
                "subject": private_subject,
                "message": private_message,
            },
            headers={"Authorization": f"Bearer {first_token}"},
        )
        self.assertEqual(status, 201)
        ticket_id = created["ticket"]["ticket_id"]
        self.assertEqual(created["ticket"]["source"], "account")
        stored_text = api.support_ticket_path(ticket_id).read_text(encoding="utf-8")
        self.assertNotIn(private_subject, stored_text)
        self.assertNotIn(private_message, stored_text)
        self.assertNotIn("Help_User_67", stored_text)
        self.assertNotIn("HelpSecure67!", stored_text)

        status, mine = self.call(
            "/api/v1/accounts/support",
            headers={"Authorization": f"Bearer {first_token}"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(mine["count"], 1)
        self.assertEqual(mine["items"][0]["message"], private_message)
        self.assertNotIn("owner_note", mine["items"][0])

        status, second = self.call(
            "/api/v1/accounts/register",
            method="POST",
            payload={"username": "Other_Help_67", "password": "OtherSecure67!"},
        )
        self.assertEqual(status, 201)
        status, other_mine = self.call(
            "/api/v1/accounts/support",
            headers={"Authorization": f"Bearer {second['session_token']}"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(other_mine["count"], 0)

        status, owner_inbox = self.call(
            "/api/v1/admin/support-tickets",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        owner_ticket = next(item for item in owner_inbox["items"] if item["ticket_id"] == ticket_id)
        self.assertEqual(owner_ticket["account_id"], first_account_id)
        self.assertEqual(owner_ticket["account_username"], "Help_User_67")
        self.assertEqual(owner_ticket["source"], "account")
        self.assertEqual(owner_ticket["machine_hash"], "")

        status, updated = self.call(
            "/api/v1/admin/support-tickets/action",
            method="POST",
            payload={
                "ticket_id": ticket_id,
                "status": "in_progress",
                "owner_reply": "I found the issue and am checking the fix.",
                "owner_note": "Private owner-only note",
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(updated["ticket"]["status"], "in_progress")
        status, mine = self.call(
            "/api/v1/accounts/support",
            headers={"Authorization": f"Bearer {first_token}"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(mine["items"][0]["owner_reply"], "I found the issue and am checking the fix.")
        self.assertNotIn("owner_note", mine["items"][0])
        self.assertEqual(
            [entry["author"] for entry in mine["items"][0]["conversation"]],
            ["customer", "owner"],
        )

        status, resolved = self.call(
            "/api/v1/admin/support-tickets/action",
            method="POST",
            payload={
                "ticket_id": ticket_id,
                "status": "resolved",
                "owner_reply": "I found the issue and am checking the fix.",
                "owner_note": "Private owner-only note",
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(resolved["ticket"]["status"], "resolved")

        customer_follow_up = "The fix helped, but the button still needs one extra click."
        status, replied = self.call(
            "/api/v1/accounts/support/reply",
            method="POST",
            payload={"ticket_id": ticket_id, "message": customer_follow_up},
            headers={"Authorization": f"Bearer {first_token}"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(replied["reopened"])
        self.assertEqual(replied["ticket"]["status"], "open")
        self.assertEqual(replied["ticket"]["conversation"][-1]["author"], "customer")
        self.assertEqual(replied["ticket"]["conversation"][-1]["message"], customer_follow_up)
        self.assertNotIn(
            customer_follow_up,
            api.support_ticket_path(ticket_id).read_text(encoding="utf-8"),
        )

        for path in (
            "/api/v1/accounts/support/reply",
            "/api/v1/accounts/support/close",
        ):
            status, hidden = self.call(
                path,
                method="POST",
                payload={
                    "ticket_id": ticket_id,
                    "message": "Another account must not be able to reply.",
                },
                headers={"Authorization": f"Bearer {second['session_token']}"},
            )
            self.assertEqual(status, 404)
            self.assertEqual(hidden["error"], "not_found")

        status, closed = self.call(
            "/api/v1/accounts/support/close",
            method="POST",
            payload={"ticket_id": ticket_id},
            headers={"Authorization": f"Bearer {first_token}"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(closed["closed"])
        self.assertFalse(closed["already_closed"])
        self.assertEqual(closed["ticket"]["status"], "closed")
        status, closed_again = self.call(
            "/api/v1/accounts/support/close",
            method="POST",
            payload={"ticket_id": ticket_id},
            headers={"Authorization": f"Bearer {first_token}"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(closed_again["already_closed"])

        with mock.patch.object(api, "MAX_ACCOUNT_SUPPORT_ACTIONS_PER_HOUR", 2):
            status, action_limited = self.call(
                "/api/v1/accounts/support/reply",
                method="POST",
                payload={"ticket_id": ticket_id, "message": "One action too many."},
                headers={"Authorization": f"Bearer {first_token}"},
            )
        self.assertEqual(status, 429)
        self.assertEqual(action_limited["error"], "rate_limited")

        status, activity = self.call(
            "/api/v1/accounts/activity",
            headers={"Authorization": f"Bearer {first_token}"},
        )
        self.assertEqual(status, 200)
        activity_labels = {item["label"] for item in activity["items"]}
        self.assertIn("Help request sent", activity_labels)
        self.assertIn("Help request reply sent", activity_labels)
        self.assertIn("Help request closed", activity_labels)

        with mock.patch.object(api, "MAX_SUPPORT_TICKETS_PER_DAY", 1):
            status, limited = self.call(
                "/api/v1/accounts/support",
                method="POST",
                payload={
                    "category": "other",
                    "subject": "Second request",
                    "message": "This request should hit the daily account limit.",
                },
                headers={"Authorization": f"Bearer {first_token}"},
            )
        self.assertEqual(status, 429)
        self.assertEqual(limited["error"], "rate_limited")

        status, _headers, page = self.call_bytes("/account")
        self.assertEqual(status, 200)
        self.assertIn(b"Help Inbox", page)
        self.assertIn(b"SEND REQUEST", page)
        self.assertIn(b"/api/v1/accounts/support", page)
        self.assertIn(b"/api/v1/accounts/support/reply", page)
        self.assertIn(b"/api/v1/accounts/support/close", page)
        self.assertIn(b"supportSubject", page)
        self.assertIn(b"supportMessage", page)
        self.assertIn(b"SEND FOLLOW-UP", page)
        self.assertIn(b"CLOSE REQUEST", page)
        self.assertIn(b"COPY FAILED", page)
        status, _headers, owner_page = self.call_bytes("/owner")
        self.assertEqual(status, 200)
        self.assertIn(b"Support Inbox", owner_page)
        self.assertIn(b"SIGNED-IN ACCOUNT", owner_page)
        self.assertIn(b"account_username", owner_page)

    def test_account_username_change_requires_password_and_invalidates_sessions(self):
        status, registered = self.call(
            "/api/v1/accounts/register",
            method="POST",
            payload={"username": "Rename_Start_65", "password": "RenameSecure9!"},
        )
        self.assertEqual(status, 201)
        old_token = registered["session_token"]
        account_id = registered["account"]["account_id"]
        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={"account_id": account_id, "plan_id": "starter"},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)
        assigned_license_id = issued["license"]["license_id"]

        status, wrong_password = self.call(
            "/api/v1/accounts/change-username",
            method="POST",
            payload={
                "new_username": "Rename_Finish_65",
                "current_password": "WrongPassword9!",
            },
            headers={"Authorization": f"Bearer {old_token}"},
        )
        self.assertEqual(status, 403)
        self.assertIn("Current password", wrong_password["message"])

        status, renamed = self.call(
            "/api/v1/accounts/change-username",
            method="POST",
            payload={
                "new_username": "Rename_Finish_65",
                "current_password": "RenameSecure9!",
            },
            headers={"Authorization": f"Bearer {old_token}"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(renamed["account"]["account_id"], account_id)
        self.assertEqual(renamed["account"]["username"], "Rename_Finish_65")
        self.assertEqual(
            renamed["account"]["license"]["license_id"],
            assigned_license_id,
        )
        self.assertNotEqual(renamed["session_token"], old_token)

        status, blocked_old_session = self.call(
            "/api/v1/accounts/me",
            headers={"Authorization": f"Bearer {old_token}"},
        )
        self.assertEqual(status, 401)
        self.assertIn("no longer valid", blocked_old_session["message"])

        status, old_login = self.call(
            "/api/v1/accounts/login",
            method="POST",
            payload={"username": "Rename_Start_65", "password": "RenameSecure9!"},
        )
        self.assertEqual(status, 403)
        status, new_login = self.call(
            "/api/v1/accounts/login",
            method="POST",
            payload={"username": "Rename_Finish_65", "password": "RenameSecure9!"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(new_login["account"]["account_id"], account_id)
        self.assertEqual(
            new_login["account"]["license"]["license_id"],
            assigned_license_id,
        )

        status, activity = self.call(
            "/api/v1/accounts/activity",
            headers={"Authorization": f"Bearer {new_login['session_token']}"},
        )
        self.assertEqual(status, 200)
        self.assertIn("Username changed", {item["label"] for item in activity["items"]})
        self.assertIn(
            "License assignment changed",
            {item["label"] for item in activity["items"]},
        )

        status, old_available = self.call(
            "/api/v1/accounts/username-availability?username=Rename_Start_65"
        )
        self.assertEqual(status, 200)
        self.assertTrue(old_available["available"])
        status, new_taken = self.call(
            "/api/v1/accounts/username-availability?username=Rename_Finish_65"
        )
        self.assertEqual(status, 200)
        self.assertFalse(new_taken["available"])

        status, _headers, page = self.call_bytes("/account")
        self.assertEqual(status, 200)
        self.assertIn(b"CHANGE USERNAME", page)
        self.assertIn(b"/api/v1/accounts/change-username", page)


if __name__ == "__main__":
    unittest.main(verbosity=2)
