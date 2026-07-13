import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from html import escape as html_escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


API_NAME = "VaultLink API"
API_VERSION = "0.19.0"
LEGAL_DOCUMENT_VERSION = "2026-07-12-draft-1"
ROOT_DIR = Path(__file__).resolve().parent
LICENSE_KEY_PREFIX = "vlk1"
LICENSE_RECEIPT_PREFIX = "vlr1"
AUDIT_DOWNLOAD_PREFIX = "vla1"
ACTIVITY_DOWNLOAD_PREFIX = "vlt1"
DEFAULT_SIGNING_SECRET = "vaultlink-dev-signing-secret-change-me"
UPDATE_DIR = ROOT_DIR / "updates"
UPDATE_MANIFEST_PATH = UPDATE_DIR / "windows-manifest.json"
UPDATE_SIGNING_KEY_ID = "4f8fb9b8dbffd4c0"
MAX_UPDATE_MANIFEST_BYTES = 64 * 1024
MAX_UPDATE_PACKAGE_BYTES = 50 * 1024 * 1024
MAX_LICENSE_JSON_BODY_BYTES = 64 * 1024
MAX_SUPPORT_JSON_BODY_BYTES = 32 * 1024
MAX_REJECTED_BODY_DRAIN_BYTES = 1024 * 1024
LICENSE_SYNC_INTERVAL_SECONDS = 60
DEVICE_LAST_SEEN_WRITE_SECONDS = 300
MAX_AUDIT_JSON_BODY_BYTES = 4 * 1024 * 1024
MAX_AUDIT_REPORT_BYTES = 3 * 1024 * 1024
MAX_AUDIT_EVENTS = 20000
MAX_AUDIT_LIST_ITEMS = 500
MAX_SIGNED_TOKEN_CHARS = 32 * 1024
ALLOWED_AUDIT_ACTIONS = frozenset(
    {
        "add_perm_unlock_items",
        "api_audit_download",
        "api_audit_list",
        "application_update",
        "audit_api_export",
        "audit_api_auto_upload",
        "audit_log_export",
        "audit_log_view",
        "application_auto_update",
        "auto_update_setting",
        "audit_viewer_export_locked",
        "audit_viewer_export_raw",
        "audit_viewer_open",
        "backup_app_data",
        "backup_master_key",
        "check_lock_format",
        "compare_backup_key",
        "configuration_change",
        "customer_center_verify",
        "customer_hub_refresh",
        "customer_hub_verify",
        "customer_status_open",
        "create_key",
        "delete_unlocked_temp",
        "delete_unlocked_temp_after_view",
        "delete_unlocked_temp_retry",
        "delete_unlocked_temp_window",
        "export_locked_audit_report",
        "failed_access",
        "find_locked_files",
        "license_issue",
        "license_deactivate",
        "license_device_reset",
        "license_local_clear",
        "license_note_update",
        "license_restore",
        "license_revoke",
        "license_sync",
        "load_key",
        "load_recent_key",
        "lock",
        "lock_note",
        "lock_remove_original",
        "locked_file_browser_scan",
        "login",
        "open_temp_unlocked_file",
        "open_temp_unlocked_text",
        "owner_usb_removed",
        "owner_announcement_view",
        "panic_lock",
        "perm_unlock_workbench_relock",
        "perm_unlock_workbench_relock_copy",
        "perm_unlock_workbench_relock_remove",
        "quick_lock_note",
        "recovery_self_test",
        "restore_app_data",
        "save_personal_vault",
        "scan_personal_files",
        "support_ticket_submit",
        "support_ticket_view",
        "shop_open",
        "unlock",
        "unlock_double_click",
        "upgrade_legacy_lock",
        "usb_key_removed",
        "vault_delete_item",
        "vault_duplicate_item",
        "vault_export_locked",
        "vault_import_text",
        "vault_open",
        "vault_pad_delete",
        "vault_pad_duplicate",
        "vault_pad_export_locked",
        "vault_pad_import_text",
        "vault_pad_open",
        "vault_pad_save",
        "verify_locked_health",
    }
)
try:
    AUDIT_EXPORT_RETENTION_HOURS = min(
        max(int(os.getenv("AUDIT_EXPORT_RETENTION_HOURS", "168")), 1),
        2160,
    )
except ValueError:
    AUDIT_EXPORT_RETENTION_HOURS = 168
AUDIT_EXPORT_DIR = Path(
    os.getenv("AUDIT_EXPORT_DIR", str(ROOT_DIR / "data" / "audit_exports"))
).expanduser()
LICENSE_STATE_DIR = Path(
    os.getenv("LICENSE_STATE_DIR", str(ROOT_DIR / "data" / "license_state"))
).expanduser()
MAX_LICENSE_NOTE_CHARS = 2000
MAX_LICENSE_RECORDS = 500
LICENSE_RECORD_AAD = b"VaultLinkLicenseRecordV1"
SUPPORT_TICKET_AAD = b"VaultLinkSupportTicketV1"
MAX_SUPPORT_TICKETS = 1000
MAX_SUPPORT_TICKETS_PER_DAY = 10
SUPPORT_TICKET_STATUSES = frozenset({"open", "acknowledged", "in_progress", "resolved", "closed"})
SUPPORT_TICKET_CATEGORIES = frozenset({"bug", "crash", "licensing", "update", "security", "idea", "other"})
ANNOUNCEMENT_SEVERITIES = frozenset({"info", "update", "maintenance", "security"})
MAX_ANNOUNCEMENTS = 250
SERVICE_STATUS_MODES = frozenset({"normal", "degraded", "maintenance"})
MAX_API_ACTIVITY_BYTES = 4 * 1024 * 1024
MAX_API_ACTIVITY_ITEMS = 5000
MAX_API_ACTIVITY_ARCHIVES = 5
LICENSE_STATE_LOCK = threading.RLock()


class RequestTooLarge(ValueError):
    pass


class UnsupportedMediaType(ValueError):
    pass


FEATURES = [
    {
        "id": "customer-hub",
        "title": "Customer Hub",
        "summary": "Review privacy-safe license, rank, service, update, and customer-page information without displaying license proof or machine identity.",
        "category": "starter",
    },
    {
        "id": "portable-locking",
        "title": "Portable locking tools",
        "summary": "Create new portable .locked files and manage the main locking queue.",
        "category": "starter",
    },
    {
        "id": "quick-lock-note",
        "title": "Quick lock notes",
        "summary": "Create encrypted text notes quickly from the desktop app.",
        "category": "starter",
    },
    {
        "id": "home-guides",
        "title": "Home safety guides",
        "summary": "Use the home safety checklist, key-custody plan, recovery plan, and fuller home instructions.",
        "category": "home",
    },
    {
        "id": "personal-vault",
        "title": "Personal vault",
        "summary": "Store passcodes, recovery codes, account notes, and private records inside a separate encrypted vault.",
        "category": "personal-plus",
    },
    {
        "id": "locked-file-browser",
        "title": "Locked File Browser",
        "summary": "Browse and launch .locked files from a dedicated companion app.",
        "category": "personal-plus",
    },
    {
        "id": "audit-log-viewer",
        "title": "Audit Log Viewer",
        "summary": "Read, export, and verify the privacy-safe audit trail from the richer companion app.",
        "category": "personal-plus",
    },
    {
        "id": "perm-unlock",
        "title": "PERM UNLOCK workflow",
        "summary": "Edit readable working copies and relock them safely with the dedicated workflow.",
        "category": "personal-plus",
    },
    {
        "id": "personal-safety-report",
        "title": "Personal Safety Report",
        "summary": "Create an anonymous personal report covering Defender, firewall, BitLocker, and update-recency checks.",
        "category": "personal-plus",
    },
    {
        "id": "privacy-safety-hub",
        "title": "Privacy Safety Hub",
        "summary": "Open the dashboard that ties the locker toolkit together.",
        "category": "family-safety",
    },
    {
        "id": "global-breach-guard",
        "title": "Global Breach Guard",
        "summary": "Run the topmost watcher that checks the signed audit trail and raises alerts.",
        "category": "family-safety",
    },
    {
        "id": "text-log-processor",
        "title": "Text Log Processor",
        "summary": "Turn pasted audit-style text logs into cleaner summaries and counts.",
        "category": "family-safety",
    },
    {
        "id": "owner-usb-mode",
        "title": "Owner USB mode",
        "summary": "Tie a PC session to one registered owner USB and relock if that drive disappears.",
        "category": "family-safety",
    },
    {
        "id": "family-device-reports",
        "title": "Family device reports",
        "summary": "Create anonymous family device reports and a family report index without storing account names.",
        "category": "family-safety",
    },
    {
        "id": "office-readiness",
        "title": "Small Office readiness pack",
        "summary": "Build an office readiness report, evidence manifest, policy templates, and operational checklists.",
        "category": "small-office",
    },
    {
        "id": "family-office-bundle",
        "title": "Family Office evidence bundle",
        "summary": "Create multi-PC indexes, anonymous device reports, policy packs, and operational record templates.",
        "category": "family-office",
    },
    {
        "id": "signature-bundle",
        "title": "Owner-signed release bundle",
        "summary": "Verify the complete release manifest and integrity records for a professionally reviewed deployment.",
        "category": "pro-baseline",
    },
    {
        "id": "pro-baseline-pack",
        "title": "Pro Baseline review pack",
        "summary": "Use security templates, a HIPAA-readiness workspace, and professional review materials without claiming certification.",
        "category": "pro-baseline",
    },
]


COMPANION_APPS = [
    {"name": "Privacy Safety Hub", "script": "privacy_safety_hub.py", "purpose": "Launch dashboard for the toolkit."},
    {"name": "Locked File Browser", "script": "locked_file_browser.py", "purpose": "Find .locked files quickly and jump into unlock mode."},
    {"name": "Quick Lock Note", "script": "quick_lock_note.py", "purpose": "Turn pasted text into a locked note fast."},
    {"name": "Key Inspector", "script": "key_inspector.py", "purpose": "Inspect a USB master key and owner-key matching."},
    {"name": "PERM UNLOCK Workbench", "script": "perm_unlock_workbench.py", "purpose": "Manage edit-and-relock items in the PERM UNLOCK folder."},
    {"name": "Personal Vault Pad", "script": "personal_vault_pad.py", "purpose": "Use the vault in a simpler note-style window."},
    {"name": "Audit Log Viewer", "script": "audit_log_viewer.py", "purpose": "Read and export the privacy-safe signed audit trail."},
    {"name": "VaultLink License Issuer", "script": "license_issuer.py", "purpose": "Issue customer licenses through the admin-protected API."},
    {"name": "Text Log Processor", "script": "text_log_processor.py", "purpose": "Parse table-style text logs into a cleaner summary."},
    {"name": "Global Breach Guard", "script": "global_breach_guard.py", "purpose": "Run a topmost global breach watcher."},
]


SECURITY_NOTES = [
    "The public API never unlocks files, never receives USB secrets, and never stores PINs or vault contents.",
    "Desktop encryption and USB-key logic stay in the Windows app instead of moving onto the internet-facing service.",
    "Signed keys and receipts are checked against persistent revocation and anonymous device-seat ledgers.",
    "Owner license keys and private notes are encrypted at rest and available only through admin-token routes.",
    "Audit exports are reduced to privacy-safe fields, require an active licensed machine, and use short-lived signed download links.",
    "Ranks are software and service package descriptions, not HIPAA certification, legal approval, guaranteed protection, or proof of professional review.",
]


PLAN_TIERS = [
    {
        "id": "starter",
        "name": "$5 Starter",
        "price_label": "$5",
        "price_min_usd": 5,
        "price_max_usd": 5,
        "best_for": "One Windows PC and basic locking instructions",
        "rank": 1,
        "includes": [
            "Portable locking tools",
            "Quick lock notes",
            "Microsoft Defender package scan",
            "Signed purchase verification",
            "Core PIN, recovery, and audit tools",
        ],
        "features": [
            "portable-locking",
            "quick-lock-note",
        ],
    },
    {
        "id": "home",
        "name": "$10-$25 Home",
        "price_label": "$10-$25",
        "price_min_usd": 10,
        "price_max_usd": 25,
        "best_for": "A home that needs clearer setup, custody, and recovery guidance",
        "rank": 2,
        "includes": [
            "Everything in Starter",
            "Home safety checklist",
            "Home key-custody plan",
            "Home recovery plan",
            "Fuller home instructions",
        ],
        "features": [
            "home-guides",
        ],
    },
    {
        "id": "personal-plus",
        "name": "$50 Personal Plus",
        "price_label": "$50",
        "price_min_usd": 50,
        "price_max_usd": 50,
        "best_for": "Personal records plus anonymous Windows safety reporting",
        "rank": 3,
        "includes": [
            "Everything in Home",
            "Personal Vault tools",
            "Audit Log Viewer",
            "Locked File Browser",
            "PERM UNLOCK workflow",
            "Anonymous Personal Safety Report",
        ],
        "features": [
            "personal-vault",
            "audit-log-viewer",
            "locked-file-browser",
            "perm-unlock",
            "personal-safety-report",
        ],
    },
    {
        "id": "family-safety",
        "name": "$100 Family Safety",
        "price_label": "$100",
        "price_min_usd": 100,
        "price_max_usd": 100,
        "best_for": "Families managing anonymous safety records across devices",
        "rank": 4,
        "includes": [
            "Everything in Personal Plus",
            "Anonymous Family Device Reports",
            "Family Report Index",
            "Family backup and weekly procedures",
            "Privacy Safety Hub",
            "Global Breach Guard",
            "Text Log Processor",
            "Owner USB mode",
        ],
        "features": [
            "privacy-safety-hub",
            "global-breach-guard",
            "text-log-processor",
            "owner-usb-mode",
            "family-device-reports",
        ],
    },
    {
        "id": "small-office",
        "name": "$200 Small Office",
        "price_label": "$200",
        "price_min_usd": 200,
        "price_max_usd": 200,
        "best_for": "Small offices that need repeatable readiness and evidence workflows",
        "rank": 5,
        "includes": [
            "Everything in Family Safety",
            "Office Readiness Report",
            "SHA-256 evidence manifest",
            "Seven office policy templates",
            "Onboarding, backup, audit, and incident docs",
        ],
        "features": [
            "office-readiness",
        ],
    },
    {
        "id": "family-office",
        "name": "$500-$3,000 Family Office",
        "price_label": "$500-$3,000",
        "price_min_usd": 500,
        "price_max_usd": 3000,
        "best_for": "Multi-PC family offices needing guided setup and records",
        "rank": 6,
        "includes": [
            "Everything in Small Office",
            "Anonymous Office Device Reports",
            "Multi-PC Office Index",
            "Family Office Evidence Bundle",
            "Policy and operational record templates",
            "Adult-led setup and testing as agreed",
        ],
        "features": [
            "family-office-bundle",
        ],
    },
    {
        "id": "pro-baseline",
        "name": "$20,000+ Pro Baseline",
        "price_label": "$20,000+",
        "price_min_usd": 20000,
        "price_max_usd": None,
        "best_for": "A professionally reviewed baseline with formal evidence and policy materials",
        "rank": 7,
        "includes": [
            "Everything in Family Office",
            "Pro security and evidence reports",
            "Owner-signed release manifest",
            "Optional physical USB-bound licensing",
            "HIPAA-readiness workspace, not certification",
            "Professional and legal review materials",
        ],
        "features": [
            "signature-bundle",
            "pro-baseline-pack",
        ],
    },
]


RANK_EXCLUSIVE_TOOLS = [
    {
        "id": "lock-readiness-check",
        "rank": 1,
        "name": "Lock Readiness Check",
        "summary": "A short pre-lock check for backups, keys, and Defender status.",
        "checklist": ["Confirm a current backup exists", "Confirm the USB key opens", "Run a Microsoft Defender scan", "Test one non-critical file first"],
    },
    {
        "id": "usb-custody-card",
        "rank": 1,
        "name": "USB Custody Card",
        "summary": "A printable, identity-free key storage checklist.",
        "checklist": ["Keep the master USB separate from the PC", "Keep a recovery copy in a second safe place", "Do not store a PIN beside the USB", "Record the last recovery test date"],
    },
    {
        "id": "recovery-practice-sheet",
        "rank": 1,
        "name": "Recovery Practice Sheet",
        "summary": "A safe drill using a disposable test file.",
        "checklist": ["Create a disposable test file", "Lock only the test file", "Unlock it with the normal key", "Open and verify the recovered test file"],
    },
    {
        "id": "home-backup-rotation",
        "rank": 2,
        "name": "Home Backup Rotation",
        "summary": "A weekly local backup rotation checklist.",
        "checklist": ["Choose two backup locations", "Alternate the active backup each week", "Verify one restored test file", "Record success without file names or paths"],
    },
    {
        "id": "home-device-setup",
        "rank": 2,
        "name": "Home Device Setup",
        "summary": "A repeatable setup checklist for a household PC.",
        "checklist": ["Install Windows updates", "Confirm Defender is active", "Create the recovery material", "Run a lock and unlock test"],
    },
    {
        "id": "home-recovery-drill",
        "rank": 2,
        "name": "Home Recovery Drill",
        "summary": "A monthly recovery practice plan for the key holder.",
        "checklist": ["Use a non-private test file", "Practice normal unlock", "Practice backup-key recovery", "Confirm the original test data matches"],
    },
    {
        "id": "vault-inventory-builder",
        "rank": 3,
        "name": "Vault Inventory Builder",
        "summary": "A category-only inventory that avoids file names and paths.",
        "checklist": ["Count document categories", "Count recovery records", "Record only totals", "Export without names, paths, or contents"],
    },
    {
        "id": "privacy-summary-builder",
        "rank": 3,
        "name": "Privacy Summary Builder",
        "summary": "A privacy-safe record of license and safety status.",
        "checklist": ["Include rank and status", "Include anonymous device totals", "Include service and release status", "Exclude keys, identities, notes, and paths"],
    },
    {
        "id": "incident-notes-template",
        "rank": 3,
        "name": "Incident Notes Template",
        "summary": "A timestamped incident outline without sensitive contents.",
        "checklist": ["Record the UTC time", "Describe the visible symptom", "Record the safe action taken", "Do not include passwords, keys, names, or file contents"],
    },
    {
        "id": "family-safety-board",
        "rank": 4,
        "name": "Family Safety Board",
        "summary": "An anonymous household readiness board.",
        "checklist": ["Count protected devices", "Mark backup readiness", "Mark recovery-test readiness", "Use device labels instead of personal names"],
    },
    {
        "id": "family-device-rollup",
        "rank": 4,
        "name": "Family Device Rollup",
        "summary": "An aggregate family device status report.",
        "checklist": ["Count active devices", "Count devices needing updates", "Count completed recovery tests", "Exclude machine identifiers and user names"],
    },
    {
        "id": "shared-recovery-drill",
        "rank": 4,
        "name": "Shared Recovery Drill",
        "summary": "An adult-led recovery practice checklist.",
        "checklist": ["Choose a disposable test file", "Confirm the adult key holder is present", "Practice recovery without sharing the key", "Record only completion and date"],
    },
    {
        "id": "office-onboarding-queue",
        "rank": 5,
        "name": "Office Onboarding Queue",
        "summary": "A role-free checklist for preparing office devices.",
        "checklist": ["Confirm approved Windows version", "Confirm Defender status", "Confirm key custody assignment", "Complete a test lock and recovery"],
    },
    {
        "id": "evidence-manifest-builder",
        "rank": 5,
        "name": "Evidence Manifest Builder",
        "summary": "A SHA-256 evidence checklist without file contents.",
        "checklist": ["Create a SHA-256 digest", "Record tool and version", "Record UTC collection time", "Store the manifest separately from the evidence"],
    },
    {
        "id": "policy-review-tracker",
        "rank": 5,
        "name": "Policy Review Tracker",
        "summary": "A schedule for reviewing office safety procedures.",
        "checklist": ["Set a review date", "Assign an adult reviewer", "Record approved changes", "Keep legal and compliance review separate"],
    },
    {
        "id": "multi-pc-rollout-planner",
        "rank": 6,
        "name": "Multi-PC Rollout Planner",
        "summary": "A staged deployment plan for multiple PCs.",
        "checklist": ["Start with one test PC", "Verify backup and recovery", "Deploy in small groups", "Pause rollout after any failed recovery test"],
    },
    {
        "id": "custody-delegation-matrix",
        "rank": 6,
        "name": "Custody Delegation Matrix",
        "summary": "A role-based key custody template without names.",
        "checklist": ["Define primary key-holder role", "Define backup key-holder role", "Separate PIN and USB custody", "Review access after role changes"],
    },
    {
        "id": "evidence-bundle-index",
        "rank": 6,
        "name": "Evidence Bundle Index",
        "summary": "A privacy-safe index for multiple evidence reports.",
        "checklist": ["Use anonymous bundle IDs", "Record report type and UTC time", "Record SHA-256 digest", "Exclude client names, paths, and contents"],
    },
    {
        "id": "release-attestation-center",
        "rank": 7,
        "name": "Release Attestation Center",
        "summary": "A formal release verification checklist.",
        "checklist": ["Verify the release SHA-256", "Record the signing key ID", "Record Defender scan status", "Require adult owner approval before distribution"],
    },
    {
        "id": "control-review-workspace",
        "rank": 7,
        "name": "Control Review Workspace",
        "summary": "A structured control-review preparation pack.",
        "checklist": ["List implemented controls", "Attach privacy-safe evidence references", "Record known limitations", "Send materials to qualified reviewers"],
    },
    {
        "id": "professional-review-handoff",
        "rank": 7,
        "name": "Professional Review Handoff",
        "summary": "A handoff checklist for legal and security reviewers.",
        "checklist": ["State that the product is not certified", "Include threat model and limitations", "Include signed release evidence", "Track reviewer findings and remediation"],
    },
    {
        "id": "defender-baseline-snapshot",
        "rank": 1,
        "name": "Defender Baseline Snapshot",
        "summary": "A simple record of Windows protection readiness.",
        "checklist": ["Confirm real-time protection is on", "Confirm security intelligence is current", "Run a quick scan", "Record only status and UTC time"],
    },
    {
        "id": "key-separation-plan",
        "rank": 1,
        "name": "Key Separation Plan",
        "summary": "A checklist for keeping recovery material separated.",
        "checklist": ["Store the USB away from the PC", "Store the PIN separately", "Keep one recovery copy offline", "Test access without revealing the secret"],
    },
    {
        "id": "update-day-checklist",
        "rank": 2,
        "name": "Home Update Day",
        "summary": "A monthly Windows and app update checklist.",
        "checklist": ["Create a current backup", "Install Windows updates", "Verify Defender status", "Test VaultLink lock and recovery"],
    },
    {
        "id": "backup-verification-log",
        "rank": 2,
        "name": "Backup Verification Log",
        "summary": "A content-free record of successful restore tests.",
        "checklist": ["Choose a disposable test file", "Restore it from backup", "Compare the restored result", "Record date and success only"],
    },
    {
        "id": "secure-sharing-checklist",
        "rank": 3,
        "name": "Secure Sharing Checklist",
        "summary": "A pre-share privacy and recovery review.",
        "checklist": ["Remove unnecessary private fields", "Use an approved transfer method", "Share keys through a separate channel", "Confirm the recipient can open the test package"],
    },
    {
        "id": "sensitive-data-map",
        "rank": 3,
        "name": "Sensitive Data Map",
        "summary": "A category-only map of protected information.",
        "checklist": ["List data categories only", "Assign a protection level", "Mark backup coverage", "Exclude names, paths, values, and file contents"],
    },
    {
        "id": "family-update-day",
        "rank": 4,
        "name": "Family Update Day",
        "summary": "An anonymous household update and recovery session.",
        "checklist": ["Count devices needing updates", "Update one device at a time", "Verify backups before restart", "Complete one family recovery drill"],
    },
    {
        "id": "guardian-safety-review",
        "rank": 4,
        "name": "Guardian Safety Review",
        "summary": "An adult-led review of family key and recovery practices.",
        "checklist": ["Review who holds the master key", "Confirm minors do not hold recovery secrets", "Confirm backup separation", "Record completion without personal names"],
    },
    {
        "id": "incident-triage-board",
        "rank": 5,
        "name": "Incident Triage Board",
        "summary": "A severity-based office incident checklist.",
        "checklist": ["Record symptom and UTC time", "Assign low, medium, high, or critical", "Preserve privacy-safe evidence", "Escalate high-risk events to qualified help"],
    },
    {
        "id": "change-approval-check",
        "rank": 5,
        "name": "Change Approval Check",
        "summary": "A compact pre-release office change review.",
        "checklist": ["Describe the intended change", "Record test evidence", "Confirm rollback steps", "Require an authorized adult approval"],
    },
    {
        "id": "recovery-coverage-map",
        "rank": 6,
        "name": "Recovery Coverage Map",
        "summary": "An anonymous multi-PC recovery coverage report.",
        "checklist": ["Count protected PCs", "Count tested recovery paths", "Identify coverage gaps by anonymous ID", "Schedule the next recovery drill"],
    },
    {
        "id": "deployment-exception-register",
        "rank": 6,
        "name": "Deployment Exception Register",
        "summary": "A privacy-safe record of rollout exceptions.",
        "checklist": ["Assign an anonymous exception ID", "Record the reason category", "Record temporary safeguards", "Set an adult review date"],
    },
    {
        "id": "threat-model-review",
        "rank": 7,
        "name": "Threat Model Review",
        "summary": "A structured review of assets, threats, and safeguards.",
        "checklist": ["List protected asset categories", "List realistic threat actors", "Map implemented safeguards", "Record residual risks for professional review"],
    },
    {
        "id": "audit-readiness-index",
        "rank": 7,
        "name": "Audit Readiness Index",
        "summary": "A preparation checklist for an independent review.",
        "checklist": ["Verify policy review dates", "Verify evidence hashes", "Verify incident records", "List gaps without claiming certification"],
    },
]


RANK_TOOL_MINUTES = {1: 10, 2: 15, 3: 20, 4: 25, 5: 30, 6: 35, 7: 45}


def rank_tool_category(tool_id):
    value = str(tool_id or "").lower()
    categories = (
        ("Recovery", ("recovery", "backup", "custody", "key-separation")),
        ("Evidence", ("evidence", "manifest", "attestation", "audit")),
        ("Governance", ("policy", "control", "professional", "approval", "delegation", "exception")),
        ("Privacy", ("privacy", "vault", "sensitive-data", "secure-sharing")),
        ("Security", ("defender", "incident", "threat", "safety", "update-day", "guardian")),
    )
    for category, terms in categories:
        if any(term in value for term in terms):
            return category
    return "Operations"


PLAN_INDEX = {item["id"]: item for item in PLAN_TIERS}
SHOP_CHECKOUT_ENV_BY_PLAN = {
    "starter": "SHOP_CHECKOUT_STARTER_URL",
    "home": "SHOP_CHECKOUT_HOME_URL",
    "personal-plus": "SHOP_CHECKOUT_PERSONAL_PLUS_URL",
    "family-safety": "SHOP_CHECKOUT_FAMILY_SAFETY_URL",
    "small-office": "SHOP_CHECKOUT_SMALL_OFFICE_URL",
    "family-office": "SHOP_CHECKOUT_FAMILY_OFFICE_URL",
    "pro-baseline": "SHOP_CHECKOUT_PRO_BASELINE_URL",
}
DEFAULT_SHOP_CHECKOUT_HOSTS = frozenset({"buy.stripe.com", "checkout.stripe.com"})
LEGACY_PLAN_ALIASES = {
    "plus": "personal-plus",
    "pro": "family-safety",
    "signature": "small-office",
}


def utc_now():
    return format_utc(datetime.now(timezone.utc))


def format_utc(moment):
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(value):
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text).astimezone(timezone.utc)


def canonical_plan_id(plan_id):
    normalized = str(plan_id or "").strip().lower()
    return LEGACY_PLAN_ALIASES.get(normalized, normalized)


def plan_entitlements(plan_id):
    plan = PLAN_INDEX.get(canonical_plan_id(plan_id))
    if not plan:
        raise ValueError(f"Unknown plan id: {plan_id}")
    unlocked = []
    seen = set()
    for candidate in sorted(PLAN_TIERS, key=lambda item: item["rank"]):
        if candidate["rank"] > plan["rank"]:
            break
        for feature_id in candidate.get("features", []):
            if feature_id in seen:
                continue
            seen.add(feature_id)
            unlocked.append(feature_id)
    return unlocked


def public_plan_payload(plan):
    return {
        "id": plan["id"],
        "name": plan["name"],
        "price_label": plan["price_label"],
        "price_min_usd": plan["price_min_usd"],
        "price_max_usd": plan["price_max_usd"],
        "rank_label": f"Rank {plan['rank']}",
        "best_for": plan["best_for"],
        "rank": plan["rank"],
        "includes": list(plan["includes"]),
        "entitlements": plan_entitlements(plan["id"]),
    }


def shop_checkout_allowed_hosts():
    configured = os.getenv("SHOP_CHECKOUT_ALLOWED_HOSTS", "").strip()
    if not configured:
        return set(DEFAULT_SHOP_CHECKOUT_HOSTS)
    hosts = set()
    for item in configured.split(","):
        host = item.strip().lower().rstrip(".")
        if host and len(host) <= 253 and all(character.isalnum() or character in ".-" for character in host):
            hosts.add(host)
    return hosts or set(DEFAULT_SHOP_CHECKOUT_HOSTS)


def validated_shop_checkout_url(plan_id):
    env_name = SHOP_CHECKOUT_ENV_BY_PLAN.get(canonical_plan_id(plan_id), "")
    raw_url = os.getenv(env_name, "").strip() if env_name else ""
    if not raw_url or len(raw_url) > 2048:
        return ""
    if any(character.isspace() or ord(character) < 32 for character in raw_url):
        return ""
    try:
        parsed = urlparse(raw_url)
        port = parsed.port
    except ValueError:
        return ""
    host = (parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme.lower() != "https"
        or not host
        or host not in shop_checkout_allowed_hosts()
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in (None, 443)
        or parsed.path in ("", "/")
    ):
        return ""
    return raw_url


def shop_plan_payload(plan):
    payload = public_plan_payload(plan)
    checkout_url = validated_shop_checkout_url(plan["id"])
    payload.update(
        {
            "checkout_available": bool(checkout_url),
            "checkout_url": checkout_url,
            "checkout_provider": "hosted checkout",
            "fulfillment": "owner_issues_license_after_payment_confirmation",
        }
    )
    return payload


def shop_payload():
    items = [shop_plan_payload(item) for item in sorted(PLAN_TIERS, key=lambda item: item["rank"])]
    configured_count = sum(bool(item["checkout_available"]) for item in items)
    return {
        "ok": True,
        "name": "VaultLink Shop",
        "items": items,
        "count": len(items),
        "configured_count": configured_count,
        "ready": configured_count > 0,
        "payment_handling": "provider_hosted_checkout_only",
        "card_data_collected_by_vaultlink": False,
        "license_fulfillment": "manual_owner_confirmation",
        "server_time_utc": utc_now(),
    }


SHOP_AUDIENCE_MINIMUM_RANK = {
    "personal": 1,
    "family": 4,
    "office": 5,
    "professional": 7,
}
SHOP_PRIORITY_MINIMUM_RANK = {
    "simple-locking": 1,
    "recovery-guides": 2,
    "private-vault": 3,
    "family-safety": 4,
    "office-evidence": 5,
    "multi-pc": 6,
    "professional-review": 7,
}


def recommend_shop_plan(payload):
    """Return a deterministic, privacy-safe plan recommendation."""
    audience = str(payload.get("audience", "personal") or "personal").strip().lower()
    if audience not in SHOP_AUDIENCE_MINIMUM_RANK:
        raise ValueError("Choose personal, family, office, or professional for audience.")
    raw_priorities = payload.get("priorities", [])
    if not isinstance(raw_priorities, list):
        raise ValueError("priorities must be a list.")
    priorities = []
    for value in raw_priorities:
        priority = str(value or "").strip().lower()
        if priority not in SHOP_PRIORITY_MINIMUM_RANK:
            raise ValueError(f"Unknown priority: {priority or 'blank'}")
        if priority not in priorities:
            priorities.append(priority)
    if len(priorities) > 7:
        raise ValueError("Choose no more than seven priorities.")
    raw_budget = payload.get("max_budget_usd")
    max_budget = None
    if raw_budget not in (None, ""):
        try:
            max_budget = int(raw_budget)
        except (TypeError, ValueError) as exc:
            raise ValueError("max_budget_usd must be a whole number.") from exc
        if max_budget < 5 or max_budget > 100000:
            raise ValueError("max_budget_usd must be between 5 and 100000.")

    target_rank = SHOP_AUDIENCE_MINIMUM_RANK[audience]
    for priority in priorities:
        target_rank = max(target_rank, SHOP_PRIORITY_MINIMUM_RANK[priority])
    ordered = sorted(PLAN_TIERS, key=lambda item: item["rank"])
    target = next(item for item in ordered if item["rank"] >= target_rank)
    affordable = [
        item
        for item in ordered
        if max_budget is None or int(item["price_min_usd"]) <= max_budget
    ]
    if not affordable:
        recommended = ordered[0]
        fit = "over_budget"
    else:
        meeting = [item for item in affordable if item["rank"] >= target_rank]
        if meeting:
            recommended = meeting[0]
            fit = "full"
        else:
            recommended = affordable[-1]
            fit = "partial"

    index = ordered.index(recommended)
    alternatives = []
    for candidate_index in (index - 1, index + 1):
        if 0 <= candidate_index < len(ordered):
            alternatives.append(public_plan_payload(ordered[candidate_index]))
    reasons = [
        f"Audience '{audience}' starts at Rank {SHOP_AUDIENCE_MINIMUM_RANK[audience]}.",
        f"Selected priorities require up to Rank {target_rank}.",
    ]
    if fit == "full":
        reasons.append("This is the lowest-priced rank that meets the selected goals and budget.")
    elif fit == "partial":
        reasons.append("No rank inside the budget meets every goal; this is the strongest affordable option.")
    else:
        reasons.append("The entered budget is below the current starting price.")
    return {
        "ok": True,
        "fit": fit,
        "recommended": shop_plan_payload(recommended),
        "target": public_plan_payload(target),
        "alternatives": alternatives,
        "audience": audience,
        "priorities": priorities,
        "max_budget_usd": max_budget,
        "reasons": reasons,
        "privacy_notice": "Plan Advisor does not request or store a name, email address, payment data, license key, or device identifier.",
        "server_time_utc": utc_now(),
    }


def compare_shop_plans(payload):
    raw_plan_ids = payload.get("plan_ids", [])
    if not isinstance(raw_plan_ids, list):
        raise ValueError("plan_ids must be a list.")
    plan_ids = []
    for value in raw_plan_ids:
        plan_id = canonical_plan_id(value)
        if plan_id not in PLAN_INDEX:
            raise ValueError(f"Unknown plan id: {plan_id or 'blank'}")
        if plan_id not in plan_ids:
            plan_ids.append(plan_id)
    if not 2 <= len(plan_ids) <= 3:
        raise ValueError("Choose two or three different plans to compare.")
    plans = [PLAN_INDEX[plan_id] for plan_id in plan_ids]
    entitlement_ids = []
    for plan in plans:
        for feature_id in plan_entitlements(plan["id"]):
            if feature_id not in entitlement_ids:
                entitlement_ids.append(feature_id)
    items = []
    for plan in plans:
        entitlements = set(plan_entitlements(plan["id"]))
        items.append(
            {
                **shop_plan_payload(plan),
                "entitlement_matrix": {
                    feature_id: feature_id in entitlements for feature_id in entitlement_ids
                },
            }
        )
    highest = max(plans, key=lambda item: item["rank"])
    return {
        "ok": True,
        "count": len(items),
        "items": items,
        "entitlement_ids": entitlement_ids,
        "highest_rank": public_plan_payload(highest),
        "privacy_notice": "Plan comparison is anonymous and does not accept customer, payment, license, device, or file data.",
        "server_time_utc": utc_now(),
    }


def signing_secret():
    return os.getenv("LICENSE_SIGNING_SECRET", DEFAULT_SIGNING_SECRET)


def using_default_signing_secret():
    return signing_secret() == DEFAULT_SIGNING_SECRET


def admin_token_configured():
    return bool(os.getenv("LICENSE_ADMIN_TOKEN", "").strip())


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text):
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode((text + padding).encode("ascii"))


def json_bytes(payload):
    return json.dumps(payload, indent=2).encode("utf-8")


def canonical_json_bytes(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_token(prefix, payload):
    payload_text = b64url_encode(canonical_json_bytes(payload))
    message = f"{prefix}.{payload_text}".encode("utf-8")
    signature = hmac.new(signing_secret().encode("utf-8"), message, hashlib.sha256).digest()
    return f"{prefix}.{payload_text}.{b64url_encode(signature)}"


def verify_token(token, prefix):
    token_text = str(token or "").strip()
    if len(token_text) > MAX_SIGNED_TOKEN_CHARS:
        raise ValueError("Token is too large.")
    parts = token_text.split(".")
    if len(parts) != 3 or parts[0] != prefix:
        raise ValueError("Wrong token format.")
    payload_text = parts[1]
    signature_text = parts[2]
    message = f"{prefix}.{payload_text}".encode("utf-8")
    expected = b64url_encode(hmac.new(signing_secret().encode("utf-8"), message, hashlib.sha256).digest())
    if not hmac.compare_digest(signature_text, expected):
        raise ValueError("Token signature did not verify.")
    payload = json.loads(b64url_decode(payload_text).decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Token payload was not a JSON object.")
    return payload


def current_plan_for_license(license_payload):
    plan_id = canonical_plan_id(license_payload.get("plan_id", ""))
    plan = PLAN_INDEX.get(plan_id)
    if not plan:
        raise ValueError("License refers to an unknown plan.")
    return plan


def license_is_expired(license_payload):
    expires_at = parse_utc(license_payload.get("expires_at_utc"))
    if not expires_at:
        return False
    return expires_at < datetime.now(timezone.utc)


def receipt_is_expired(receipt_payload):
    valid_until = parse_utc(receipt_payload.get("valid_until_utc"))
    if not valid_until:
        return False
    return valid_until < datetime.now(timezone.utc)


def license_state_storage_is_persistent():
    return bool(os.getenv("LICENSE_STATE_DIR", "").strip())


def license_records_secret():
    return os.getenv("LICENSE_RECORDS_SECRET", "").strip() or signing_secret()


def license_record_encryption_key():
    material = ("vaultlink-license-records-v1\0" + license_records_secret()).encode("utf-8")
    return hashlib.sha256(material).digest()


def clean_license_note(value):
    text = "".join(
        character if ord(character) >= 32 and ord(character) != 127 else " "
        for character in str(value or "")
    ).strip()
    text = " ".join(text.split())
    if len(text) > MAX_LICENSE_NOTE_CHARS:
        raise ValueError(f"license_note must be {MAX_LICENSE_NOTE_CHARS} characters or fewer.")
    return text


def validated_license_id(value):
    text = str(value or "").strip()
    if not text or len(text) > 80:
        raise ValueError("license_id must be between 1 and 80 characters.")
    if any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in text):
        raise ValueError("license_id may contain only letters, numbers, hyphens, and underscores.")
    return text


def private_record_path(folder, identity):
    digest = hashlib.sha256(str(identity).encode("utf-8")).hexdigest()
    return LICENSE_STATE_DIR / folder / f"{digest}.json"


def write_private_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(LICENSE_STATE_DIR, 0o700)
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def encrypt_license_private_fields(payload):
    nonce = os.urandom(12)
    encrypted = AESGCM(license_record_encryption_key()).encrypt(
        nonce,
        canonical_json_bytes(payload),
        LICENSE_RECORD_AAD,
    )
    return b64url_encode(nonce + encrypted)


def decrypt_license_private_fields(record):
    encoded = str(record.get("private_blob", "")).strip()
    if not encoded:
        return {}
    packed = b64url_decode(encoded)
    if len(packed) < 29:
        raise ValueError("Stored private license data is damaged.")
    plain = AESGCM(license_record_encryption_key()).decrypt(
        packed[:12],
        packed[12:],
        LICENSE_RECORD_AAD,
    )
    payload = json.loads(plain.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Stored private license data is invalid.")
    return payload


def support_ticket_encryption_key():
    material = ("vaultlink-support-tickets-v1\0" + license_records_secret()).encode("utf-8")
    return hashlib.sha256(material).digest()


def encrypt_support_private_fields(payload):
    nonce = os.urandom(12)
    encrypted = AESGCM(support_ticket_encryption_key()).encrypt(
        nonce,
        canonical_json_bytes(payload),
        SUPPORT_TICKET_AAD,
    )
    return b64url_encode(nonce + encrypted)


def decrypt_support_private_fields(record):
    encoded = str(record.get("private_blob", "")).strip()
    if not encoded:
        return {}
    packed = b64url_decode(encoded)
    if len(packed) < 29:
        raise ValueError("Stored support ticket data is damaged.")
    plain = AESGCM(support_ticket_encryption_key()).decrypt(
        packed[:12],
        packed[12:],
        SUPPORT_TICKET_AAD,
    )
    payload = json.loads(plain.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Stored support ticket data is invalid.")
    return payload


def license_record_path(license_id):
    return private_record_path("licenses", license_id)


def read_license_record(license_id):
    path = license_record_path(license_id)
    if not path.is_file():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("license_id") != license_id:
        raise ValueError("Stored license record identity did not verify.")
    return payload


def stored_license_private_fields(record):
    try:
        return decrypt_license_private_fields(record)
    except Exception:
        return {}


def write_license_record(license_payload, license_key, license_note="", status=None, revocation_note=None):
    license_id = validated_license_id(license_payload.get("license_id"))
    plan = current_plan_for_license(license_payload)
    existing = read_license_record(license_id) or {}
    private_fields = stored_license_private_fields(existing)
    private_fields.update(
        {
            "license_key": str(license_key or private_fields.get("license_key", "")).strip(),
            "license_note": clean_license_note(
                license_note if license_note is not None else private_fields.get("license_note", "")
            ),
            "customer_label": str(license_payload.get("customer_label", "")).strip()[:160],
            "customer_email": str(license_payload.get("customer_email", "")).strip()[:254],
        }
    )
    if revocation_note is not None:
        private_fields["revocation_note"] = clean_license_note(revocation_note)
    now = utc_now()
    selected_status = status or existing.get("status") or "active"
    record = {
        "schema_version": 1,
        "license_id": license_id,
        "plan_id": plan["id"],
        "plan_name": plan["name"],
        "issued_at_utc": str(license_payload.get("issued_at_utc", "")),
        "expires_at_utc": str(license_payload.get("expires_at_utc", "")),
        "max_devices": int(license_payload.get("max_devices", 1) or 1),
        "status": selected_status,
        "revoked_at_utc": existing.get("revoked_at_utc", ""),
        "restored_at_utc": existing.get("restored_at_utc", ""),
        "updated_at_utc": now,
        "private_blob": encrypt_license_private_fields(private_fields),
    }
    if selected_status == "revoked":
        record["revoked_at_utc"] = existing.get("revoked_at_utc") or now
    elif status == "active":
        record["restored_at_utc"] = now if existing else ""
        record["revoked_at_utc"] = ""
    write_private_json(license_record_path(license_id), record)
    return record


def license_is_revoked(license_payload):
    license_id = str(license_payload.get("license_id", "")).strip()
    if not license_id:
        return False
    record = read_license_record(license_id)
    return bool(record and record.get("status") == "revoked")


def license_limit_path(license_id):
    return LICENSE_STATE_DIR / "license_limits" / f"{validated_license_id(license_id)}.json"


def license_limit_payload(license_payload):
    license_id = validated_license_id(license_payload.get("license_id"))
    path = license_limit_path(license_id)
    if not path.is_file():
        return {}
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
    if not isinstance(record, dict) or record.get("license_id") != license_id:
        return {}
    expires_at = parse_utc(record.get("limited_until_utc"))
    if expires_at is None or expires_at <= datetime.now(timezone.utc):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return {}
    return {
        "limited": True,
        "reason": str(record.get("reason", "Limited by the license owner."))[:240],
        "limited_at_utc": str(record.get("limited_at_utc", "")),
        "limited_until_utc": format_utc(expires_at),
    }


def receipt_deactivation_path(receipt):
    return private_record_path("deactivations", receipt)


def receipt_is_deactivated(receipt):
    return bool(receipt and receipt_deactivation_path(receipt).is_file())


def mark_receipt_deactivated(receipt, receipt_payload, app_version=""):
    record = {
        "schema_version": 1,
        "receipt_hash": hashlib.sha256(receipt.encode("utf-8")).hexdigest(),
        "receipt_id": str(receipt_payload.get("receipt_id", ""))[:80],
        "license_id": str(receipt_payload.get("license_id", ""))[:80],
        "machine_hash": hashlib.sha256(str(receipt_payload.get("machine_id", "")).encode("utf-8")).hexdigest()[:16],
        "deactivated_at_utc": utc_now(),
        "app_version": str(app_version or "").strip()[:80],
    }
    write_private_json(receipt_deactivation_path(receipt), record)
    return record


def anonymous_machine_hash(machine_id):
    return hashlib.sha256(str(machine_id or "").encode("utf-8")).hexdigest()[:24]


def activation_folder(license_id):
    license_digest = hashlib.sha256(str(license_id or "").encode("utf-8")).hexdigest()
    return LICENSE_STATE_DIR / "activations" / license_digest


def activation_path(license_id, machine_id):
    return activation_folder(license_id) / f"{anonymous_machine_hash(machine_id)}.json"


def read_activation_record(license_id, machine_id):
    path = activation_path(license_id, machine_id)
    if not path.is_file():
        return None
    record = json.loads(path.read_text(encoding="utf-8"))
    expected_machine_hash = anonymous_machine_hash(machine_id)
    if (
        not isinstance(record, dict)
        or record.get("license_id") != license_id
        or record.get("machine_hash") != expected_machine_hash
    ):
        raise ValueError("Stored activation record identity did not verify.")
    return record


def activation_record_is_active(record):
    if not isinstance(record, dict) or record.get("status") != "active":
        return False
    valid_until = parse_utc(record.get("valid_until_utc"))
    return valid_until is None or valid_until >= datetime.now(timezone.utc)


def activation_records(license_id):
    records = []
    folder = activation_folder(license_id)
    if not folder.is_dir():
        return records
    for path in folder.glob("*.json"):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            machine_hash = str(record.get("machine_hash", "")) if isinstance(record, dict) else ""
            if (
                isinstance(record, dict)
                and record.get("license_id") == license_id
                and machine_hash == path.stem
                and len(machine_hash) == 24
                and all(character in "0123456789abcdef" for character in machine_hash)
            ):
                records.append(record)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    return records


def active_device_count(license_id):
    return sum(activation_record_is_active(record) for record in activation_records(license_id))


def validated_machine_hash(value):
    text = str(value or "").strip().lower()
    if len(text) != 24 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError("machine_hash must be a 24-character anonymous device id.")
    return text


def admin_license_devices(license_id):
    clean_license_id = validated_license_id(license_id)
    if not read_license_record(clean_license_id):
        raise FileNotFoundError("License record was not found.")
    items = []
    for record in activation_records(clean_license_id):
        items.append(
            {
                "machine_hash": str(record.get("machine_hash", "")),
                "status": str(record.get("status", "unknown")),
                "active": activation_record_is_active(record),
                "activated_at_utc": str(record.get("activated_at_utc", "")),
                "valid_until_utc": str(record.get("valid_until_utc", "")),
                "updated_at_utc": str(record.get("updated_at_utc", "")),
                "last_seen_at_utc": str(record.get("last_seen_at_utc", "")),
                "app_version": str(record.get("app_version", "")),
            }
        )
    items.sort(key=lambda item: item.get("updated_at_utc", ""), reverse=True)
    return {
        "ok": True,
        "license_id": clean_license_id,
        "count": len(items),
        "active_count": sum(bool(item.get("active")) for item in items),
        "items": items,
        "privacy": "Device ids are one-way anonymous hashes; PC names and hardware ids are not returned.",
        "server_time_utc": utc_now(),
    }


def write_activation_record(receipt, receipt_payload, status="active", status_time_field=""):
    license_id = validated_license_id(receipt_payload.get("license_id"))
    machine_id = str(receipt_payload.get("machine_id", "")).strip()
    if not machine_id:
        raise ValueError("Activation receipt is missing its machine identity.")
    now = utc_now()
    record = {
        "schema_version": 1,
        "license_id": license_id,
        "machine_hash": anonymous_machine_hash(machine_id),
        "receipt_id": str(receipt_payload.get("receipt_id", ""))[:80],
        "receipt_hash": hashlib.sha256(str(receipt or "").encode("utf-8")).hexdigest(),
        "status": status,
        "activated_at_utc": str(receipt_payload.get("activated_at_utc", "")),
        "valid_until_utc": str(receipt_payload.get("valid_until_utc", "")),
        "app_version": str(receipt_payload.get("app_version", ""))[:80],
        "updated_at_utc": now,
    }
    if status_time_field:
        record[status_time_field] = now
    write_private_json(activation_path(license_id, machine_id), record)
    return record


def register_activation_receipt(license_payload, receipt, receipt_payload):
    license_id = validated_license_id(license_payload.get("license_id"))
    machine_id = str(receipt_payload.get("machine_id", "")).strip()
    max_devices = int(license_payload.get("max_devices", 1) or 1)
    with LICENSE_STATE_LOCK:
        current = read_activation_record(license_id, machine_id)
        current_uses_seat = activation_record_is_active(current)
        used_devices = active_device_count(license_id)
        if not current_uses_seat and used_devices >= max_devices:
            return False, used_devices
        write_activation_record(receipt, receipt_payload, status="active")
        return True, used_devices if current_uses_seat else used_devices + 1


def verify_activation_receipt(license_payload, receipt, receipt_payload, app_version=""):
    license_id = validated_license_id(license_payload.get("license_id"))
    machine_id = str(receipt_payload.get("machine_id", "")).strip()
    with LICENSE_STATE_LOCK:
        record = read_activation_record(license_id, machine_id)
        if record is None:
            registered, used_devices = register_activation_receipt(
                license_payload,
                receipt,
                receipt_payload,
            )
            if not registered:
                return False, "device_limit", used_devices
            return True, "active", used_devices
        if not activation_record_is_active(record):
            return False, str(record.get("status") or "inactive"), active_device_count(license_id)
        receipt_hash = hashlib.sha256(receipt.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(str(record.get("receipt_hash", "")), receipt_hash):
            return False, "receipt_replaced", active_device_count(license_id)
        last_seen = parse_utc(record.get("last_seen_at_utc"))
        now = datetime.now(timezone.utc)
        if last_seen is None or (now - last_seen).total_seconds() >= DEVICE_LAST_SEEN_WRITE_SECONDS:
            record["last_seen_at_utc"] = format_utc(now)
            current_version = str(app_version or "").strip()[:80]
            if current_version:
                record["app_version"] = current_version
            write_private_json(activation_path(license_id, machine_id), record)
        return True, "active", active_device_count(license_id)


def deactivate_activation_record(receipt_payload):
    license_id = validated_license_id(receipt_payload.get("license_id"))
    machine_id = str(receipt_payload.get("machine_id", "")).strip()
    with LICENSE_STATE_LOCK:
        existing = read_activation_record(license_id, machine_id)
        receipt = ""
        if existing:
            receipt = str(existing.get("receipt_hash", ""))
        record = write_activation_record(receipt, receipt_payload, status="deactivated", status_time_field="deactivated_at_utc")
        if existing and existing.get("receipt_hash"):
            record["receipt_hash"] = str(existing.get("receipt_hash"))
            write_private_json(activation_path(license_id, machine_id), record)
        return record


def reset_license_devices(license_payload):
    license_id = validated_license_id(license_payload.get("license_id"))
    reset_count = 0
    with LICENSE_STATE_LOCK:
        for record in activation_records(license_id):
            if not activation_record_is_active(record):
                continue
            record["status"] = "reset"
            record["reset_at_utc"] = utc_now()
            record["updated_at_utc"] = record["reset_at_utc"]
            path = activation_folder(license_id) / f"{record.get('machine_hash', '')}.json"
            write_private_json(path, record)
            reset_count += 1
    return reset_count


def masked_license_key(value):
    text = str(value or "").strip()
    if len(text) < 18:
        return text
    return f"{text[:8]}...{text[-6:]}"


def admin_license_record_view(record, include_private=True):
    private_fields = stored_license_private_fields(record) if include_private else {}
    license_key = str(private_fields.get("license_key", ""))
    license_id = str(record.get("license_id", ""))
    limit = license_limit_payload({"license_id": license_id})
    return {
        "license_id": license_id,
        "plan_id": str(record.get("plan_id", "")),
        "plan_name": str(record.get("plan_name", "")),
        "status": str(record.get("status", "active")),
        "issued_at_utc": str(record.get("issued_at_utc", "")),
        "expires_at_utc": str(record.get("expires_at_utc", "")),
        "max_devices": int(record.get("max_devices", 1) or 1),
        "active_devices": active_device_count(license_id),
        "limited": bool(limit),
        "limit_reason": str(limit.get("reason", "")),
        "limited_until_utc": str(limit.get("limited_until_utc", "")),
        "revoked_at_utc": str(record.get("revoked_at_utc", "")),
        "restored_at_utc": str(record.get("restored_at_utc", "")),
        "updated_at_utc": str(record.get("updated_at_utc", "")),
        "license_key": license_key,
        "masked_license_key": masked_license_key(license_key),
        "license_note": str(private_fields.get("license_note", "")),
        "revocation_note": str(private_fields.get("revocation_note", "")),
        "customer_label": str(private_fields.get("customer_label", "")),
        "customer_email": str(private_fields.get("customer_email", "")),
        "private_data_available": bool(private_fields),
    }


def list_admin_license_records():
    folder = LICENSE_STATE_DIR / "licenses"
    records = []
    if folder.is_dir():
        for path in sorted(folder.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(record, dict) and record.get("license_id"):
                    records.append(admin_license_record_view(record))
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            if len(records) >= MAX_LICENSE_RECORDS:
                break
    return {
        "ok": True,
        "count": len(records),
        "items": records,
        "storage": "persistent_configured" if license_state_storage_is_persistent() else "local_ephemeral",
        "private_fields_encrypted": True,
        "server_time_utc": utc_now(),
    }


def product_payload():
    companion_scripts = sorted(
        {
            "usb_file_locker.py",
            "privacy_safety_hub.py",
            "personal_vault_pad.py",
            "audit_log_viewer.py",
            "license_issuer.py",
            "global_breach_guard.py",
            "text_log_processor.py",
            "locked_file_browser.py",
            "perm_unlock_workbench.py",
            "key_inspector.py",
            "quick_lock_note.py",
            "customer_hub.py",
        }
    )
    return {
        "name": "USB File Locker",
        "api_name": API_NAME,
        "api_version": API_VERSION,
        "tagline": "USB-key file locking, personal vault tools, signed audit tracking, and API-backed licensing.",
        "desktop_scripts": companion_scripts,
        "updated_at_utc": utc_now(),
    }


def docs_payload():
    return {
        "service": API_NAME,
        "version": API_VERSION,
        "license_mode": "signed_tokens_with_revocation_ledger",
        "routes": [
            {"method": "GET", "path": "/", "purpose": "HTML homepage"},
            {"method": "GET", "path": "/shop", "purpose": "Public seven-tier shop with provider-hosted checkout"},
            {"method": "GET", "path": "/customer", "purpose": "Privacy-safe read-only customer license center"},
            {"method": "GET", "path": "/status", "purpose": "Public customer service and signed-release status"},
            {"method": "GET", "path": "/terms", "purpose": "Draft Terms of Use for adult and legal review"},
            {"method": "GET", "path": "/privacy", "purpose": "Public privacy notice and data-handling summary"},
            {"method": "GET", "path": "/owner", "purpose": "Owner-only key and note web console"},
            {"method": "GET", "path": "/owner/insights", "purpose": "Owner-only 50-point operations and readiness command center"},
            {"method": "GET", "path": "/docs", "purpose": "JSON route index"},
            {"method": "GET", "path": "/health", "purpose": "Health check"},
            {"method": "GET", "path": "/api/v1/product", "purpose": "Product metadata"},
            {"method": "GET", "path": "/api/v1/features", "purpose": "Feature catalog"},
            {"method": "GET", "path": "/api/v1/companions", "purpose": "Companion app catalog"},
            {"method": "GET", "path": "/api/v1/plans", "purpose": "Plan and entitlement catalog"},
            {"method": "GET", "path": "/api/v1/ranks", "purpose": "Complete ordered license-rank comparison"},
            {"method": "GET", "path": "/api/v1/shop", "purpose": "Public shop readiness and validated checkout links"},
            {"method": "POST", "path": "/api/v1/shop/recommend", "purpose": "Anonymous audience, priority, and budget plan advisor"},
            {"method": "POST", "path": "/api/v1/shop/compare", "purpose": "Anonymous comparison of two or three license ranks"},
            {"method": "GET", "path": "/api/v1/legal", "purpose": "Public legal-document version and review status"},
            {"method": "GET", "path": "/api/v1/service-status", "purpose": "Public read-only service status"},
            {"method": "GET", "path": "/api/v1/security", "purpose": "Public security and licensing notes"},
            {"method": "GET", "path": "/api/v1/deploy", "purpose": "Railway deploy hints"},
            {"method": "POST", "path": "/api/v1/licenses/issue", "purpose": "Admin-only license issuance"},
            {"method": "POST", "path": "/api/v1/licenses/activate", "purpose": "Machine-bound license activation"},
            {"method": "POST", "path": "/api/v1/licenses/verify", "purpose": "License and receipt verification"},
            {"method": "POST", "path": "/api/v1/licenses/preview", "purpose": "Read-only signed-license status without device activation"},
            {"method": "POST", "path": "/api/v1/licenses/upgrade-options", "purpose": "Privacy-safe higher-rank and added-entitlement comparison"},
            {"method": "POST", "path": "/api/v1/licenses/rank-tools", "purpose": "License-gated cumulative rank-exclusive customer tool packs"},
            {"method": "POST", "path": "/api/v1/licenses/customer-checkup", "purpose": "Privacy-safe license, seat, service, update, and rank-tool attention check"},
            {"method": "POST", "path": "/api/v1/licenses/sync", "purpose": "Automatic client heartbeat with revocation, seat, release, and sync policy"},
            {"method": "POST", "path": "/api/v1/licenses/deactivate", "purpose": "Remove the current machine activation"},
            {"method": "POST", "path": "/api/v1/licenses/revoke", "purpose": "Admin-only license revocation"},
            {"method": "POST", "path": "/api/v1/licenses/restore", "purpose": "Admin-only license restoration"},
            {"method": "POST", "path": "/api/v1/licenses/limit", "purpose": "Admin-only temporary premium-access limit with a customer-visible reason"},
            {"method": "POST", "path": "/api/v1/licenses/unlimit", "purpose": "Admin-only removal of temporary limited status"},
            {"method": "POST", "path": "/api/v1/licenses/note", "purpose": "Admin-only private note update"},
            {"method": "POST", "path": "/api/v1/licenses/reset-devices", "purpose": "Admin-only reset of active device seats"},
            {"method": "POST", "path": "/api/v1/licenses/remove-device", "purpose": "Admin-only removal of one anonymous device seat"},
            {"method": "GET", "path": "/api/v1/admin/licenses", "purpose": "Admin-only encrypted key and note inventory"},
            {"method": "GET", "path": "/api/v1/admin/licenses/{license_id}/devices", "purpose": "Admin-only anonymous device-seat inventory"},
            {"method": "GET", "path": "/api/v1/admin/dashboard", "purpose": "Admin-only license, device, audit, breach, and release totals"},
            {"method": "GET", "path": "/api/v1/admin/insights", "purpose": "Admin-only set of exactly 50 privacy-safe owner operations insights"},
            {"method": "POST", "path": "/api/v1/support-tickets", "purpose": "Licensed privacy-safe customer bug report submission"},
            {"method": "POST", "path": "/api/v1/support-tickets/mine", "purpose": "Licensed customer ticket status and owner replies"},
            {"method": "GET", "path": "/api/v1/admin/support-tickets", "purpose": "Admin-only encrypted support inbox"},
            {"method": "POST", "path": "/api/v1/admin/support-tickets/action", "purpose": "Admin-only acknowledge, resolve, close, note, and reply action"},
            {"method": "POST", "path": "/api/v1/admin/support-tickets/delete", "purpose": "Admin-only permanent support-ticket deletion"},
            {"method": "POST", "path": "/api/v1/announcements/mine", "purpose": "Licensed read-only owner announcements for this plan rank"},
            {"method": "GET", "path": "/api/v1/admin/announcements", "purpose": "Admin-only announcement inventory"},
            {"method": "POST", "path": "/api/v1/admin/announcements/create", "purpose": "Admin-only rank-targeted announcement publishing"},
            {"method": "POST", "path": "/api/v1/admin/announcements/delete", "purpose": "Admin-only announcement deletion"},
            {"method": "POST", "path": "/api/v1/admin/service-status", "purpose": "Admin-only normal, degraded, or maintenance status update"},
            {"method": "GET", "path": "/api/v1/admin/activity", "purpose": "Admin-only tamper-evident API activity feed"},
            {"method": "POST", "path": "/api/v1/admin/activity/download-link", "purpose": "Admin-only short-lived activity export link"},
            {"method": "GET", "path": "/api/v1/admin/activity/download", "purpose": "Signed short-lived API activity JSON download"},
            {"method": "POST", "path": "/api/v1/audit-exports", "purpose": "Upload a privacy-safe audit report from a licensed machine"},
            {"method": "GET", "path": "/api/v1/audit-exports/{export_id}/download", "purpose": "Download an audit export with a short-lived bearer token"},
            {"method": "GET", "path": "/api/v1/admin/audit-exports", "purpose": "Admin-only list of stored audit reports and breach levels"},
            {"method": "GET", "path": "/api/v1/admin/audit-exports/{export_id}/download", "purpose": "Admin-only stored audit report download"},
            {"method": "POST", "path": "/api/v1/admin/audit-exports/download-link", "purpose": "Admin-only two-minute report-scoped browser download link"},
            {"method": "GET", "path": "/api/v1/updates/windows", "purpose": "Signed Windows desktop update manifest and compatibility data"},
            {"method": "GET", "path": "/api/v1/updates/windows/download", "purpose": "SHA-256-pinned Windows desktop update package"},
        ],
        "required_env": [
            {"name": "PORT", "required": False, "purpose": "HTTP bind port on Railway or local runs"},
            {"name": "LICENSE_SIGNING_SECRET", "required": True, "purpose": "HMAC secret for license keys and activation receipts"},
            {"name": "LICENSE_ADMIN_TOKEN", "required": True, "purpose": "Admin-only token required for issuing new licenses"},
            {"name": "LICENSE_STATE_DIR", "required": False, "purpose": "Persistent revocation and encrypted license-record folder; mount a Railway Volume here"},
            {"name": "LICENSE_RECORDS_SECRET", "required": False, "purpose": "Separate encryption secret for saved owner keys and private notes; defaults to the signing secret"},
            {"name": "AUDIT_EXPORT_DIR", "required": False, "purpose": "Persistent audit-export folder; mount a Railway Volume here for durable retention"},
            {"name": "AUDIT_EXPORT_RETENTION_HOURS", "required": False, "purpose": "Stored export lifetime from 1 to 2160 hours; default 168"},
            {"name": "SHOP_CHECKOUT_*_URL", "required": False, "purpose": "Provider-hosted HTTPS checkout URL for each plan; missing tiers stay unavailable"},
            {"name": "SHOP_CHECKOUT_ALLOWED_HOSTS", "required": False, "purpose": "Comma-separated checkout host allowlist; defaults to Stripe hosted-checkout domains"},
        ],
        "request_limits": {
            "license_routes_bytes": MAX_LICENSE_JSON_BODY_BYTES,
            "audit_export_route_bytes": MAX_AUDIT_JSON_BODY_BYTES,
            "audit_events": MAX_AUDIT_EVENTS,
        },
    }


def update_file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def load_windows_update_release():
    if not UPDATE_MANIFEST_PATH.exists():
        raise FileNotFoundError("No Windows update release is published.")
    raw = UPDATE_MANIFEST_PATH.read_bytes()
    if len(raw) > MAX_UPDATE_MANIFEST_BYTES:
        raise ValueError("The update manifest is too large.")
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("The update manifest is invalid.") from exc
    if not isinstance(manifest, dict):
        raise ValueError("The update manifest must be a JSON object.")
    allowed_fields = {
        "schema_version",
        "product",
        "platform",
        "version",
        "minimum_supported_version",
        "published_at_utc",
        "package_filename",
        "download_path",
        "sha256",
        "size_bytes",
        "signing_key_id",
        "notes",
        "preserves_local_app_data",
        "signature",
    }
    if set(manifest) != allowed_fields:
        raise ValueError("The update manifest field set is invalid.")
    if manifest.get("schema_version") != 1:
        raise ValueError("The update manifest schema is not supported.")
    if manifest.get("product") != "USB File Locker" or manifest.get("platform") != "windows-source":
        raise ValueError("The update manifest is for a different product or platform.")
    for field in ("version", "minimum_supported_version"):
        value = str(manifest.get(field, ""))
        if not value or len(value) > 40 or any(part == "" or not part.isdigit() for part in value.split(".")):
            raise ValueError(f"The update manifest {field} is invalid.")
    if clean_audit_time(manifest.get("published_at_utc")) != manifest.get("published_at_utc"):
        raise ValueError("The update manifest timestamp is invalid.")
    filename = str(manifest.get("package_filename", ""))
    if not filename.endswith(".zip") or Path(filename).name != filename or len(filename) > 120:
        raise ValueError("The update package filename is invalid.")
    if manifest.get("download_path") != "/api/v1/updates/windows/download":
        raise ValueError("The update download path is invalid.")
    expected_hash = str(manifest.get("sha256", "")).lower()
    if len(expected_hash) != 64 or any(character not in "0123456789abcdef" for character in expected_hash):
        raise ValueError("The update package SHA-256 is invalid.")
    package_path = UPDATE_DIR / filename
    if not package_path.exists() or not package_path.is_file():
        raise FileNotFoundError("The published update package is missing.")
    size_bytes = package_path.stat().st_size
    if not 0 < size_bytes <= MAX_UPDATE_PACKAGE_BYTES or int(manifest.get("size_bytes", 0)) != size_bytes:
        raise ValueError("The update package size does not match its manifest.")
    if not hmac.compare_digest(update_file_sha256(package_path), expected_hash):
        raise ValueError("The update package hash does not match its manifest.")
    notes = manifest.get("notes")
    if not isinstance(notes, list) or len(notes) > 12 or any(not isinstance(note, str) or len(note) > 240 for note in notes):
        raise ValueError("The update release notes are invalid.")
    if not manifest.get("preserves_local_app_data"):
        raise ValueError("The update package does not declare app-data preservation.")
    signature = str(manifest.get("signature", ""))
    if manifest.get("signing_key_id") != UPDATE_SIGNING_KEY_ID:
        raise ValueError("The update manifest signing key is not recognized.")
    if not 40 <= len(signature) <= 160 or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in signature):
        raise ValueError("The update manifest signature format is invalid.")
    return manifest, package_path


def windows_update_payload():
    manifest, _package_path = load_windows_update_release()
    return {
        "ok": True,
        "api_version": API_VERSION,
        "update": manifest,
        "security": {
            "manifest_signature": "Ed25519",
            "package_integrity": "SHA-256",
            "manual_install_requires_confirmation": True,
            "automatic_install_requires_local_opt_in": True,
        },
        "server_time_utc": utc_now(),
    }


def homepage_html():
    product = product_payload()
    feature_html = "".join(
        f"<li><strong>{item['title']}</strong><br>{item['summary']}</li>"
        for item in FEATURES[:8]
    )
    app_html = "".join(
        f"<li><strong>{item['name']}</strong><br>{item['purpose']}</li>"
        for item in COMPANION_APPS[:6]
    )
    security_html = "".join(f"<li>{line}</li>" for line in SECURITY_NOTES)
    plan_html = "".join(
        (
            f"<article class=\"rank-card rank-{item['rank']}\">"
            f"<div class=\"rank-number\">RANK {item['rank']}</div>"
            f"<h3>{item['name']}</h3>"
            f"<p>{item['best_for']}</p>"
            f"<ul>{''.join(f'<li>{included}</li>' for included in item['includes'])}</ul>"
            f"<div class=\"rank-total\">{len(item['entitlements'])} total entitlements</div>"
            "</article>"
        )
        for item in public_plans()
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{API_NAME}</title>
  <style>
    :root {{
      --bg: #111317;
      --panel: #1a1e25;
      --line: #2a313c;
      --text: #f1f3f5;
      --muted: #aeb7c4;
      --accent: #74e27f;
      --accent-2: #ffd166;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    .wrap {{
      max-width: 1100px;
      margin: 0 auto;
      padding: 36px 20px 56px;
    }}
    .hero {{
      display: grid;
      gap: 18px;
      padding: 28px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #161a20;
    }}
    h1 {{
      margin: 0;
      font-size: clamp(2rem, 4vw, 3.2rem);
      line-height: 1.05;
      letter-spacing: 0;
    }}
    p {{
      margin: 0;
      color: var(--muted);
      line-height: 1.6;
      max-width: 760px;
    }}
    .cta {{
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-top: 6px;
    }}
    .cta a {{
      text-decoration: none;
      color: var(--text);
      padding: 12px 16px;
      border-radius: 8px;
      border: 1px solid var(--line);
      background: var(--panel);
    }}
    .cta a.primary {{
      background: var(--accent);
      color: #09110b;
      border-color: transparent;
      font-weight: 700;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px;
      margin-top: 20px;
    }}
    .rank-section {{
      margin-top: 24px;
      padding: 22px 0 2px;
    }}
    .rank-section h2 {{
      margin: 0 0 6px;
      font-size: 1.45rem;
    }}
    .rank-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 14px;
      margin-top: 16px;
    }}
    .rank-card {{
      min-width: 0;
      background: var(--panel);
      border: 1px solid var(--line);
      border-top: 4px solid var(--accent);
      border-radius: 8px;
      padding: 18px;
    }}
    .rank-card.rank-2 {{ border-top-color: #58b7e8; }}
    .rank-card.rank-3 {{ border-top-color: var(--accent-2); }}
    .rank-card.rank-4 {{ border-top-color: #e58bb8; }}
    .rank-card.rank-5 {{ border-top-color: #ff7b72; }}
    .rank-card.rank-6 {{ border-top-color: #b89cff; }}
    .rank-card.rank-7 {{ border-top-color: #f1f3f5; }}
    .rank-number {{
      color: var(--muted);
      font-size: 0.75rem;
      font-weight: 800;
      margin-bottom: 7px;
    }}
    .rank-card h3 {{
      margin: 0;
      font-size: 1.15rem;
    }}
    .rank-card p {{
      min-height: 76px;
      margin-top: 8px;
      font-size: 0.92rem;
      line-height: 1.45;
    }}
    .rank-card ul {{
      margin-top: 14px;
      font-size: 0.9rem;
    }}
    .rank-total {{
      margin-top: 14px;
      padding-top: 12px;
      border-top: 1px solid var(--line);
      color: var(--text);
      font-size: 0.82rem;
      font-weight: 700;
    }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
    }}
    .card h2 {{
      margin: 0 0 10px;
      font-size: 1.05rem;
    }}
    ul {{
      margin: 0;
      padding-left: 18px;
      color: var(--muted);
      line-height: 1.6;
    }}
    .meta {{
      margin-top: 18px;
      color: var(--muted);
      font-size: 0.95rem;
    }}
    @media (max-width: 900px) {{
      .rank-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .rank-card p {{ min-height: 0; }}
    }}
    @media (max-width: 560px) {{
      .wrap {{ padding: 20px 14px 40px; }}
      .hero {{ padding: 20px; }}
      .rank-grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <div>
        <div style="color: var(--accent-2); font-weight: 700; margin-bottom: 10px;">{product['name']}</div>
        <h1>{API_NAME}</h1>
      </div>
      <p>{product['tagline']}</p>
      <div class="cta">
        <a class="primary" href="/shop">Open Shop</a>
        <a href="/customer">Customer License Center</a>
        <a href="/status">Customer Status</a>
        <a href="/terms">Draft Terms</a>
        <a href="/privacy">Privacy Notice</a>
        <a href="/docs">Open Route Index</a>
        <a href="/owner">Owner Console</a>
        <a href="/api/v1/product">Product JSON</a>
        <a href="/api/v1/ranks">All Ranks JSON</a>
      </div>
      <div class="meta">API version {API_VERSION} - Updated {product['updated_at_utc']}</div>
    </section>
    <section class="rank-section">
      <h2>All License Ranks</h2>
      <p>Every rank is shown below in order, including its price, audience, included tools, and cumulative entitlement count.</p>
      <div class="rank-grid">{plan_html}</div>
    </section>
    <section class="grid">
      <div class="card">
        <h2>Core Features</h2>
        <ul>{feature_html}</ul>
      </div>
      <div class="card">
        <h2>Companion Apps</h2>
        <ul>{app_html}</ul>
      </div>
      <div class="card">
        <h2>Security Shape</h2>
        <ul>{security_html}</ul>
      </div>
    </section>
  </div>
</body>
</html>"""


def customer_status_html():
    service = service_status_payload()
    try:
        manifest, _package = load_windows_update_release()
        desktop_version = str(manifest.get("version", "")) or "Not published"
        published_at = str(manifest.get("published_at_utc", "")) or "Unknown"
        notes = list(manifest.get("notes", []))[:8]
    except (FileNotFoundError, OSError, ValueError):
        desktop_version = "Not published"
        published_at = "Unknown"
        notes = []
    note_html = "".join(f"<li>{html_escape(str(note))}</li>" for note in notes)
    if not note_html:
        note_html = "<li>No signed desktop release notes are available.</li>"
    mode = str(service.get("mode", "normal"))
    mode_label = mode.upper()
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VaultLink Customer Status</title>
  <style>
    :root {{ --bg:#111317; --panel:#1a1e25; --line:#303844; --text:#f1f3f5; --muted:#aeb7c4; --green:#74e27f; --yellow:#ffd166; --red:#ff7b72; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:var(--bg); color:var(--text); font-family:"Segoe UI",Arial,sans-serif; }}
    header {{ border-bottom:1px solid var(--line); }}
    header div, main {{ width:min(920px,calc(100% - 32px)); margin:0 auto; }}
    header div {{ min-height:68px; display:flex; align-items:center; justify-content:space-between; gap:16px; }}
    header a {{ color:var(--muted); text-decoration:none; }}
    main {{ padding:32px 0 52px; }}
    h1 {{ margin:0; font-size:2rem; letter-spacing:0; }}
    .lead {{ margin:8px 0 24px; color:var(--muted); line-height:1.6; }}
    .grid {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px; }}
    section {{ border:1px solid var(--line); background:var(--panel); padding:20px; border-radius:8px; min-width:0; }}
    section.full {{ grid-column:1 / -1; }}
    label {{ display:block; color:var(--muted); font-size:.76rem; font-weight:700; text-transform:uppercase; }}
    strong {{ display:block; margin-top:8px; font-size:1.35rem; overflow-wrap:anywhere; }}
    .mode {{ color:{'var(--green)' if mode == 'normal' else 'var(--yellow)' if mode == 'degraded' else 'var(--red)'}; }}
    p,li {{ color:var(--muted); line-height:1.55; overflow-wrap:anywhere; }}
    ul {{ padding-left:20px; }}
    @media(max-width:620px) {{ .grid {{ grid-template-columns:1fr; }} section.full {{ grid-column:auto; }} header div {{ align-items:flex-start; flex-direction:column; padding:16px 0; }} }}
  </style>
</head>
<body>
  <header><div><strong>VaultLink</strong><nav><a href="/">HOME</a> &nbsp; <a href="/shop">SHOP</a> &nbsp; <a href="/terms">TERMS</a> &nbsp; <a href="/privacy">PRIVACY</a></nav></div></header>
  <main>
    <h1>Customer Status</h1>
    <p class="lead">Public service and signed-release information. This page does not request or display license keys, device identifiers, files, or account data.</p>
    <div class="grid">
      <section><label>Service mode</label><strong class="mode">{html_escape(mode_label)}</strong><p>{html_escape(str(service.get('message', '')))}</p></section>
      <section><label>Latest signed desktop release</label><strong>{html_escape(desktop_version)}</strong><p>Published {html_escape(published_at)}</p></section>
      <section><label>API version</label><strong>{API_VERSION}</strong><p>Live service metadata only.</p></section>
      <section><label>Update protection</label><strong>Ed25519 + SHA-256</strong><p>Automatic installation requires a local opt-in and remains blocked in Git working folders.</p></section>
      <section class="full"><label>Release notes</label><ul>{note_html}</ul></section>
    </div>
  </main>
</body>
</html>"""


def legal_payload():
    return {
        "ok": True,
        "document_version": LEGAL_DOCUMENT_VERSION,
        "terms_path": "/terms",
        "privacy_path": "/privacy",
        "draft": True,
        "adult_business_owner_review_required": True,
        "qualified_legal_review_recommended": True,
        "not_legal_advice": True,
        "server_time_utc": utc_now(),
    }


def legal_document_html(document):
    if document == "privacy":
        title = "Privacy Notice"
        summary = "How VaultLink handles licensing, support, audit, and update data."
        sections = [
            ("Local data", "USB key secrets, optional PINs, vault contents, locked-file contents, full paths, and local audit keys remain on the customer PC unless the customer explicitly exports a privacy-safe report."),
            ("Licensing", "The API stores a signed license record, encrypted private license fields, one-way anonymous device hashes, app version, device-seat status, and coarse last-sync time. It does not store PC names or raw machine identifiers."),
            ("Support", "A customer chooses the text sent in a bug report. Ticket text and owner replies are encrypted at rest. Files and local logs are never attached automatically."),
            ("Audit exports", "Only approved privacy-safe fields are accepted. Raw files, file contents, USB secrets, passwords, PINs, client names, and full paths are rejected or removed."),
            ("Payments", "Checkout happens on an allowlisted payment provider. VaultLink does not collect or store card numbers. The business owner remains responsible for the provider account and required notices."),
            ("Retention and deletion", "The owner can delete support tickets and license records through authorized tools. Stored audit exports expire according to the configured retention period. Local customer data is controlled from the customer PC."),
        ]
    else:
        title = "Draft Terms of Use"
        summary = "A plain-language starting template for the adult business owner and qualified counsel to review."
        sections = [
            ("Draft status", "These terms are a software-generated draft, not legal advice, and are not ready for commercial use until reviewed and approved by the adult business owner. Qualified legal review is recommended."),
            ("Service", "VaultLink provides local file-locking tools, licensing, signed updates, privacy-safe audit features, support messaging, and related customer utilities. Features vary by license rank."),
            ("Authorized use", "Customers must use the software only on devices and files they own or are authorized to manage. The software may not be used to access another person's data, evade security controls, or violate law."),
            ("Keys and backups", "Customers are responsible for protecting and backing up USB keys and remembering optional PINs. Lost keys or forgotten PINs can make locked data unrecoverable."),
            ("Licenses and payments", "License duration, device limits, price, refund terms, taxes, and support commitments must be clearly stated by the adult business owner. Payment-provider records do not automatically create a software license."),
            ("Updates and security", "Automatic installation requires local opt-in. Every published update must pass the embedded Ed25519 manifest check and SHA-256 package check. No software can promise complete protection from every threat or data loss."),
            ("Warranty and liability", "The adult business owner and qualified counsel must supply legally appropriate warranty, liability, dispute, governing-law, cancellation, and consumer-rights terms for every place the product is offered."),
            ("Contact and changes", "The adult business owner must publish accurate business contact information and notify customers when approved terms materially change. This draft intentionally contains no invented address, company registration, or legal contact."),
        ]
    section_html = "".join(
        f"<section><h2>{html_escape(heading)}</h2><p>{html_escape(body)}</p></section>"
        for heading, body in sections
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VaultLink {html_escape(title)}</title>
  <style>
    :root {{ --bg:#111317; --panel:#1a1e25; --line:#303844; --text:#f1f3f5; --muted:#aeb7c4; --green:#74e27f; --yellow:#ffd166; }}
    * {{ box-sizing:border-box; }} body {{ margin:0; background:var(--bg); color:var(--text); font-family:"Segoe UI",Arial,sans-serif; }}
    header {{ border-bottom:1px solid var(--line); }} header div, main {{ width:min(880px,calc(100% - 32px)); margin:0 auto; }}
    header div {{ min-height:68px; display:flex; align-items:center; justify-content:space-between; gap:16px; }}
    nav a {{ color:var(--muted); text-decoration:none; margin-left:14px; }} main {{ padding:32px 0 56px; }}
    .draft {{ color:var(--yellow); font-size:.78rem; font-weight:800; }} h1 {{ margin:7px 0 8px; font-size:2rem; letter-spacing:0; }}
    .lead {{ color:var(--muted); line-height:1.6; margin:0 0 22px; }} section {{ border-top:1px solid var(--line); padding:18px 0; }}
    h2 {{ margin:0 0 7px; font-size:1.02rem; }} p {{ margin:0; color:var(--muted); line-height:1.65; overflow-wrap:anywhere; }}
    .meta {{ margin-top:20px; color:var(--green); font-size:.84rem; }}
    @media(max-width:600px) {{ header div {{ align-items:flex-start; flex-direction:column; padding:16px 0; }} nav a {{ margin:0 14px 0 0; }} }}
  </style>
</head>
<body>
  <header><div><strong>VaultLink</strong><nav><a href="/status">STATUS</a><a href="/terms">TERMS</a><a href="/privacy">PRIVACY</a></nav></div></header>
  <main>
    <div class="draft">DRAFT FOR ADULT AND LEGAL REVIEW</div>
    <h1>{html_escape(title)}</h1>
    <p class="lead">{html_escape(summary)}</p>
    {section_html}
    <div class="meta">Document version {LEGAL_DOCUMENT_VERSION}</div>
  </main>
</body>
</html>"""


def shop_html():
    shop = shop_payload()
    cards = []
    for item in shop["items"]:
        included = "".join(f"<li>{html_escape(str(value))}</li>" for value in item["includes"])
        if item["checkout_available"]:
            action = (
                f'<a class="buy" href="{html_escape(item["checkout_url"], quote=True)}" '
                'target="_blank" rel="noopener noreferrer">BUY THROUGH SECURE CHECKOUT</a>'
            )
        else:
            action = '<span class="unavailable" aria-disabled="true">NOT ON SALE YET</span>'
        cards.append(
            f'<article class="plan rank-{item["rank"]}" data-available="{str(item["checkout_available"]).lower()}" '
            f'data-search="{html_escape(" ".join([item["name"], item["best_for"], *item["includes"]]).lower(), quote=True)}">'
            f'<div class="rank">RANK {item["rank"]}</div>'
            f'<h2>{html_escape(item["name"])}</h2>'
            f'<div class="price">{html_escape(item["price_label"])}</div>'
            f'<p>{html_escape(item["best_for"])}</p>'
            f'<ul>{included}</ul>'
            f'<div class="entitlements">{len(item["entitlements"])} cumulative entitlements</div>'
            f'<label class="compare-choice"><input class="compare-plan" type="checkbox" value="{html_escape(item["id"], quote=True)}"> ADD TO COMPARE</label>'
            f'{action}</article>'
        )
    readiness = (
        f'{shop["configured_count"]} of {shop["count"]} checkout links are live.'
        if shop["configured_count"]
        else "Checkout is not open yet. No tier can accept payment until the owner configures its hosted link."
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VaultLink Shop</title>
  <style>
    :root {{ --bg:#101216; --surface:#191d23; --line:#303741; --text:#f5f6f7; --muted:#b5bec9; --green:#72e184; --blue:#69bce8; --yellow:#ffd166; --red:#ff8278; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:var(--bg); color:var(--text); font-family:"Segoe UI",Arial,sans-serif; }}
    header {{ border-bottom:1px solid var(--line); background:#14171c; }}
    header > div, main, footer > div {{ width:min(1180px,calc(100% - 32px)); margin:0 auto; }}
    header > div {{ display:flex; align-items:center; justify-content:space-between; gap:18px; min-height:72px; }}
    .brand {{ font-size:1.05rem; font-weight:800; }}
    nav {{ display:flex; gap:10px; flex-wrap:wrap; }}
    nav a {{ color:var(--text); text-decoration:none; padding:9px 12px; border:1px solid var(--line); border-radius:6px; }}
    main {{ padding:42px 0 54px; }}
    .intro {{ max-width:800px; margin-bottom:26px; }}
    h1 {{ margin:0; font-size:clamp(2.1rem,5vw,4rem); line-height:1; letter-spacing:0; }}
    .intro p {{ color:var(--muted); line-height:1.6; margin:14px 0 0; }}
    .ready {{ display:inline-block; margin-top:16px; padding:8px 10px; border-left:4px solid var(--yellow); background:#212026; color:var(--text); }}
    .advisor {{ margin:0 0 22px; padding:18px; border:1px solid var(--line); border-radius:8px; background:#171c22; }}
    .advisor h2 {{ margin:0; font-size:1.1rem; }}
    .advisor-grid {{ display:grid; grid-template-columns:1fr 1fr 1.2fr auto; gap:10px; margin-top:14px; align-items:end; }}
    label {{ display:block; margin-bottom:6px; color:var(--muted); font-size:.72rem; font-weight:800; text-transform:uppercase; }}
    select,input {{ width:100%; min-width:0; height:42px; padding:0 10px; border:1px solid var(--line); border-radius:5px; background:#0f1318; color:var(--text); font:inherit; }}
    button {{ min-height:42px; padding:0 14px; border:0; border-radius:5px; background:var(--blue); color:#071119; font-weight:800; cursor:pointer; }}
    #advisorResult {{ min-height:22px; margin-top:12px; color:var(--muted); line-height:1.5; }}
    #advisorResult strong {{ color:var(--green); }}
    .compare-tray {{ display:grid; grid-template-columns:minmax(0,1fr) auto; gap:12px; align-items:center; margin:0 0 18px; padding:14px; border:1px solid var(--line); border-radius:8px; background:#151a20; }}
    #compareResult {{ min-width:0; color:var(--muted); line-height:1.5; overflow-wrap:anywhere; }}
    #compareResult strong {{ color:var(--green); }}
    .catalog-tools {{ display:grid; grid-template-columns:minmax(0,1fr) auto; gap:12px; align-items:end; margin:0 0 14px; }}
    .toggle {{ display:flex; align-items:center; gap:8px; min-height:42px; color:var(--muted); white-space:nowrap; }}
    .toggle input {{ width:18px; height:18px; }}
    .hidden {{ display:none!important; }}
    .plans {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:16px; }}
    .plan {{ display:flex; min-width:0; flex-direction:column; padding:20px; background:var(--surface); border:1px solid var(--line); border-top:4px solid var(--green); border-radius:8px; }}
    .plan.rank-2 {{ border-top-color:var(--blue); }} .plan.rank-3 {{ border-top-color:var(--yellow); }} .plan.rank-4 {{ border-top-color:#ef98bd; }}
    .plan.rank-5 {{ border-top-color:var(--red); }} .plan.rank-6 {{ border-top-color:#bca3ff; }} .plan.rank-7 {{ border-top-color:#f5f6f7; }}
    .rank {{ color:var(--muted); font-size:.75rem; font-weight:800; }}
    h2 {{ margin:7px 0 0; font-size:1.2rem; letter-spacing:0; }}
    .price {{ margin-top:10px; font-size:1.8rem; font-weight:800; color:var(--green); }}
    .plan p {{ min-height:72px; color:var(--muted); line-height:1.5; }}
    ul {{ flex:1; margin:0; padding-left:19px; color:var(--muted); line-height:1.55; }}
    .entitlements {{ margin:17px 0 12px; padding-top:12px; border-top:1px solid var(--line); font-size:.82rem; font-weight:700; }}
    .compare-choice {{ display:flex; align-items:center; gap:8px; min-height:38px; margin:0 0 8px; color:var(--muted); font-size:.72rem; font-weight:800; }}
    .compare-choice input {{ width:18px; height:18px; }}
    .buy,.unavailable {{ display:block; width:100%; min-height:44px; padding:12px; border-radius:6px; text-align:center; font-size:.82rem; font-weight:800; }}
    .buy {{ background:var(--green); color:#071109; text-decoration:none; }}
    .buy:hover {{ background:#8aeb96; }}
    .unavailable {{ border:1px solid var(--line); color:var(--muted); background:#12151a; }}
    footer {{ border-top:1px solid var(--line); background:#14171c; }}
    footer > div {{ padding:24px 0 32px; color:var(--muted); line-height:1.6; }}
    footer strong {{ color:var(--text); }}
    @media (max-width:800px) {{ .advisor-grid {{ grid-template-columns:1fr 1fr; }} }}
    @media (max-width:620px) {{ header > div {{ align-items:flex-start; flex-direction:column; padding:16px 0; }} main {{ padding-top:28px; }} .advisor-grid,.catalog-tools,.compare-tray {{ grid-template-columns:1fr; }} .plans {{ grid-template-columns:1fr; }} .plan p {{ min-height:0; }} .toggle {{ white-space:normal; }} }}
  </style>
</head>
<body>
  <header><div><div class="brand">VaultLink</div><nav><a href="/">HOME</a><a href="/customer">CUSTOMER</a><a href="/owner">OWNER</a></nav></div></header>
  <main>
    <section class="intro">
      <h1>VaultLink Shop</h1>
      <p>Choose a Windows USB File Locker rank. Payments open only on the payment provider's hosted checkout page; this site does not collect card numbers.</p>
      <div class="ready">{html_escape(readiness)}</div>
    </section>
    <section class="advisor" aria-labelledby="advisorTitle">
      <h2 id="advisorTitle">Plan Advisor</h2>
      <div class="advisor-grid">
        <div><label for="audience">For</label><select id="audience"><option value="personal">Personal</option><option value="family">Family</option><option value="office">Office</option><option value="professional">Professional review</option></select></div>
        <div><label for="budget">Maximum budget, USD</label><input id="budget" type="number" min="5" max="100000" step="1" placeholder="No maximum"></div>
        <div><label for="priority">Main priority</label><select id="priority"><option value="simple-locking">Simple locking</option><option value="recovery-guides">Recovery guides</option><option value="private-vault">Private vault</option><option value="family-safety">Family safety</option><option value="office-evidence">Office evidence</option><option value="multi-pc">Multiple PCs</option><option value="professional-review">Professional review</option></select></div>
        <button id="recommend" type="button">RECOMMEND</button>
      </div>
      <div id="advisorResult" role="status" aria-live="polite">Choose your needs to see the lowest matching rank.</div>
    </section>
    <section class="compare-tray" aria-label="Plan comparison">
      <div id="compareResult" role="status" aria-live="polite">Select two or three ranks below.</div>
      <button id="comparePlans" type="button">COMPARE SELECTED</button>
    </section>
    <div class="catalog-tools">
      <div><label for="planSearch">Search plans and included tools</label><input id="planSearch" type="search" placeholder="Search"></div>
      <label class="toggle"><input id="availableOnly" type="checkbox"> Show available checkout only</label>
    </div>
    <section class="plans">{''.join(cards)}</section>
  </main>
  <footer><div><strong>How delivery works:</strong> after the payment provider confirms payment, the owner issues the matching VaultLink license. A checkout receipt is not itself a license key. The plans are software packages, not HIPAA certification or a guarantee against data loss, malware, or legal risk.</div></footer>
  <script>
    const plans=[...document.querySelectorAll(".plan")];
    function filterPlans() {{
      const query=document.getElementById("planSearch").value.trim().toLowerCase();
      const availableOnly=document.getElementById("availableOnly").checked;
      plans.forEach((card) => {{
        const matchesText=!query || card.dataset.search.includes(query);
        const matchesAvailability=!availableOnly || card.dataset.available==="true";
        card.classList.toggle("hidden",!(matchesText && matchesAvailability));
      }});
    }}
    async function recommend() {{
      const output=document.getElementById("advisorResult");
      const budget=document.getElementById("budget").value.trim();
      const payload={{audience:document.getElementById("audience").value,priorities:[document.getElementById("priority").value]}};
      if (budget) payload.max_budget_usd=Number(budget);
      output.textContent="Checking the plan catalog...";
      try {{
        const response=await fetch("/api/v1/shop/recommend",{{method:"POST",headers:{{"Content-Type":"application/json","Accept":"application/json"}},body:JSON.stringify(payload),cache:"no-store",redirect:"error"}});
        const result=await response.json();
        if (!response.ok) throw new Error(result.message || "Recommendation failed.");
        output.replaceChildren();
        const strong=document.createElement("strong"); strong.textContent=result.recommended.name;
        output.append(strong,document.createTextNode(`: ${{result.reasons[result.reasons.length-1]}}`));
      }} catch (error) {{ output.textContent=error.message || "Recommendation failed."; }}
    }}
    async function compareSelected() {{
      const output=document.getElementById("compareResult");
      const planIds=[...document.querySelectorAll(".compare-plan:checked")].map((input) => input.value);
      if (planIds.length < 2 || planIds.length > 3) {{ output.textContent="Choose two or three ranks to compare."; return; }}
      output.textContent="Comparing selected ranks...";
      try {{
        const response=await fetch("/api/v1/shop/compare",{{method:"POST",headers:{{"Content-Type":"application/json","Accept":"application/json"}},body:JSON.stringify({{plan_ids:planIds}}),cache:"no-store",redirect:"error"}});
        const result=await response.json();
        if (!response.ok) throw new Error(result.message || "Comparison failed.");
        output.replaceChildren();
        const strong=document.createElement("strong"); strong.textContent=result.items.map((item) => item.name).join(" vs ");
        output.append(strong,document.createTextNode(`. Highest selected: ${{result.highest_rank.name}} with ${{result.entitlement_ids.length}} cumulative entitlement types in the comparison.`));
      }} catch (error) {{ output.textContent=error.message || "Comparison failed."; }}
    }}
    document.querySelectorAll(".compare-plan").forEach((input) => input.addEventListener("change",() => {{
      const selected=[...document.querySelectorAll(".compare-plan:checked")];
      if (selected.length > 3) {{ input.checked=false; document.getElementById("compareResult").textContent="You can compare up to three ranks."; }}
      else document.getElementById("compareResult").textContent=selected.length ? `${{selected.length}} rank${{selected.length===1?"":"s"}} selected.` : "Select two or three ranks below.";
    }}));
    document.getElementById("planSearch").addEventListener("input",filterPlans);
    document.getElementById("availableOnly").addEventListener("change",filterPlans);
    document.getElementById("recommend").addEventListener("click",recommend);
    document.getElementById("comparePlans").addEventListener("click",compareSelected);
  </script>
</body>
</html>"""


def customer_license_center_html():
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VaultLink Customer License Center</title>
  <style>
    :root { --bg:#0f1216; --surface:#171c22; --surface2:#202731; --line:#34404c; --text:#f4f7f8; --muted:#aeb9c4; --green:#69df8a; --blue:#69bce8; --yellow:#ffd166; --red:#ff8278; }
    * { box-sizing:border-box; }
    body { margin:0; min-width:0; background:var(--bg); color:var(--text); font-family:"Segoe UI",Arial,sans-serif; }
    header { border-bottom:1px solid var(--line); background:#14181d; }
    header > div, main, footer > div { width:min(1040px,calc(100% - 32px)); margin:0 auto; }
    header > div { min-height:68px; display:flex; align-items:center; justify-content:space-between; gap:16px; }
    .brand { font-weight:800; }
    nav { display:flex; gap:8px; flex-wrap:wrap; }
    nav a { color:var(--text); text-decoration:none; border:1px solid var(--line); border-radius:6px; padding:8px 11px; }
    main { padding:38px 0 54px; }
    .top { display:grid; grid-template-columns:minmax(0,1.15fr) minmax(280px,.85fr); gap:18px; align-items:start; }
    h1 { margin:0; max-width:680px; font-size:clamp(2rem,5vw,3.8rem); line-height:1.02; letter-spacing:0; }
    .lead { color:var(--muted); line-height:1.55; max-width:680px; }
    .privacy { margin-top:18px; padding:13px 14px; border-left:4px solid var(--blue); background:#171e25; color:var(--muted); line-height:1.45; }
    .panel { padding:18px; background:var(--surface); border:1px solid var(--line); border-radius:8px; }
    label { display:block; margin-bottom:7px; color:var(--muted); font-size:.75rem; font-weight:800; text-transform:uppercase; }
    input { width:100%; min-width:0; height:44px; padding:0 12px; border:1px solid var(--line); border-radius:5px; background:#0d1116; color:var(--text); font:inherit; }
    .secondary-field { margin-top:11px; }
    .actions { display:grid; grid-template-columns:1fr auto; gap:9px; margin-top:10px; }
    button { min-height:42px; border:0; border-radius:5px; padding:0 14px; font-weight:800; cursor:pointer; }
    #check { background:var(--green); color:#061109; }
    #clear { background:var(--surface2); color:var(--text); border:1px solid var(--line); }
    #status { min-height:23px; margin-top:12px; color:var(--muted); line-height:1.4; }
    #status.good { color:var(--green); } #status.bad { color:var(--red); } #status.warn { color:var(--yellow); }
    #result { margin-top:20px; }
    .empty { padding:30px 18px; border:1px dashed var(--line); border-radius:8px; color:var(--muted); text-align:center; }
    .summary { display:grid; grid-template-columns:minmax(0,1.3fr) repeat(5,minmax(112px,.55fr)); border:1px solid var(--line); border-radius:8px; overflow:hidden; }
    .summary > div { min-width:0; padding:17px; background:var(--surface); border-right:1px solid var(--line); }
    .summary > div:last-child { border-right:0; }
    .eyebrow { color:var(--muted); font-size:.72rem; font-weight:800; text-transform:uppercase; }
    .value { margin-top:6px; font-size:1.05rem; font-weight:800; overflow-wrap:anywhere; }
    .badge { display:inline-flex; align-items:center; min-height:28px; padding:0 9px; border-radius:4px; background:#203329; color:var(--green); }
    .badge.warn { background:#3a321c; color:var(--yellow); } .badge.bad { background:#3b2324; color:var(--red); }
    .message { margin-top:12px; padding:14px; background:#181f26; border-left:4px solid var(--blue); color:var(--muted); line-height:1.5; }
    .checkup { margin-top:16px; }
    .checkup-head { display:flex; justify-content:space-between; gap:12px; align-items:end; margin-bottom:10px; }
    .checkup-head p { margin:0; color:var(--muted); font-size:.85rem; }
    .checkup-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:10px; }
    .checkup-item { min-width:0; padding:14px; border:1px solid var(--line); border-top:3px solid var(--blue); border-radius:8px; background:var(--surface); }
    .checkup-item.good { border-top-color:var(--green); } .checkup-item.check { border-top-color:var(--yellow); } .checkup-item.action { border-top-color:var(--red); }
    .checkup-item h3 { margin:5px 0; font-size:.96rem; }
    .checkup-item p { margin:0; color:var(--muted); line-height:1.45; }
    .dashboard-actions { display:flex; gap:8px; flex-wrap:wrap; margin-top:12px; }
    .dashboard-actions button,.dashboard-actions a { display:inline-flex; align-items:center; justify-content:center; min-height:40px; padding:0 12px; border-radius:5px; background:var(--surface2); border:1px solid var(--line); color:var(--text); text-decoration:none; font-size:.78rem; font-weight:800; }
    .dashboard-actions .primary-action { background:var(--blue); border-color:var(--blue); color:#071119; }
    .details { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:14px; margin-top:14px; }
    .details section { min-width:0; padding:18px; border:1px solid var(--line); border-radius:8px; background:var(--surface); }
    h2 { margin:0 0 13px; font-size:1rem; }
    ul { margin:0; padding-left:19px; color:var(--muted); line-height:1.6; }
    .rank-progress { height:8px; margin:13px 0 0; overflow:hidden; border-radius:4px; background:#0d1116; }
    .rank-progress span { display:block; height:100%; background:var(--green); }
    .rank-tools { margin-top:18px; }
    .rank-tools-head { display:flex; justify-content:space-between; gap:12px; align-items:end; margin-bottom:10px; }
    .rank-tools-head p { margin:0; max-width:620px; color:var(--muted); font-size:.85rem; text-align:right; }
    .rank-session { display:grid; grid-template-columns:minmax(0,1fr) minmax(170px,.45fr) auto; gap:9px; align-items:end; margin:0 0 12px; }
    .rank-session label { margin:0; }
    .rank-session input,.rank-session select { width:100%; min-width:0; height:40px; padding:0 10px; border:1px solid var(--line); border-radius:5px; background:#0d1116; color:var(--text); font:inherit; }
    .rank-options { display:flex; gap:12px; flex-wrap:wrap; margin:0 0 12px; }
    .rank-options label { display:flex; align-items:center; gap:7px; margin:0; color:var(--muted); font-size:.78rem; font-weight:700; }
    .rank-options input { width:17px; height:17px; margin:0; }
    .rank-options button { min-height:36px; }
    .rank-options .import-pack { display:inline-flex; align-items:center; min-height:36px; padding:0 11px; border:1px solid var(--line); border-radius:5px; background:var(--surface2); color:var(--text); cursor:pointer; }
    .rank-options .import-pack input { display:none; }
    .session-progress { margin:0 0 12px; color:var(--muted); font-size:.85rem; }
    .rank-tool-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(235px,1fr)); gap:12px; }
    .rank-tool { min-width:0; padding:16px; border:1px solid var(--line); border-top:3px solid var(--blue); border-radius:8px; background:var(--surface); }
    .rank-tool.current { border-top-color:var(--green); background:#17221c; }
    .rank-tool h3 { margin:6px 0; font-size:1rem; }
    .rank-tool-head { display:flex; align-items:flex-start; justify-content:space-between; gap:8px; }
    .favorite-tool { min-width:38px; min-height:34px; padding:0 8px; background:var(--surface2); border:1px solid var(--line); color:var(--muted); }
    .favorite-tool.active { background:#3a321c; color:var(--yellow); }
    .rank-tool p { margin:0 0 10px; color:var(--muted); line-height:1.45; }
    .rank-tool ul { list-style:none; padding:0; font-size:.86rem; }
    .rank-tool li { margin:7px 0; }
    .rank-step { display:flex; align-items:flex-start; gap:8px; color:var(--muted); text-transform:none; font-size:inherit; font-weight:400; line-height:1.4; }
    .rank-step input { flex:0 0 auto; width:17px; height:17px; margin:2px 0 0; padding:0; }
    .rank-step input:checked + span { color:var(--green); text-decoration:line-through; }
    .locked-summary { margin-top:10px; color:var(--muted); font-size:.82rem; }
    .hidden { display:none!important; }
    .upgrades { margin-top:18px; }
    .upgrades-head { display:flex; justify-content:space-between; gap:12px; align-items:end; margin-bottom:10px; }
    .upgrades-head p { margin:0; color:var(--muted); font-size:.85rem; }
    .upgrade-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(235px,1fr)); gap:12px; }
    .upgrade { min-width:0; padding:16px; border:1px solid var(--line); border-radius:8px; background:var(--surface); }
    .upgrade h3 { margin:6px 0; font-size:1rem; }
    .upgrade p { margin:0; color:var(--muted); line-height:1.45; }
    .upgrade a,.upgrade .not-live { display:flex; align-items:center; justify-content:center; min-height:38px; margin-top:12px; padding:0 10px; border-radius:5px; font-size:.75rem; font-weight:800; text-align:center; }
    .upgrade a { background:var(--green); color:#061109; text-decoration:none; }
    .upgrade .not-live { border:1px solid var(--line); color:var(--muted); }
    footer { border-top:1px solid var(--line); background:#14181d; }
    footer > div { padding:23px 0 30px; color:var(--muted); line-height:1.5; }
    @media (max-width:900px) { .summary { grid-template-columns:1fr 1fr; } .summary > div { border-bottom:1px solid var(--line); } .summary > div:nth-child(even) { border-right:0; } .summary > div:nth-last-child(-n+2) { border-bottom:0; } }
    @media (max-width:760px) { .top { grid-template-columns:1fr; } .rank-tools-head,.upgrades-head,.checkup-head { align-items:flex-start; flex-direction:column; } .rank-tools-head p { text-align:left; } .rank-session { grid-template-columns:1fr; } }
    @media (max-width:480px) { header > div { align-items:flex-start; flex-direction:column; padding:14px 0; } .summary { grid-template-columns:1fr; } .summary > div { border-right:0; border-bottom:1px solid var(--line)!important; } .summary > div:last-child { border-bottom:0!important; } .actions { grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <header><div><div class="brand">VaultLink Customer</div><nav><a href="/shop">SHOP</a><a href="/status">STATUS</a><a href="/privacy">PRIVACY</a></nav></div></header>
  <main>
    <div class="top">
      <section>
        <h1>Customer License Center</h1>
        <p class="lead">Check your signed VaultLink rank, expiration, service status, release, and included tools without activating another device.</p>
        <div class="privacy">Your license key stays in this page's memory for this check. It is not saved in browser storage, placed in a URL, or included in the result.</div>
      </section>
      <section class="panel">
        <label for="licenseKey">License key</label>
        <input id="licenseKey" type="password" autocomplete="off" spellcheck="false">
        <label class="secondary-field" for="appVersion">Installed app version, optional</label>
        <input id="appVersion" maxlength="80" autocomplete="off" spellcheck="false" placeholder="Example: 2026.07.12.9">
        <div class="actions"><button id="check" type="button">CHECK LICENSE</button><button id="clear" type="button">CLEAR</button></div>
        <div id="status" role="status" aria-live="polite">Not checked.</div>
      </section>
    </div>
    <div id="result"><div class="empty">License information will appear here.</div></div>
  </main>
  <footer><div>This page is read-only. It cannot activate a device, unlock files, retrieve PINs, read file contents, or change your PC.</div></footer>
  <script>
    const $ = (id) => document.getElementById(id);
    const state = { payload:null, upgrades:null, rankTools:null, checkup:null, favorites:new Set() };
    const text = (value) => String(value ?? "");
    function setStatus(message, tone="") { const node=$("status"); node.textContent=message; node.className=tone; }
    function badgeTone(status) { return status === "active" ? "" : status === "limited" ? "warn" : "bad"; }
    function safeExport(payload) {
      return {
        exported_at_utc:new Date().toISOString(),
        status:payload.status,
        plan:{id:payload.plan.id,name:payload.plan.name,rank:payload.plan.rank},
        issued_at_utc:payload.license.issued_at_utc,
        expires_at_utc:payload.license.expires_at_utc,
        device_usage:payload.device_usage,
        service_status:payload.service_status,
        release:payload.release,
        customer_checkup:state.checkup ? {overall:state.checkup.overall,counts:state.checkup.counts,attention_count:state.checkup.attention_count,items:state.checkup.items} : null,
        privacy_notice:"This customer-created summary excludes the license key, license id, identity, notes, device identities, receipts, paths, PINs, USB secrets, and file contents."
      };
    }
    async function copySummary() {
      if (!state.payload) return;
      const data=safeExport(state.payload);
      const lines=["VaultLink Customer Summary",`Status: ${data.status}`,`Plan: ${data.plan.name}`,`Rank: ${data.plan.rank} of 7`,`Devices: ${data.device_usage.active} of ${data.device_usage.maximum}`,`Expires: ${data.expires_at_utc || "No expiration"}`,`Service: ${data.service_status.mode}`,`Release: ${data.release.latest_version || "Not published"}`];
      try { await navigator.clipboard.writeText(lines.join("\\n")); setStatus("Privacy-safe summary copied.","good"); }
      catch (_) { setStatus("Browser clipboard access was blocked.","bad"); }
    }
    function exportSummary() {
      if (!state.payload) return;
      const blob=new Blob([JSON.stringify(safeExport(state.payload),null,2)],{type:"application/json"});
      const url=URL.createObjectURL(blob); const link=document.createElement("a");
      link.href=url; link.download="vaultlink-customer-summary.json"; document.body.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url),1000); setStatus("Privacy-safe summary exported.","good");
    }
    function safeRankPack() {
      const steps=[...document.querySelectorAll(".rank-step input")];
      return {
        exported_at_utc:new Date().toISOString(),
        rank:{current:state.rankTools.current_rank,name:state.rankTools.current_rank_name},
        unlocked_count:state.rankTools.unlocked_count,
        tools:state.rankTools.items,
        favorite_tool_ids:[...state.favorites].sort(),
        session_progress:{
          completed:steps.filter((input) => input.checked).length,
          total:steps.length,
          steps:steps.map((input) => ({tool_id:input.dataset.toolId,step:Number(input.dataset.step),completed:input.checked}))
        },
        privacy_notice:"This rank pack excludes the license key, license id, customer identity, notes, device data, receipts, payment data, paths, PINs, USB secrets, and file contents."
      };
    }
    async function copyRankTools() {
      if (!state.rankTools?.active) return;
      const lines=[`VaultLink Rank ${state.rankTools.current_rank} Exclusive Tools`,...state.rankTools.current_rank_items.flatMap((tool) => ["",tool.name,...tool.checklist.map((item) => `- ${item}`)])];
      try { await navigator.clipboard.writeText(lines.join("\\n")); setStatus("Current-rank exclusive tools copied.","good"); }
      catch (_) { setStatus("Browser clipboard access was blocked.","bad"); }
    }
    function exportRankPack() {
      if (!state.rankTools?.active) return;
      const blob=new Blob([JSON.stringify(safeRankPack(),null,2)],{type:"application/json"});
      const url=URL.createObjectURL(blob); const link=document.createElement("a");
      link.href=url; link.download=`vaultlink-rank-${state.rankTools.current_rank}-tool-pack.json`; document.body.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url),1000); setStatus("Privacy-safe rank tool pack exported.","good");
    }
    function updateRankProgress() {
      const steps=[...document.querySelectorAll(".rank-step input")];
      const completed=steps.filter((input) => input.checked).length;
      const progress=$("rankSessionProgress");
      if (progress) progress.textContent=`${completed} of ${steps.length} checklist steps complete in this session. ${state.favorites.size} favorite tool${state.favorites.size===1?"":"s"}.`;
      if ($("incompleteOnly")?.checked) filterRankTools();
    }
    function filterRankTools() {
      const query=($("rankToolSearch")?.value || "").trim().toLowerCase();
      const category=$("rankToolCategory")?.value || "";
      const currentOnly=Boolean($("currentRankOnly")?.checked);
      const incompleteOnly=Boolean($("incompleteOnly")?.checked);
      const favoritesOnly=Boolean($("favoritesOnly")?.checked);
      document.querySelectorAll(".rank-tool").forEach((card) => {
        const matchesText=!query || card.dataset.search.includes(query);
        const matchesCategory=!category || card.dataset.category===category;
        const matchesRank=!currentOnly || card.dataset.current==="true";
        const matchesIncomplete=!incompleteOnly || Boolean(card.querySelector('.rank-step input:not(:checked)'));
        const matchesFavorite=!favoritesOnly || state.favorites.has(card.dataset.toolId);
        card.classList.toggle("hidden",!(matchesText && matchesCategory && matchesRank && matchesIncomplete && matchesFavorite));
      });
    }
    function toggleFavorite(toolId,button) {
      if (state.favorites.has(toolId)) state.favorites.delete(toolId); else state.favorites.add(toolId);
      const active=state.favorites.has(toolId); button.classList.toggle("active",active); button.textContent=active?"FAVORITED":"FAVORITE"; button.setAttribute("aria-pressed",String(active));
      updateRankProgress(); filterRankTools();
    }
    function focusNextIncomplete() {
      const next=[...document.querySelectorAll('.rank-tool:not(.hidden) .rank-step input:not(:checked)')][0];
      if (!next) return setStatus("No incomplete visible checklist step.","good");
      next.scrollIntoView({behavior:"smooth",block:"center"}); next.focus(); setStatus("Focused the next incomplete visible step.");
    }
    async function importRankPack(file) {
      if (!file) return;
      if (file.size > 1024*1024) return setStatus("Rank pack must be 1 MB or smaller.","bad");
      try {
        const pack=JSON.parse(await file.text());
        const savedSteps=pack?.session_progress?.steps;
        if (!Array.isArray(savedSteps) || savedSteps.length > 1000) throw new Error("Rank pack progress is invalid.");
        const inputs=[...document.querySelectorAll('.rank-step input')]; const known=new Map(inputs.map((input)=>[`${input.dataset.toolId}:${input.dataset.step}`,input]));
        inputs.forEach((input)=>{input.checked=false;});
        savedSteps.forEach((item)=>{ const input=known.get(`${String(item.tool_id)}:${Number(item.step)}`); if (input) input.checked=Boolean(item.completed); });
        state.favorites=new Set((Array.isArray(pack.favorite_tool_ids)?pack.favorite_tool_ids:[]).filter((id)=>state.rankTools.items.some((tool)=>tool.id===id)));
        document.querySelectorAll('.favorite-tool').forEach((button)=>{ const active=state.favorites.has(button.dataset.toolId); button.classList.toggle("active",active); button.textContent=active?"FAVORITED":"FAVORITE"; button.setAttribute("aria-pressed",String(active)); });
        updateRankProgress(); filterRankTools(); setStatus("Privacy-safe rank pack imported into this page session.","good");
      } catch (error) { setStatus(error.message || "Rank pack import failed.","bad"); }
      finally { const input=$("rankPackImport"); if (input) input.value=""; }
    }
    function resetRankProgress() {
      document.querySelectorAll(".rank-step input").forEach((input) => { input.checked=false; });
      updateRankProgress(); setStatus("Session checklist progress reset.");
    }
    function render(payload,upgrades,rankTools,checkup) {
      const root=$("result"); root.replaceChildren();
      const summary=document.createElement("div"); summary.className="summary";
      const fields=[
        ["Plan", payload.license.plan_name],
        ["Status", payload.status],
        ["Rank", `${payload.rank_progress.current} of ${payload.rank_progress.maximum}`],
        ["Devices", `${payload.device_usage.active} of ${payload.device_usage.maximum}`],
        ["Expires", payload.license.expires_at_utc || "No expiration"],
        ["Latest release", payload.release.latest_version || "Not published"]
      ];
      fields.forEach(([label,value],index) => {
        const cell=document.createElement("div");
        const key=document.createElement("div"); key.className="eyebrow"; key.textContent=label;
        const val=document.createElement("div"); val.className="value"; val.textContent=text(value);
        if (index===1) { val.className=`value badge ${badgeTone(payload.status)}`; }
        cell.append(key,val); summary.append(cell);
      });
      const progress=document.createElement("div"); progress.className="rank-progress"; progress.setAttribute("aria-label",`Rank progress ${payload.rank_progress.percent} percent`);
      const progressValue=document.createElement("span"); progressValue.style.width=`${payload.rank_progress.percent}%`; progress.append(progressValue);
      const message=document.createElement("div"); message.className="message"; message.textContent=payload.message;
      const toolbar=document.createElement("div"); toolbar.className="dashboard-actions";
      const copy=document.createElement("button"); copy.type="button"; copy.textContent="COPY SUMMARY"; copy.addEventListener("click",copySummary);
      const download=document.createElement("button"); download.type="button"; download.textContent="EXPORT JSON"; download.addEventListener("click",exportSummary);
      const shop=document.createElement("a"); shop.href="/shop"; shop.textContent="OPEN SHOP";
      toolbar.append(copy,download,shop);
      if (rankTools.active) {
        const copyTools=document.createElement("button"); copyTools.type="button"; copyTools.textContent="COPY RANK TOOLS"; copyTools.addEventListener("click",copyRankTools);
        const exportTools=document.createElement("button"); exportTools.type="button"; exportTools.textContent="EXPORT RANK PACK"; exportTools.addEventListener("click",exportRankPack);
        toolbar.append(copyTools,exportTools);
      }
      if (payload.release.published && payload.release.download_path) {
        const update=document.createElement("a"); update.className="primary-action"; update.href=payload.release.download_path; update.textContent="DOWNLOAD SIGNED UPDATE"; toolbar.append(update);
      }
      const checkupSection=document.createElement("section"); checkupSection.className="checkup";
      const checkupHead=document.createElement("div"); checkupHead.className="checkup-head";
      const checkupTitle=document.createElement("h2"); checkupTitle.textContent="Customer Checkup";
      const checkupSummary=document.createElement("p"); checkupSummary.textContent=`${checkup.attention_count} item${checkup.attention_count===1?"":"s"} need attention. Overall: ${checkup.overall}.`;
      checkupHead.append(checkupTitle,checkupSummary); checkupSection.append(checkupHead);
      const checkupGrid=document.createElement("div"); checkupGrid.className="checkup-grid";
      checkup.items.forEach((item)=>{ const card=document.createElement("article"); card.className=`checkup-item ${item.severity}`; const severity=document.createElement("div"); severity.className="eyebrow"; severity.textContent=item.severity.toUpperCase(); const title=document.createElement("h3"); title.textContent=item.title; const detail=document.createElement("p"); detail.textContent=item.detail; card.append(severity,title,detail); checkupGrid.append(card); });
      checkupSection.append(checkupGrid);
      const details=document.createElement("div"); details.className="details";
      const included=document.createElement("section");
      const includedTitle=document.createElement("h2"); includedTitle.textContent=`Rank ${payload.plan.rank} included tools`;
      const list=document.createElement("ul"); payload.plan.includes.forEach((item) => { const li=document.createElement("li"); li.textContent=item; list.append(li); });
      included.append(includedTitle,list);
      const service=document.createElement("section");
      const serviceTitle=document.createElement("h2"); serviceTitle.textContent="Service and privacy";
      const serviceList=document.createElement("ul");
      [
        `Service: ${payload.service_status.mode}`,
        payload.service_status.message,
        "No device seat was activated by this check.",
        "Customer names, email addresses, notes, and machine identifiers are excluded."
      ].forEach((item) => { const li=document.createElement("li"); li.textContent=item; serviceList.append(li); });
      service.append(serviceTitle,serviceList);
      const actions=document.createElement("section");
      const actionsTitle=document.createElement("h2"); actionsTitle.textContent="Next actions";
      const actionsList=document.createElement("ul"); payload.customer_actions.forEach((item) => { const li=document.createElement("li"); li.textContent=item; actionsList.append(li); });
      actions.append(actionsTitle,actionsList); details.append(included,service,actions);
      root.append(summary,progress,message,toolbar,checkupSection,details);
      const rankSection=document.createElement("section"); rankSection.className="rank-tools";
      const rankHead=document.createElement("div"); rankHead.className="rank-tools-head";
      const rankTitle=document.createElement("h2"); rankTitle.textContent="Rank-exclusive tools";
      const rankMessage=document.createElement("p"); rankMessage.textContent=rankTools.message;
      rankHead.append(rankTitle,rankMessage); rankSection.append(rankHead);
      if (rankTools.items.length) {
        const session=document.createElement("div"); session.className="rank-session";
        const searchWrap=document.createElement("label"); searchWrap.textContent="SEARCH UNLOCKED TOOLS";
        const search=document.createElement("input"); search.id="rankToolSearch"; search.type="search"; search.placeholder="Search"; searchWrap.append(search);
        const categoryWrap=document.createElement("label"); categoryWrap.textContent="CATEGORY";
        const category=document.createElement("select"); category.id="rankToolCategory";
        const all=document.createElement("option"); all.value=""; all.textContent="All categories"; category.append(all);
        rankTools.categories.forEach((value) => { const option=document.createElement("option"); option.value=value; option.textContent=value; category.append(option); }); categoryWrap.append(category);
        const reset=document.createElement("button"); reset.type="button"; reset.textContent="RESET PROGRESS"; reset.addEventListener("click",resetRankProgress);
        session.append(searchWrap,categoryWrap,reset); rankSection.append(session);
        const options=document.createElement("div"); options.className="rank-options";
        [["currentRankOnly","CURRENT RANK ONLY"],["incompleteOnly","INCOMPLETE ONLY"],["favoritesOnly","FAVORITES ONLY"]].forEach(([id,labelText])=>{ const label=document.createElement("label"); const input=document.createElement("input"); input.id=id; input.type="checkbox"; input.addEventListener("change",filterRankTools); const value=document.createElement("span"); value.textContent=labelText; label.append(input,value); options.append(label); });
        const next=document.createElement("button"); next.type="button"; next.textContent="NEXT INCOMPLETE"; next.addEventListener("click",focusNextIncomplete); options.append(next);
        const importLabel=document.createElement("label"); importLabel.className="import-pack"; importLabel.textContent="IMPORT RANK PACK";
        const importInput=document.createElement("input"); importInput.id="rankPackImport"; importInput.type="file"; importInput.accept="application/json,.json"; importInput.addEventListener("change",()=>importRankPack(importInput.files?.[0])); importLabel.append(importInput); options.append(importLabel); rankSection.append(options);
        const sessionProgress=document.createElement("div"); sessionProgress.id="rankSessionProgress"; sessionProgress.className="session-progress"; sessionProgress.textContent=`0 of ${rankTools.total_checklist_steps} checklist steps complete in this session. 0 favorite tools.`; rankSection.append(sessionProgress);
        const rankGrid=document.createElement("div"); rankGrid.className="rank-tool-grid";
        rankTools.items.forEach((tool) => {
          const card=document.createElement("article"); card.className=`rank-tool${tool.rank===rankTools.current_rank?" current":""}`;
          card.dataset.toolId=tool.id; card.dataset.current=String(tool.rank===rankTools.current_rank); card.dataset.category=tool.category; card.dataset.search=`${tool.name} ${tool.summary} ${tool.category}`.toLowerCase();
          const rank=document.createElement("div"); rank.className="eyebrow"; rank.textContent=`RANK ${tool.rank}${tool.rank===rankTools.current_rank?" - CURRENT RANK":""} - ${tool.category.toUpperCase()} - ${tool.estimated_minutes} MIN`;
          const head=document.createElement("div"); head.className="rank-tool-head";
          const title=document.createElement("h3"); title.textContent=tool.name;
          const favorite=document.createElement("button"); favorite.type="button"; favorite.className="favorite-tool"; favorite.dataset.toolId=tool.id; favorite.textContent="FAVORITE"; favorite.setAttribute("aria-label",`Favorite ${tool.name}`); favorite.setAttribute("aria-pressed","false"); favorite.addEventListener("click",()=>toggleFavorite(tool.id,favorite)); head.append(title,favorite);
          const detail=document.createElement("p"); detail.textContent=tool.summary;
          const list=document.createElement("ul"); tool.checklist.forEach((item,index) => { const li=document.createElement("li"); const label=document.createElement("label"); label.className="rank-step"; const input=document.createElement("input"); input.type="checkbox"; input.dataset.toolId=tool.id; input.dataset.step=String(index+1); input.addEventListener("change",updateRankProgress); const value=document.createElement("span"); value.textContent=item; label.append(input,value); li.append(label); list.append(li); });
          card.append(rank,head,detail,list); rankGrid.append(card);
        });
        rankSection.append(rankGrid); search.addEventListener("input",filterRankTools); category.addEventListener("change",filterRankTools);
      }
      const locked=document.createElement("div"); locked.className="locked-summary"; locked.textContent=rankTools.locked_count ? `${rankTools.locked_count} additional tool${rankTools.locked_count===1?"":"s"} remain locked or unavailable.` : "All rank-exclusive tools are unlocked.";
      rankSection.append(locked); root.append(rankSection);
      const upgradeSection=document.createElement("section"); upgradeSection.className="upgrades";
      const upgradeHead=document.createElement("div"); upgradeHead.className="upgrades-head";
      const upgradeTitle=document.createElement("h2"); upgradeTitle.textContent="Higher ranks";
      const upgradeCount=document.createElement("p"); upgradeCount.textContent=upgrades.items.length ? `${upgrades.items.length} upgrade option${upgrades.items.length===1?"":"s"}` : "Highest rank reached";
      upgradeHead.append(upgradeTitle,upgradeCount); upgradeSection.append(upgradeHead);
      if (upgrades.items.length) {
        const grid=document.createElement("div"); grid.className="upgrade-grid";
        upgrades.items.forEach((option) => {
          const card=document.createElement("article"); card.className="upgrade";
          const rank=document.createElement("div"); rank.className="eyebrow"; rank.textContent=`RANK ${option.plan.rank} - +${option.added_entitlement_count} ENTITLEMENTS`;
          const title=document.createElement("h3"); title.textContent=option.plan.name;
          const detail=document.createElement("p"); detail.textContent=option.plan.best_for;
          card.append(rank,title,detail);
          if (option.plan.checkout_available) { const buy=document.createElement("a"); buy.href=option.plan.checkout_url; buy.target="_blank"; buy.rel="noopener noreferrer"; buy.textContent="SECURE HOSTED CHECKOUT"; card.append(buy); }
          else { const unavailable=document.createElement("div"); unavailable.className="not-live"; unavailable.textContent="NOT ON SALE YET"; card.append(unavailable); }
          grid.append(card);
        });
        upgradeSection.append(grid);
      }
      root.append(upgradeSection);
    }
    async function checkLicense() {
      const licenseKey=$("licenseKey").value.trim();
      const appVersion=$("appVersion").value.trim();
      if (!licenseKey) return setStatus("Enter a license key.","warn");
      setStatus("Checking..."); $("check").disabled=true;
      try {
        const response=await fetch("/api/v1/licenses/preview",{method:"POST",headers:{"Content-Type":"application/json","Accept":"application/json"},body:JSON.stringify({license_key:licenseKey}),cache:"no-store",redirect:"error"});
        const payload=await response.json();
        if (!response.ok) throw new Error(payload.message || "License check failed.");
        const upgradeResponse=await fetch("/api/v1/licenses/upgrade-options",{method:"POST",headers:{"Content-Type":"application/json","Accept":"application/json"},body:JSON.stringify({license_key:licenseKey}),cache:"no-store",redirect:"error"});
        const upgrades=await upgradeResponse.json();
        if (!upgradeResponse.ok) throw new Error(upgrades.message || "Upgrade options failed.");
        const rankResponse=await fetch("/api/v1/licenses/rank-tools",{method:"POST",headers:{"Content-Type":"application/json","Accept":"application/json"},body:JSON.stringify({license_key:licenseKey}),cache:"no-store",redirect:"error"});
        const rankTools=await rankResponse.json();
        if (!rankResponse.ok) throw new Error(rankTools.message || "Rank tools failed.");
        const checkupResponse=await fetch("/api/v1/licenses/customer-checkup",{method:"POST",headers:{"Content-Type":"application/json","Accept":"application/json"},body:JSON.stringify({license_key:licenseKey,app_version:appVersion}),cache:"no-store",redirect:"error"});
        const checkup=await checkupResponse.json();
        if (!checkupResponse.ok) throw new Error(checkup.message || "Customer checkup failed.");
        state.payload=payload; state.upgrades=upgrades; state.rankTools=rankTools; state.checkup=checkup; state.favorites=new Set(); render(payload,upgrades,rankTools,checkup); setStatus("Customer dashboard loaded.",payload.status==="active"?"good":payload.status==="limited"?"warn":"bad");
      } catch (error) { setStatus(error.message || "License check failed.","bad"); }
      finally { $("check").disabled=false; }
    }
    $("check").addEventListener("click",checkLicense);
    $("clear").addEventListener("click",() => { state.payload=null; state.upgrades=null; state.rankTools=null; state.checkup=null; state.favorites=new Set(); $("licenseKey").value=""; $("appVersion").value=""; $("result").innerHTML='<div class="empty">License information will appear here.</div>'; setStatus("License key and session data cleared from page memory."); });
    $("licenseKey").addEventListener("keydown",(event) => { if (event.key === "Enter") checkLicense(); });
    $("appVersion").addEventListener("keydown",(event) => { if (event.key === "Enter") checkLicense(); });
  </script>
</body>
</html>"""


def owner_portal_html():
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VaultLink Owner Console</title>
  <style>
    :root { color-scheme: dark; --bg:#0d0f12; --panel:#161a20; --field:#0a0c0f; --line:#313843; --text:#f4f7fa; --muted:#9ba8b6; --green:#35e878; --blue:#58b7e8; --yellow:#f3c84b; --red:#ff626d; }
    * { box-sizing:border-box; letter-spacing:0; }
    body { margin:0; min-width:320px; background:var(--bg); color:var(--text); font:14px/1.45 "Segoe UI",Arial,sans-serif; }
    header { border-bottom:1px solid var(--line); background:#111419; }
    header > div, main { width:min(1180px,calc(100% - 32px)); margin:0 auto; }
    header > div { min-height:78px; display:flex; align-items:center; justify-content:space-between; gap:20px; }
    h1 { margin:0; font-size:24px; }
    h2 { margin:0 0 14px; font-size:17px; }
    .api-state { color:var(--muted); font-weight:700; }
    main { padding:24px 0 44px; }
    section { padding:20px 0 24px; border-bottom:1px solid var(--line); }
    .auth, .grid, .latest, .record-head, .record-actions, .ticket-actions, .audit-row, .activity-row, .stats { display:grid; gap:10px; align-items:end; }
    .auth { grid-template-columns:minmax(220px,1fr) auto auto; }
    .grid { grid-template-columns:repeat(2,minmax(0,1fr)); }
    .latest { grid-template-columns:minmax(0,1fr) auto; }
    .record-head { grid-template-columns:minmax(180px,1fr) minmax(160px,.7fr) auto; align-items:start; }
    .record-actions { grid-template-columns:minmax(180px,1fr) auto auto auto auto auto; }
    .ticket-actions { grid-template-columns:minmax(130px,.45fr) minmax(200px,1fr) minmax(200px,1fr) auto auto; align-items:start; }
    .audit-row { grid-template-columns:minmax(180px,1fr) minmax(140px,.5fr) auto; align-items:center; }
    .activity-row { grid-template-columns:minmax(180px,1fr) minmax(140px,.6fr) auto; align-items:center; }
    .stats { grid-template-columns:repeat(4,minmax(0,1fr)); align-items:stretch; }
    .stat { min-width:0; padding:12px 10px; border-left:3px solid var(--blue); background:var(--panel); }
    .stat strong { display:block; margin-top:3px; font-size:20px; overflow-wrap:anywhere; }
    label { display:block; color:var(--muted); font-size:11px; font-weight:800; text-transform:uppercase; margin-bottom:5px; }
    input, select, textarea { width:100%; border:1px solid var(--line); border-radius:4px; background:var(--field); color:var(--text); padding:10px 11px; font:inherit; }
    textarea { min-height:72px; resize:vertical; }
    button { min-height:40px; border:0; border-radius:4px; padding:0 14px; background:#29303a; color:var(--text); font:700 12px "Segoe UI",Arial,sans-serif; cursor:pointer; }
    button:hover { filter:brightness(1.12); }
    button:disabled { cursor:not-allowed; opacity:.45; }
    .primary { background:var(--green); color:#06120a; }
    .blue { background:var(--blue); color:#061017; }
    .warn { background:var(--yellow); color:#171204; }
    .danger { background:var(--red); color:#190407; }
    .status { min-height:22px; margin-top:10px; color:var(--muted); }
    .status.bad { color:var(--red); }
    .status.good { color:var(--green); }
    .record { margin-top:10px; padding:15px; border:1px solid var(--line); border-radius:6px; background:var(--panel); }
    .record strong { font-size:15px; overflow-wrap:anywhere; }
    .meta { color:var(--muted); font-size:12px; margin-top:4px; }
    .badge { display:inline-block; min-width:72px; padding:4px 8px; border-radius:4px; text-align:center; text-transform:uppercase; font-size:11px; font-weight:800; background:#25302a; color:var(--green); }
    .badge.revoked { background:#392126; color:#ff9aa2; }
    .badge.open { background:#352f1d; color:var(--yellow); }
    .badge.acknowledged, .badge.in_progress { background:#1d3039; color:var(--blue); }
    .badge.resolved, .badge.closed { background:#25302a; color:var(--green); }
    .ticket-copy { margin:10px 0 0; padding:10px; background:var(--field); color:var(--text); white-space:pre-wrap; overflow-wrap:anywhere; }
    .device-list { margin-top:12px; padding-top:12px; border-top:1px solid var(--line); }
    .device-row { display:grid; grid-template-columns:minmax(180px,1fr) minmax(120px,.6fr) auto; gap:10px; align-items:center; padding:8px 0; }
    .empty { padding:26px 0; color:var(--muted); }
    .page-links { display:flex; gap:18px; flex-wrap:wrap; }
    .page-links a { color:var(--blue); text-decoration:none; font-weight:700; }
    .split { grid-column:1 / -1; }
    @media (max-width:900px) { .stats { grid-template-columns:repeat(3,minmax(0,1fr)); } }
    @media (max-width:760px) { .auth,.grid,.latest,.record-head,.record-actions,.ticket-actions,.audit-row,.activity-row,.device-row { grid-template-columns:1fr; } .stats { grid-template-columns:repeat(2,minmax(0,1fr)); } header > div { align-items:flex-start; flex-direction:column; padding:16px 0; } button { width:100%; } }
  </style>
</head>
<body>
  <header><div><h1>VaultLink Owner Console</h1><div id="apiState" class="api-state">DISCONNECTED</div></div></header>
  <main>
    <section>
      <h2>Owner Access</h2>
      <div class="auth">
        <div><label for="token">License admin token</label><input id="token" type="password" autocomplete="off" spellcheck="false"></div>
        <button id="connect" class="blue">CONNECT</button>
        <button id="clearToken">CLEAR TOKEN</button>
      </div>
      <div id="status" class="status">The token stays in this page memory and is sent only in the admin header.</div>
    </section>

    <section>
      <h2>API Dashboard</h2>
      <div class="stats">
        <div class="stat"><label>Active licenses</label><strong id="statLicenses">-</strong></div>
        <div class="stat"><label>Active devices</label><strong id="statDevices">-</strong></div>
        <div class="stat"><label>Device capacity</label><strong id="statCapacity">-</strong></div>
        <div class="stat"><label>Audit reports</label><strong id="statAudits">-</strong></div>
        <div class="stat"><label>High + critical</label><strong id="statBreaches">-</strong></div>
        <div class="stat"><label>Desktop release</label><strong id="statRelease">-</strong></div>
        <div class="stat"><label>API version</label><strong id="statApi">-</strong></div>
        <div class="stat"><label>Client sync</label><strong id="statSync">-</strong></div>
        <div class="stat"><label>Bugs needing action</label><strong id="statSupport">-</strong></div>
        <div class="stat"><label>Shop links live</label><strong id="statShop">-</strong></div>
        <div class="stat"><label>Active announcements</label><strong id="statAnnouncements">-</strong></div>
        <div class="stat"><label>Service status</label><strong id="statService">-</strong></div>
        <div class="stat"><label>Activity integrity</label><strong id="statActivity">-</strong></div>
        <div class="stat"><label>Current release clients</label><strong id="statCurrentClients">-</strong></div>
        <div class="stat"><label>Stale clients, 24h</label><strong id="statStaleClients">-</strong></div>
      </div>
    </section>

    <section>
      <h2>50-Point Owner Command Center</h2>
      <div class="latest">
        <div class="status">Open a focused view with exactly 50 live, privacy-safe business and service insights plus search, filters, copy, and JSON/CSV exports.</div>
        <a href="/owner/insights" style="display:inline-flex;align-items:center;justify-content:center;min-height:40px;padding:0 14px;border-radius:4px;background:var(--blue);color:#061017;text-decoration:none;font-weight:800;">OPEN COMMAND CENTER</a>
      </div>
    </section>

    <section>
      <div class="record-head"><h2>Client Release Adoption</h2><div id="clientHealthSummary" class="meta">Connect to load anonymous client health.</div></div>
      <div id="clientVersionRecords"><div class="empty">No client version data loaded.</div></div>
    </section>

    <section>
      <h2>Customer Pages</h2>
      <div class="page-links"><a href="/status" target="_blank" rel="noopener">STATUS</a><a href="/terms" target="_blank" rel="noopener">DRAFT TERMS</a><a href="/privacy" target="_blank" rel="noopener">PRIVACY</a><a href="/shop" target="_blank" rel="noopener">SHOP</a><a href="/docs" target="_blank" rel="noopener">API DOCS</a></div>
      <div class="status">Legal document """ + LEGAL_DOCUMENT_VERSION + """ is a draft. Adult business-owner approval and qualified legal review are recommended before commercial use.</div>
    </section>

    <section>
      <h2>Service Status</h2>
      <div class="grid">
        <div><label for="serviceMode">Mode</label><select id="serviceMode"><option value="normal">NORMAL</option><option value="degraded">DEGRADED</option><option value="maintenance">MAINTENANCE</option></select></div>
        <div><label for="serviceExpires">Expires, optional</label><input id="serviceExpires" type="datetime-local"></div>
        <div class="split"><label for="serviceMessage">Customer message</label><input id="serviceMessage" maxlength="240" value="All VaultLink services are operating normally."></div>
        <div class="split"><button id="saveServiceStatus" class="blue" disabled>SAVE SERVICE STATUS</button></div>
      </div>
      <div id="serviceStatusSummary" class="status">Connect to manage the public service status.</div>
    </section>

    <section>
      <h2>Issue License</h2>
      <div class="grid">
        <div><label for="rank">Rank</label><select id="rank"></select></div>
        <div><label for="devices">Maximum devices</label><input id="devices" type="number" min="1" max="1000" value="1"></div>
        <div><label for="customer">Customer label</label><input id="customer" maxlength="160"></div>
        <div><label for="email">Customer email</label><input id="email" type="email" maxlength="254"></div>
        <div><label for="expires">Expiration, optional</label><input id="expires" type="datetime-local"></div>
        <div><label for="note">Private owner note</label><input id="note" maxlength="2000"></div>
        <div class="split"><button id="issue" class="primary" disabled>ISSUE LICENSE</button></div>
      </div>
      <div id="latestWrap" hidden>
        <label for="latestKey">Latest key</label>
        <div class="latest"><textarea id="latestKey" readonly></textarea><button id="copyLatest" class="warn">COPY KEY</button></div>
      </div>
    </section>

    <section>
      <h2>Giveaway License</h2>
      <div class="grid">
        <div><label for="giveawayWinner">Winner alias</label><input id="giveawayWinner" maxlength="80" placeholder="Public alias, not a full legal name"></div>
        <div><label for="giveawayRank">Rank</label><select id="giveawayRank"></select></div>
        <div><label for="giveawayDays">Duration in days</label><input id="giveawayDays" type="number" min="1" max="365" value="30"></div>
        <div><label for="giveawayDevices">Maximum devices</label><input id="giveawayDevices" type="number" min="1" max="10" value="1"></div>
        <div class="split"><button id="issueGiveaway" class="primary" disabled>ISSUE GIVEAWAY LICENSE</button></div>
      </div>
      <div class="status">This issues a promotional license only. It does not select winners, collect entries, process payment, or provide contest-law compliance.</div>
    </section>

    <section>
      <h2>Owner Announcements</h2>
      <div class="grid">
        <div><label for="announcementSeverity">Type</label><select id="announcementSeverity"><option value="info">INFO</option><option value="update">UPDATE</option><option value="maintenance">MAINTENANCE</option><option value="security">SECURITY</option></select></div>
        <div><label for="announcementRank">Audience</label><select id="announcementRank"><option value="1">ALL RANKS</option></select></div>
        <div><label for="announcementStarts">Starts, optional</label><input id="announcementStarts" type="datetime-local"></div>
        <div><label for="announcementExpires">Expires, optional</label><input id="announcementExpires" type="datetime-local"></div>
        <div class="split"><label for="announcementTitle">Title</label><input id="announcementTitle" maxlength="120"></div>
        <div class="split"><label for="announcementMessage">Message</label><textarea id="announcementMessage" maxlength="2000"></textarea></div>
        <div class="split"><button id="publishAnnouncement" class="primary" disabled>PUBLISH ANNOUNCEMENT</button></div>
      </div>
      <div class="record-head"><h2>Published Messages</h2><div id="announcementStorage" class="meta"></div><button id="refreshAnnouncements" disabled>REFRESH MESSAGES</button></div>
      <div id="announcementRecords"><div class="empty">Connect to load owner announcements.</div></div>
    </section>

    <section>
      <div class="record-head"><h2>Keys And Notes</h2><div id="storage" class="meta"></div><button id="refresh" disabled>REFRESH</button></div>
      <div id="records"><div class="empty">Connect to load licenses.</div></div>
    </section>

    <section>
      <div class="record-head"><h2>Bug Inbox</h2><div id="supportStorage" class="meta"></div><button id="refreshSupport" disabled>REFRESH BUGS</button></div>
      <div id="supportRecords"><div class="empty">Connect to load customer bug reports.</div></div>
    </section>

    <section>
      <div class="record-head"><h2>Audit Logs</h2><div id="auditStorage" class="meta"></div><button id="refreshLogs" disabled>REFRESH LOGS</button></div>
      <div id="auditRecords"><div class="empty">Connect to load privacy-safe API logs.</div></div>
    </section>

    <section>
      <div class="record-head"><h2>API Activity</h2><div id="activityIntegrity" class="meta"></div><div><button id="refreshActivity" disabled>REFRESH ACTIVITY</button> <button id="downloadActivity" class="warn" disabled>DOWNLOAD ACTIVITY JSON</button></div></div>
      <div id="activityRecords"><div class="empty">Connect to load tamper-evident owner activity.</div></div>
    </section>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    const state = { token: "", connected: false, busy: false, loading: false, items: [], supportItems: [], auditItems: [], announcementItems: [], activityItems: [], activityIntegrity: null, serviceStatus: null, dashboard: null };
    const AUTO_REFRESH_MS = 30000;

    function setStatus(message, kind="") {
      $("status").textContent = message;
      $("status").className = `status ${kind}`;
    }

    function setConnected(value) {
      state.connected = value;
      $("apiState").textContent = value ? "CONNECTED" : "DISCONNECTED";
      $("apiState").style.color = value ? "var(--green)" : "var(--muted)";
      $("issue").disabled = !value || state.busy;
      $("issueGiveaway").disabled = !value || state.busy;
      $("refresh").disabled = !value || state.busy;
      $("refreshSupport").disabled = !value || state.busy;
      $("refreshLogs").disabled = !value || state.busy;
      $("publishAnnouncement").disabled = !value || state.busy;
      $("refreshAnnouncements").disabled = !value || state.busy;
      $("saveServiceStatus").disabled = !value || state.busy;
      $("refreshActivity").disabled = !value || state.busy;
      $("downloadActivity").disabled = !value || state.busy;
    }

    async function api(path, options={}) {
      const headers = { "Accept":"application/json", ...(options.headers || {}) };
      if (state.token) headers["X-License-Admin-Token"] = state.token;
      if (options.body) headers["Content-Type"] = "application/json";
      const response = await fetch(path, { ...options, headers, cache:"no-store", redirect:"error" });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.message || `API request failed (${response.status})`);
      return payload;
    }

    async function loadRanks() {
      const payload = await api("/api/v1/ranks");
      const select = $("rank");
      const giveaway = $("giveawayRank");
      const audience = $("announcementRank");
      select.replaceChildren();
      giveaway.replaceChildren();
      audience.replaceChildren();
      for (const plan of payload.items || []) {
        const option = document.createElement("option");
        option.value = plan.id;
        option.textContent = `Rank ${plan.rank}: ${plan.name} (${plan.price_label})`;
        select.append(option);
        const giveawayOption = document.createElement("option");
        giveawayOption.value = plan.id;
        giveawayOption.textContent = `Rank ${plan.rank}: ${plan.name}`;
        giveaway.append(giveawayOption);
        const audienceOption = document.createElement("option");
        audienceOption.value = String(plan.rank);
        audienceOption.textContent = plan.rank === 1 ? "ALL RANKS" : `RANK ${plan.rank} AND ABOVE`;
        audience.append(audienceOption);
      }
    }

    async function loadLicenses(silent=false) {
      if (state.loading) return;
      state.loading = true;
      try {
      const [payload, dashboard, support, audits, announcements, serviceStatus, activity] = await Promise.all([
        api("/api/v1/admin/licenses"),
        api("/api/v1/admin/dashboard"),
        api("/api/v1/admin/support-tickets"),
        api("/api/v1/admin/audit-exports"),
        api("/api/v1/admin/announcements"),
        api("/api/v1/service-status"),
        api("/api/v1/admin/activity")
      ]);
      state.items = payload.items || [];
      state.supportItems = support.items || [];
      state.auditItems = audits.items || [];
      state.announcementItems = announcements.items || [];
      state.serviceStatus = serviceStatus.service_status || null;
      state.activityItems = activity.items || [];
      state.activityIntegrity = activity.integrity || null;
      state.dashboard = dashboard;
      $("storage").textContent = payload.storage === "persistent_configured" ? "PERSISTENT STORAGE" : "TEMPORARY STORAGE";
      $("supportStorage").textContent = support.storage === "persistent_configured" ? "ENCRYPTED PERSISTENT STORAGE" : "TEMPORARY STORAGE";
      $("auditStorage").textContent = `${audits.storage === "persistent_configured" ? "PERSISTENT STORAGE" : "TEMPORARY STORAGE"} | ${audits.retention_hours || 0}H RETENTION`;
      $("announcementStorage").textContent = announcements.storage === "persistent_configured" ? "PERSISTENT STORAGE" : "TEMPORARY STORAGE";
      renderDashboard(dashboard);
      renderRecords();
      renderSupport();
      renderAudits();
      renderAnnouncements();
      renderServiceStatus();
      renderActivity();
      setConnected(true);
      if (!silent) setStatus(`Loaded ${payload.count || 0} license(s), ${support.count || 0} bug report(s), ${audits.count || 0} audit log(s), ${announcements.count || 0} announcement(s), and ${activity.count || 0} activity event(s).`, "good");
      } finally {
        state.loading = false;
      }
    }

    function renderDashboard(dashboard) {
      const licenses = dashboard?.licenses || {};
      const devices = dashboard?.devices || {};
      const audits = dashboard?.audit_exports || {};
      const levels = audits.breach_levels || {};
      const support = dashboard?.support_tickets || {};
      const shop = dashboard?.shop || {};
      const announcements = dashboard?.announcements || {};
      const service = dashboard?.service_status || {};
      const activity = dashboard?.api_activity || {};
      const clients = dashboard?.client_health || {};
      $("statLicenses").textContent = dashboard ? String(licenses.active || 0) : "-";
      $("statDevices").textContent = dashboard ? String(devices.active || 0) : "-";
      $("statCapacity").textContent = dashboard ? String(devices.capacity || 0) : "-";
      $("statAudits").textContent = dashboard ? String(audits.total || 0) : "-";
      $("statBreaches").textContent = dashboard ? String((levels.high || 0) + (levels.critical || 0)) : "-";
      $("statRelease").textContent = dashboard ? String((dashboard.release || {}).desktop_version || "none") : "-";
      $("statApi").textContent = dashboard ? String((dashboard.release || {}).api_version || "unknown") : "-";
      $("statSync").textContent = dashboard ? `${String((dashboard.release || {}).license_sync_seconds || 60)}s` : "-";
      $("statSupport").textContent = dashboard ? String(support.needs_action || 0) : "-";
      $("statShop").textContent = dashboard ? `${String(shop.configured || 0)}/${String(shop.total || 0)}` : "-";
      $("statAnnouncements").textContent = dashboard ? String(announcements.active || 0) : "-";
      $("statService").textContent = dashboard ? String(service.mode || "normal").toUpperCase() : "-";
      $("statActivity").textContent = dashboard ? (activity.integrity_valid ? "VALID" : "CHECK") : "-";
      $("statCurrentClients").textContent = dashboard ? `${String(clients.current_release_devices || 0)}/${String(clients.active_devices || 0)}` : "-";
      $("statStaleClients").textContent = dashboard ? String(clients.stale_24h || 0) : "-";
      renderClientHealth(dashboard ? clients : null);
    }

    function renderClientHealth(clients) {
      const host = $("clientVersionRecords");
      host.replaceChildren();
      const summary = $("clientHealthSummary");
      if (!clients) {
        summary.textContent = "Connect to load anonymous client health.";
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "No client version data loaded.";
        host.append(empty);
        return;
      }
      summary.textContent = `release ${clients.current_release || "none"} | ${clients.current_release_devices || 0} current | ${clients.other_version_devices || 0} other | ${clients.unknown_version_devices || 0} unknown | ${clients.stale_24h || 0} stale`;
      const versions = Array.isArray(clients.version_counts) ? clients.version_counts : [];
      if (!versions.length) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "No active licensed clients have reported an app version yet.";
        host.append(empty);
        return;
      }
      for (const item of versions) {
        const row = document.createElement("article");
        row.className = "record activity-row";
        const identity = document.createElement("div");
        const title = document.createElement("strong");
        title.textContent = item.version || "UNKNOWN";
        const detail = document.createElement("div");
        detail.className = "meta";
        detail.textContent = `${item.devices || 0} anonymous active device(s)`;
        identity.append(title, detail);
        const release = document.createElement("div");
        release.className = "meta";
        release.textContent = item.current_release ? "Matches published desktop release" : "Different reported release";
        const badge = document.createElement("span");
        badge.className = `badge ${item.current_release ? "resolved" : "open"}`;
        badge.textContent = item.current_release ? "CURRENT" : "OTHER";
        row.append(identity, release, badge);
        host.append(row);
      }
    }

    function actionButton(text, className, action) {
      const button = document.createElement("button");
      button.textContent = text;
      button.className = className;
      button.addEventListener("click", action);
      return button;
    }

    function renderRecords() {
      const host = $("records");
      host.replaceChildren();
      if (!state.items.length) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "No license records yet.";
        host.append(empty);
        return;
      }
      for (const item of state.items) {
        const record = document.createElement("article");
        record.className = "record";
        const head = document.createElement("div");
        head.className = "record-head";
        const identity = document.createElement("div");
        const title = document.createElement("strong");
        title.textContent = item.license_id || "Unknown license";
        const meta = document.createElement("div");
        meta.className = "meta";
        meta.textContent = `${item.plan_name || item.plan_id} | devices ${item.active_devices || 0}/${item.max_devices || 1} | issued ${item.issued_at_utc || "unknown"}`;
        identity.append(title, meta);
        const customer = document.createElement("div");
        customer.className = "meta";
        customer.textContent = item.customer_label || item.customer_email || "No customer label";
        const badge = document.createElement("span");
        const effectiveStatus = item.limited ? "limited" : (item.status || "active");
        badge.className = `badge ${effectiveStatus === "revoked" ? "revoked" : effectiveStatus === "limited" ? "open" : ""}`;
        badge.textContent = effectiveStatus;
        head.append(identity, customer, badge);

        const keyLabel = document.createElement("label");
        keyLabel.textContent = "License key";
        const key = document.createElement("input");
        key.readOnly = true;
        key.value = item.license_key || "Private data unavailable";

        const noteLabel = document.createElement("label");
        noteLabel.textContent = "Private owner note";
        const actions = document.createElement("div");
        actions.className = "record-actions";
        const note = document.createElement("input");
        note.maxLength = 2000;
        note.value = item.license_note || "";
        actions.append(note);
        actions.append(actionButton("SAVE NOTE", "blue", () => saveNote(item, note.value)));
        actions.append(actionButton("COPY KEY", "warn", () => copyText(item.license_key || "")));
        const deviceList = document.createElement("div");
        deviceList.className = "device-list";
        deviceList.hidden = true;
        actions.append(actionButton("DEVICES", "", () => toggleDevices(item, deviceList)));
        actions.append(actionButton("RESET DEVICES", "", () => resetDevices(item)));
        actions.append(item.limited
          ? actionButton("REMOVE LIMIT", "primary", () => unlimitLicense(item))
          : actionButton("LIMIT", "warn", () => limitLicense(item)));
        actions.append(item.status === "revoked"
          ? actionButton("RESTORE", "primary", () => changeStatus(item, "restore"))
          : actionButton("BLOCK", "danger", () => changeStatus(item, "revoke")));
        record.append(head, keyLabel, key, noteLabel, actions, deviceList);
        host.append(record);
      }
    }

    function renderSupport() {
      const host = $("supportRecords");
      host.replaceChildren();
      if (!state.supportItems.length) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "No customer bug reports yet.";
        host.append(empty);
        return;
      }
      for (const item of state.supportItems) {
        const record = document.createElement("article");
        record.className = "record";
        const head = document.createElement("div");
        head.className = "record-head";
        const identity = document.createElement("div");
        const title = document.createElement("strong");
        title.textContent = item.subject || item.ticket_id || "Bug report";
        const meta = document.createElement("div");
        meta.className = "meta";
        meta.textContent = `${item.ticket_id || "unknown"} | ${item.category || "other"} | ${item.license_id || "unknown license"} | ${item.created_at_utc || "unknown time"}`;
        identity.append(title, meta);
        const source = document.createElement("div");
        source.className = "meta";
        source.textContent = `device ${item.machine_hash || "anonymous"} | app ${item.app_version || "unknown"}`;
        const badge = document.createElement("span");
        badge.className = `badge ${item.status || "open"}`;
        badge.textContent = (item.status || "open").replace("_", " ");
        head.append(identity, source, badge);

        const message = document.createElement("div");
        message.className = "ticket-copy";
        message.textContent = item.message || "No description supplied.";
        record.append(head, message);
        if (item.steps) {
          const stepsLabel = document.createElement("label");
          stepsLabel.textContent = "Steps to reproduce";
          const steps = document.createElement("div");
          steps.className = "ticket-copy";
          steps.textContent = item.steps;
          record.append(stepsLabel, steps);
        }

        const actions = document.createElement("div");
        actions.className = "ticket-actions";
        const status = document.createElement("select");
        for (const value of ["open", "acknowledged", "in_progress", "resolved", "closed"]) {
          const option = document.createElement("option");
          option.value = value;
          option.textContent = value.replace("_", " ").toUpperCase();
          option.selected = value === item.status;
          status.append(option);
        }
        const reply = document.createElement("textarea");
        reply.maxLength = 4000;
        reply.placeholder = "Reply visible to the customer";
        reply.value = item.owner_reply || "";
        const note = document.createElement("textarea");
        note.maxLength = 4000;
        note.placeholder = "Private owner note";
        note.value = item.owner_note || "";
        actions.append(status, reply, note);
        actions.append(actionButton("SAVE ACTION", "blue", () => saveSupport(item, status.value, reply.value, note.value)));
        actions.append(actionButton("DELETE", "danger", () => deleteSupport(item)));
        record.append(actions);
        host.append(record);
      }
    }

    function renderAudits() {
      const host = $("auditRecords");
      host.replaceChildren();
      if (!state.auditItems.length) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "No API audit logs are stored right now.";
        host.append(empty);
        return;
      }
      for (const item of state.auditItems) {
        const row = document.createElement("article");
        row.className = "record audit-row";
        const identity = document.createElement("div");
        const title = document.createElement("strong");
        title.textContent = item.export_id || "Audit report";
        const source = item.source || {};
        const meta = document.createElement("div");
        meta.className = "meta";
        meta.textContent = `${item.uploaded_at_utc || "unknown time"} | ${source.license_id || "unknown license"} | ${item.event_count || 0} event(s)`;
        identity.append(title, meta);
        const level = String((item.breach_summary || {}).level || "clear").toLowerCase();
        const badge = document.createElement("span");
        badge.className = `badge ${level === "high" || level === "critical" ? "revoked" : "resolved"}`;
        badge.textContent = level;
        row.append(identity, badge, actionButton("DOWNLOAD JSON", "warn", () => downloadAudit(item)));
        host.append(row);
      }
    }

    function renderAnnouncements() {
      const host = $("announcementRecords");
      host.replaceChildren();
      if (!state.announcementItems.length) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "No owner announcements have been published.";
        host.append(empty);
        return;
      }
      for (const item of state.announcementItems) {
        const record = document.createElement("article");
        record.className = "record";
        const head = document.createElement("div");
        head.className = "record-head";
        const identity = document.createElement("div");
        const title = document.createElement("strong");
        title.textContent = item.title || item.announcement_id || "Owner announcement";
        const meta = document.createElement("div");
        meta.className = "meta";
        meta.textContent = `${item.announcement_id || "unknown"} | ${item.audience || "all ranks"} | created ${item.created_at_utc || "unknown"}`;
        identity.append(title, meta);
        const schedule = document.createElement("div");
        schedule.className = "meta";
        schedule.textContent = `starts ${item.starts_at_utc || "now"} | expires ${item.expires_at_utc || "never"}`;
        const badge = document.createElement("span");
        badge.className = `badge ${item.active ? "resolved" : "revoked"}`;
        badge.textContent = item.active ? item.severity || "info" : "inactive";
        head.append(identity, schedule, badge);
        const message = document.createElement("div");
        message.className = "ticket-copy";
        message.textContent = item.message || "No message supplied.";
        const actions = document.createElement("div");
        actions.className = "record-head";
        const spacer = document.createElement("div");
        actions.append(spacer, document.createElement("div"), actionButton("DELETE", "danger", () => deleteAnnouncement(item)));
        record.append(head, message, actions);
        host.append(record);
      }
    }

    function utcToLocalInput(value) {
      if (!value) return "";
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return "";
      return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
    }

    function renderServiceStatus() {
      const service = state.serviceStatus || { mode:"normal", message:"All VaultLink services are operating normally." };
      $("serviceMode").value = service.mode || "normal";
      $("serviceMessage").value = service.message || "";
      $("serviceExpires").value = utcToLocalInput(service.expires_at_utc || "");
      const summary = $("serviceStatusSummary");
      summary.textContent = `${String(service.mode || "normal").toUpperCase()} | ${service.message || "No message"} | expires ${service.expires_at_utc || "not scheduled"}`;
      summary.className = `status ${service.mode === "normal" ? "good" : "bad"}`;
    }

    function renderActivity() {
      const host = $("activityRecords");
      host.replaceChildren();
      const integrity = state.activityIntegrity || {};
      $("activityIntegrity").textContent = integrity.message || "Activity integrity not checked.";
      $("activityIntegrity").style.color = integrity.valid ? "var(--green)" : "var(--red)";
      if (!state.activityItems.length) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "No API activity events have been recorded.";
        host.append(empty);
        return;
      }
      for (const item of state.activityItems) {
        const row = document.createElement("article");
        row.className = "record activity-row";
        const identity = document.createElement("div");
        const title = document.createElement("strong");
        title.textContent = String(item.action || "activity").replaceAll("_", " ").toUpperCase();
        const meta = document.createElement("div");
        meta.className = "meta";
        meta.textContent = `${item.event_id || "unknown"} | ${item.time_utc || "unknown time"} | ${item.actor || "owner"}`;
        identity.append(title, meta);
        const resource = document.createElement("div");
        resource.className = "meta";
        resource.textContent = `${item.resource_type || "resource"}: ${item.resource_id || "none"} | chain ${String(item.hash || "").slice(0, 12)}`;
        const badge = document.createElement("span");
        badge.className = `badge ${item.result === "ok" ? "resolved" : "revoked"}`;
        badge.textContent = item.result || "unknown";
        row.append(identity, resource, badge);
        host.append(row);
      }
    }

    async function connect() {
      state.token = $("token").value.trim();
      if (!state.token) return setStatus("Enter the Railway LICENSE_ADMIN_TOKEN.", "bad");
      try { await loadLicenses(); } catch (error) { state.token = ""; setConnected(false); setStatus(error.message, "bad"); }
    }

    async function autoRefresh() {
      if (!state.connected || state.busy || state.loading) return;
      if (document.activeElement && document.activeElement.matches("input, textarea, select")) return;
      try {
        await loadLicenses(true);
        setStatus(`Owner data refreshed automatically at ${new Date().toLocaleTimeString()}.`, "good");
      } catch (error) {
        setStatus(`Automatic refresh failed: ${error.message}`, "bad");
      }
    }

    async function issueLicense() {
      if (!state.connected || state.busy) return;
      state.busy = true; setConnected(true); setStatus("Issuing license...");
      try {
        const expiresValue = $("expires").value;
        const payload = await api("/api/v1/licenses/issue", { method:"POST", body:JSON.stringify({
          plan_id: $("rank").value,
          max_devices: Number($("devices").value || 1),
          customer_label: $("customer").value.trim(),
          customer_email: $("email").value.trim(),
          license_note: $("note").value.trim(),
          expires_at_utc: expiresValue ? new Date(expiresValue).toISOString() : ""
        }) });
        $("latestKey").value = payload.license_key || "";
        $("latestWrap").hidden = false;
        await loadLicenses();
        setStatus("License issued and stored. Copy the key for the customer.", "good");
      } catch (error) { setStatus(error.message, "bad"); }
      finally { state.busy = false; setConnected(state.connected); }
    }

    async function issueGiveaway() {
      if (!state.connected || state.busy) return;
      const winner = $("giveawayWinner").value.trim();
      const days = Number($("giveawayDays").value || 30);
      const devices = Number($("giveawayDevices").value || 1);
      if (winner.length < 2) return setStatus("Enter a winner alias with at least 2 characters.", "bad");
      if (!Number.isInteger(days) || days < 1 || days > 365) return setStatus("Giveaway duration must be 1 to 365 days.", "bad");
      if (!Number.isInteger(devices) || devices < 1 || devices > 10) return setStatus("Giveaway devices must be 1 to 10.", "bad");
      if (!confirm(`ISSUE A ${days}-DAY GIVEAWAY LICENSE TO ${winner}?`)) return;
      state.busy = true; setConnected(true); setStatus("Issuing giveaway license...");
      try {
        const expires = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
        const result = await api("/api/v1/licenses/issue", { method:"POST", body:JSON.stringify({
          plan_id: $("giveawayRank").value,
          max_devices: devices,
          customer_label: `Giveaway: ${winner}`,
          customer_email: "",
          license_note: `Promotional giveaway license | ${days} day(s) | no payment recorded`,
          expires_at_utc: expires
        }) });
        $("latestKey").value = result.license_key || "";
        $("latestWrap").hidden = false;
        $("giveawayWinner").value = "";
        await loadLicenses(true);
        setStatus(`Giveaway license issued for ${winner}. Copy the latest key.`, "good");
      } catch (error) { setStatus(error.message, "bad"); }
      finally { state.busy = false; setConnected(state.connected); }
    }

    async function publishAnnouncement() {
      if (!state.connected || state.busy) return;
      const title = $("announcementTitle").value.trim();
      const message = $("announcementMessage").value.trim();
      if (title.length < 3) return setStatus("Announcement title must be at least 3 characters.", "bad");
      if (message.length < 5) return setStatus("Announcement message must be at least 5 characters.", "bad");
      if (!confirm(`PUBLISH \"${title}\" TO THE SELECTED LICENSE RANKS?`)) return;
      state.busy = true; setConnected(true); setStatus("Publishing announcement...");
      try {
        const starts = $("announcementStarts").value;
        const expires = $("announcementExpires").value;
        const result = await api("/api/v1/admin/announcements/create", { method:"POST", body:JSON.stringify({
          severity:$("announcementSeverity").value,
          minimum_rank:Number($("announcementRank").value || 1),
          title,
          message,
          starts_at_utc:starts ? new Date(starts).toISOString() : "",
          expires_at_utc:expires ? new Date(expires).toISOString() : ""
        }) });
        $("announcementTitle").value = "";
        $("announcementMessage").value = "";
        $("announcementStarts").value = "";
        $("announcementExpires").value = "";
        await loadLicenses(true);
        setStatus(result.message || "Announcement published.", "good");
      } catch (error) { setStatus(error.message, "bad"); }
      finally { state.busy = false; setConnected(state.connected); }
    }

    async function saveServiceStatus() {
      if (!state.connected || state.busy) return;
      const mode = $("serviceMode").value;
      const message = $("serviceMessage").value.trim();
      const expires = $("serviceExpires").value;
      if (mode !== "normal" && message.length < 5) return setStatus("Write a customer status message with at least 5 characters.", "bad");
      if (!confirm(`SET PUBLIC SERVICE STATUS TO ${mode.toUpperCase()}? This is informational and will not control customer PCs.`)) return;
      state.busy = true; setConnected(true); setStatus("Saving service status...");
      try {
        const result = await api("/api/v1/admin/service-status", { method:"POST", body:JSON.stringify({
          mode,
          message,
          expires_at_utc:expires ? new Date(expires).toISOString() : ""
        }) });
        state.serviceStatus = result.service_status || null;
        await loadLicenses(true);
        setStatus(result.message || "Service status saved.", "good");
      } catch (error) { setStatus(error.message, "bad"); }
      finally { state.busy = false; setConnected(state.connected); }
    }

    async function downloadActivity() {
      try {
        const result = await api("/api/v1/admin/activity/download-link", { method:"POST", body:"{}" });
        const link = document.createElement("a");
        link.href = result.download_path;
        link.download = result.filename || "vaultlink-api-activity.json";
        document.body.append(link);
        link.click();
        window.setTimeout(() => link.remove(), 1500);
        setStatus("Downloaded the tamper-evident API activity log.", "good");
      } catch (error) { setStatus(error.message, "bad"); }
    }

    async function deleteAnnouncement(item) {
      if (!confirm(`PERMANENTLY DELETE ${item.announcement_id}?`)) return;
      try {
        const result = await api("/api/v1/admin/announcements/delete", { method:"POST", body:JSON.stringify({ announcement_id:item.announcement_id }) });
        await loadLicenses(true);
        setStatus(result.message || `Deleted ${item.announcement_id}.`, "good");
      } catch (error) { setStatus(error.message, "bad"); }
    }

    async function saveNote(item, note) {
      try {
        await api("/api/v1/licenses/note", { method:"POST", body:JSON.stringify({ license_key:item.license_key, license_note:note }) });
        await loadLicenses();
        setStatus(`Saved note for ${item.license_id}.`, "good");
      } catch (error) { setStatus(error.message, "bad"); }
    }

    async function changeStatus(item, action) {
      const verb = action === "revoke" ? "block" : "restore";
      const past = action === "revoke" ? "blocked" : "restored";
      if (!confirm(`${verb.toUpperCase()} ${item.license_id}?`)) return;
      try {
        await api(`/api/v1/licenses/${action}`, { method:"POST", body:JSON.stringify({ license_key:item.license_key }) });
        await loadLicenses();
        setStatus(`${item.license_id} ${past}.`, "good");
      } catch (error) { setStatus(error.message, "bad"); }
    }

    async function limitLicense(item) {
      const reason = prompt("Reason shown to the customer:", "Temporary account review.");
      if (reason === null) return;
      const hoursText = prompt("How many hours should LIMITED status last? (1-8760)", "24");
      if (hoursText === null) return;
      const hours = Number(hoursText);
      if (!Number.isInteger(hours) || hours < 1 || hours > 8760) return setStatus("Limit duration must be 1 to 8760 whole hours.", "bad");
      if (reason.trim().length < 3) return setStatus("Limit reason must be at least 3 characters.", "bad");
      if (!confirm(`LIMIT PREMIUM ACCESS FOR ${item.license_id} FOR ${hours} HOUR(S)? Unlock and recovery remain available.`)) return;
      try {
        const result = await api("/api/v1/licenses/limit", { method:"POST", body:JSON.stringify({ license_key:item.license_key, reason:reason.trim(), hours }) });
        await loadLicenses(true);
        setStatus(result.message || `${item.license_id} is temporarily limited.`, "good");
      } catch (error) { setStatus(error.message, "bad"); }
    }

    async function unlimitLicense(item) {
      if (!confirm(`REMOVE LIMITED STATUS FROM ${item.license_id}?`)) return;
      try {
        const result = await api("/api/v1/licenses/unlimit", { method:"POST", body:JSON.stringify({ license_key:item.license_key }) });
        await loadLicenses(true);
        setStatus(result.message || `${item.license_id} is no longer limited.`, "good");
      } catch (error) { setStatus(error.message, "bad"); }
    }

    async function resetDevices(item) {
      if (!confirm(`RESET ALL DEVICE SEATS FOR ${item.license_id}? Existing receipts will need activation again.`)) return;
      try {
        const result = await api("/api/v1/licenses/reset-devices", { method:"POST", body:JSON.stringify({ license_key:item.license_key }) });
        await loadLicenses();
        setStatus(result.message || `Reset devices for ${item.license_id}.`, "good");
      } catch (error) { setStatus(error.message, "bad"); }
    }

    async function toggleDevices(item, host) {
      if (!host.hidden) { host.hidden = true; return; }
      host.hidden = false;
      host.textContent = "Loading anonymous device seats...";
      try {
        const payload = await api(`/api/v1/admin/licenses/${encodeURIComponent(item.license_id)}/devices`);
        host.replaceChildren();
        if (!(payload.items || []).length) {
          host.textContent = "No device seats have been recorded for this license.";
          return;
        }
        for (const device of payload.items) {
          const row = document.createElement("div");
          row.className = "device-row";
          const identity = document.createElement("div");
          identity.textContent = device.machine_hash || "unknown device";
          const meta = document.createElement("div");
          meta.className = "meta";
          const lastSeen = device.last_seen_at_utc ? new Date(device.last_seen_at_utc).toLocaleString() : "not synced yet";
          meta.textContent = `${device.status || "unknown"} | app ${device.app_version || "unknown"} | last sync ${lastSeen}`;
          const remove = actionButton("REMOVE DEVICE", "danger", () => removeDevice(item, device));
          remove.disabled = !device.active;
          row.append(identity, meta, remove);
          host.append(row);
        }
      } catch (error) {
        host.textContent = error.message;
        setStatus(error.message, "bad");
      }
    }

    async function removeDevice(item, device) {
      if (!confirm(`REMOVE DEVICE ${device.machine_hash} FROM ${item.license_id}? Its receipt will stop working at the next sync.`)) return;
      try {
        const result = await api("/api/v1/licenses/remove-device", { method:"POST", body:JSON.stringify({ license_key:item.license_key, machine_hash:device.machine_hash }) });
        await loadLicenses(true);
        setStatus(result.message || `Removed device from ${item.license_id}.`, "good");
      } catch (error) { setStatus(error.message, "bad"); }
    }

    async function saveSupport(item, status, ownerReply, ownerNote) {
      try {
        const result = await api("/api/v1/admin/support-tickets/action", { method:"POST", body:JSON.stringify({
          ticket_id:item.ticket_id,
          status,
          owner_reply:ownerReply,
          owner_note:ownerNote
        }) });
        await loadLicenses(true);
        setStatus(result.message || `Updated ${item.ticket_id}.`, "good");
      } catch (error) { setStatus(error.message, "bad"); }
    }

    async function deleteSupport(item) {
      if (!confirm(`PERMANENTLY DELETE ${item.ticket_id}? This removes the report and owner reply.`)) return;
      try {
        const result = await api("/api/v1/admin/support-tickets/delete", { method:"POST", body:JSON.stringify({ ticket_id:item.ticket_id }) });
        await loadLicenses(true);
        setStatus(result.message || `Deleted ${item.ticket_id}.`, "good");
      } catch (error) { setStatus(error.message, "bad"); }
    }

    async function downloadAudit(item) {
      try {
        const result = await api("/api/v1/admin/audit-exports/download-link", {
          method:"POST",
          body:JSON.stringify({ export_id:item.export_id })
        });
        const link = document.createElement("a");
        link.href = result.download_path;
        link.download = result.filename || `vaultlink-audit-${item.export_id}.json`;
        document.body.append(link);
        link.click();
        window.setTimeout(() => {
          link.remove();
        }, 1500);
        setStatus(`Downloaded ${item.export_id}.`, "good");
      } catch (error) { setStatus(error.message, "bad"); }
    }

    async function copyText(text) {
      if (!text) return setStatus("No key is available to copy.", "bad");
      try { await navigator.clipboard.writeText(text); setStatus("License key copied.", "good"); }
      catch (_) { setStatus("Browser clipboard access was blocked.", "bad"); }
    }

    $("connect").addEventListener("click", connect);
    $("clearToken").addEventListener("click", () => { state.token=""; $("token").value=""; state.items=[]; state.supportItems=[]; state.auditItems=[]; state.announcementItems=[]; state.activityItems=[]; state.activityIntegrity=null; state.serviceStatus=null; state.dashboard=null; setConnected(false); renderDashboard(null); renderRecords(); renderSupport(); renderAudits(); renderAnnouncements(); renderActivity(); setStatus("Admin token cleared from page memory."); });
    $("issue").addEventListener("click", issueLicense);
    $("issueGiveaway").addEventListener("click", issueGiveaway);
    $("refresh").addEventListener("click", () => loadLicenses().catch((error) => setStatus(error.message,"bad")));
    $("refreshSupport").addEventListener("click", () => loadLicenses().catch((error) => setStatus(error.message,"bad")));
    $("refreshLogs").addEventListener("click", () => loadLicenses().catch((error) => setStatus(error.message,"bad")));
    $("publishAnnouncement").addEventListener("click", publishAnnouncement);
    $("refreshAnnouncements").addEventListener("click", () => loadLicenses().catch((error) => setStatus(error.message,"bad")));
    $("saveServiceStatus").addEventListener("click", saveServiceStatus);
    $("refreshActivity").addEventListener("click", () => loadLicenses().catch((error) => setStatus(error.message,"bad")));
    $("downloadActivity").addEventListener("click", downloadActivity);
    $("copyLatest").addEventListener("click", () => copyText($("latestKey").value));
    $("token").addEventListener("keydown", (event) => { if (event.key === "Enter") connect(); });
    window.setInterval(autoRefresh, AUTO_REFRESH_MS);
    loadRanks().catch((error) => setStatus(error.message,"bad"));
  </script>
</body>
</html>"""


def owner_insights_html():
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VaultLink Owner Command Center</title>
  <style>
    :root { color-scheme:dark; --bg:#0c0e11; --band:#12161b; --surface:#181d24; --field:#090b0e; --line:#343d48; --text:#f5f7fa; --muted:#9da9b6; --green:#4ce47a; --blue:#55bce9; --yellow:#f1c94d; --red:#ff6a74; --pink:#ed8ab6; }
    * { box-sizing:border-box; letter-spacing:0; }
    body { margin:0; min-width:320px; background:var(--bg); color:var(--text); font:14px/1.45 "Segoe UI",Arial,sans-serif; }
    header { border-bottom:1px solid var(--line); background:#111419; }
    header > div, main, footer > div { width:min(1240px,calc(100% - 32px)); margin:0 auto; }
    header > div { min-height:72px; display:flex; align-items:center; justify-content:space-between; gap:16px; }
    .brand { display:flex; align-items:baseline; gap:12px; min-width:0; }
    h1 { margin:0; font-size:21px; }
    .version { color:var(--muted); font-size:12px; font-weight:700; }
    nav { display:flex; gap:9px; flex-wrap:wrap; }
    nav a { color:var(--text); text-decoration:none; padding:8px 11px; border:1px solid var(--line); border-radius:6px; font-weight:700; }
    main { padding:24px 0 48px; }
    section { padding:20px 0 24px; border-bottom:1px solid var(--line); }
    h2 { margin:0 0 8px; font-size:17px; }
    p { color:var(--muted); margin:0; }
    .auth { display:grid; grid-template-columns:minmax(220px,1fr) auto auto; gap:10px; align-items:end; margin-top:16px; }
    label { display:block; color:var(--muted); margin-bottom:5px; font-size:11px; font-weight:800; text-transform:uppercase; }
    input,select { width:100%; min-height:40px; border:1px solid var(--line); border-radius:4px; background:var(--field); color:var(--text); padding:9px 11px; font:inherit; }
    button { min-height:40px; border:0; border-radius:4px; padding:0 14px; background:#29313b; color:var(--text); font:800 12px "Segoe UI",Arial,sans-serif; cursor:pointer; }
    button:hover { filter:brightness(1.12); }
    button:disabled { cursor:not-allowed; opacity:.45; }
    .primary { background:var(--green); color:#07130a; }
    .blue { background:var(--blue); color:#071119; }
    .status { min-height:22px; margin-top:10px; color:var(--muted); }
    .status.good { color:var(--green); } .status.bad { color:var(--red); }
    .toolbar { display:grid; grid-template-columns:minmax(180px,1.2fr) minmax(150px,.7fr) minmax(130px,.55fr) repeat(4,auto); gap:9px; align-items:end; }
    .summary { display:flex; justify-content:space-between; gap:12px; align-items:center; flex-wrap:wrap; margin-top:14px; padding:12px 0; color:var(--muted); }
    .count { color:var(--text); font-weight:800; }
    .category { padding:18px 0 8px; }
    .category-head { display:flex; align-items:center; gap:10px; margin-bottom:10px; }
    .category-head h3 { margin:0; font-size:14px; }
    .category-head span { color:var(--muted); font-size:12px; }
    .insights { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:10px; }
    .insight { min-width:0; min-height:132px; padding:14px; border:1px solid var(--line); border-left:4px solid var(--blue); border-radius:8px; background:var(--surface); }
    .insight.good { border-left-color:var(--green); } .insight.warn { border-left-color:var(--yellow); } .insight.bad { border-left-color:var(--red); } .insight.info { border-left-color:var(--blue); }
    .insight-title { color:var(--muted); font-size:11px; font-weight:800; text-transform:uppercase; overflow-wrap:anywhere; }
    .insight-value { margin-top:7px; color:var(--text); font-size:25px; font-weight:800; overflow-wrap:anywhere; }
    .insight-unit { color:var(--muted); font-size:12px; font-weight:700; }
    .insight-detail { margin-top:8px; color:var(--muted); font-size:12px; line-height:1.4; overflow-wrap:anywhere; }
    .empty { padding:36px 0; color:var(--muted); }
    footer { background:var(--band); border-top:1px solid var(--line); }
    footer > div { padding:22px 0 30px; color:var(--muted); font-size:12px; line-height:1.55; }
    @media (max-width:1060px) { .insights { grid-template-columns:repeat(3,minmax(0,1fr)); } .toolbar { grid-template-columns:repeat(3,minmax(0,1fr)); } }
    @media (max-width:760px) { header > div { align-items:flex-start; flex-direction:column; padding:15px 0; } .auth,.toolbar { grid-template-columns:1fr; } .insights { grid-template-columns:repeat(2,minmax(0,1fr)); } button { width:100%; } }
    @media (max-width:470px) { .insights { grid-template-columns:1fr; } .brand { align-items:flex-start; flex-direction:column; gap:2px; } }
  </style>
</head>
<body>
  <header><div><div class="brand"><h1>Owner Command Center</h1><span class="version">50 live insights</span></div><nav><a href="/owner">OWNER CONSOLE</a><a href="/status">CUSTOMER STATUS</a></nav></div></header>
  <main>
    <section>
      <h2>Owner Access</h2>
      <p>This page uses aggregate operational data. Your admin token remains in page memory and is never put in a URL or export.</p>
      <div class="auth">
        <div><label for="token">License admin token</label><input id="token" type="password" autocomplete="off" spellcheck="false"></div>
        <button id="connect" class="primary">CONNECT</button>
        <button id="clear">CLEAR</button>
      </div>
      <div id="status" class="status" role="status" aria-live="polite">Disconnected.</div>
    </section>
    <section>
      <h2>Find And Export</h2>
      <div class="toolbar">
        <div><label for="search">Search insights</label><input id="search" type="search" placeholder="licenses, stale, support..."></div>
        <div><label for="category">Category</label><select id="category"><option value="">ALL CATEGORIES</option></select></div>
        <div><label for="stateFilter">State</label><select id="stateFilter"><option value="">ALL STATES</option><option value="good">GOOD</option><option value="warn">CHECK</option><option value="bad">URGENT</option><option value="info">INFO</option></select></div>
        <button id="refresh" class="blue" disabled>REFRESH</button>
        <button id="copy" disabled>COPY SUMMARY</button>
        <button id="json" disabled>EXPORT JSON</button>
        <button id="csv" disabled>EXPORT CSV</button>
      </div>
      <div class="summary"><span id="showing" class="count">Showing 0 of 50</span><span id="updated">Not loaded</span></div>
    </section>
    <div id="content"><div class="empty">Connect with the owner admin token to load the 50-point report.</div></div>
  </main>
  <footer><div id="privacy">Exports contain aggregate counts only. They do not contain license keys, customer information, notes, device identifiers, paths, PINs, USB secrets, or file contents.</div></footer>
  <script>
    const $ = (id) => document.getElementById(id);
    const state = { token:"", payload:null, visible:[] };

    function setStatus(message, kind="") {
      $("status").textContent = message;
      $("status").className = `status ${kind}`;
    }

    function setConnected(connected) {
      for (const id of ["refresh","copy","json","csv"]) $(id).disabled = !connected;
    }

    async function api(path) {
      const response = await fetch(path, { headers:{ "X-License-Admin-Token":state.token, "Accept":"application/json" }, cache:"no-store" });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.message || `API request failed (${response.status}).`);
      return payload;
    }

    async function connect() {
      const token = $("token").value.trim();
      if (!token) return setStatus("Enter the admin token.", "bad");
      state.token = token;
      await load();
    }

    async function load() {
      setStatus("Loading the 50-point report...");
      try {
        const payload = await api("/api/v1/admin/insights");
        if (payload.count !== 50 || !Array.isArray(payload.items)) throw new Error("The API did not return the complete 50-point report.");
        state.payload = payload;
        buildCategories(payload.categories || []);
        $("privacy").textContent = payload.privacy_notice || $("privacy").textContent;
        $("updated").textContent = `Updated ${new Date(payload.updated_at_utc).toLocaleString()}`;
        setConnected(true);
        render();
        setStatus("Connected. All 50 live insights loaded.", "good");
      } catch (error) {
        state.payload = null;
        state.visible = [];
        setConnected(false);
        $("content").innerHTML = '<div class="empty">The report is not available.</div>';
        $("showing").textContent = "Showing 0 of 50";
        setStatus(error.message, "bad");
      }
    }

    function buildCategories(categories) {
      const select = $("category");
      const current = select.value;
      select.replaceChildren(new Option("ALL CATEGORIES", ""));
      for (const name of categories) select.append(new Option(name.toUpperCase(), name));
      if ([...select.options].some((option) => option.value === current)) select.value = current;
    }

    function filteredItems() {
      if (!state.payload) return [];
      const search = $("search").value.trim().toLowerCase();
      const category = $("category").value;
      const stateValue = $("stateFilter").value;
      return state.payload.items.filter((item) => {
        const text = `${item.title} ${item.detail} ${item.category} ${item.value} ${item.unit || ""}`.toLowerCase();
        return (!search || text.includes(search)) && (!category || item.category === category) && (!stateValue || item.state === stateValue);
      });
    }

    function render() {
      state.visible = filteredItems();
      $("showing").textContent = `Showing ${state.visible.length} of 50`;
      const host = $("content");
      host.replaceChildren();
      if (!state.visible.length) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "No insights match those filters.";
        host.append(empty);
        return;
      }
      const grouped = new Map();
      for (const item of state.visible) {
        if (!grouped.has(item.category)) grouped.set(item.category, []);
        grouped.get(item.category).push(item);
      }
      for (const [category, items] of grouped.entries()) {
        const band = document.createElement("section");
        band.className = "category";
        const head = document.createElement("div");
        head.className = "category-head";
        const title = document.createElement("h3");
        title.textContent = category;
        const count = document.createElement("span");
        count.textContent = `${items.length} insight${items.length === 1 ? "" : "s"}`;
        head.append(title, count);
        const grid = document.createElement("div");
        grid.className = "insights";
        for (const item of items) {
          const card = document.createElement("article");
          card.className = `insight ${item.state || "info"}`;
          const cardTitle = document.createElement("div");
          cardTitle.className = "insight-title";
          cardTitle.textContent = item.title;
          const value = document.createElement("div");
          value.className = "insight-value";
          value.textContent = String(item.value);
          if (item.unit) {
            const unit = document.createElement("span");
            unit.className = "insight-unit";
            unit.textContent = ` ${item.unit}`;
            value.append(unit);
          }
          const detail = document.createElement("div");
          detail.className = "insight-detail";
          detail.textContent = item.detail;
          card.append(cardTitle, value, detail);
          grid.append(card);
        }
        band.append(head, grid);
        host.append(band);
      }
    }

    function reportForExport() {
      return { product:"VaultLink", report:"50-point owner command center", updated_at_utc:state.payload.updated_at_utc, count:state.visible.length, privacy_notice:state.payload.privacy_notice, items:state.visible };
    }

    function download(name, body, type) {
      const url = URL.createObjectURL(new Blob([body], { type }));
      const link = document.createElement("a");
      link.href = url;
      link.download = name;
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    function csvCell(value) { return `"${String(value ?? "").replaceAll('"','""')}"`; }
    function exportJson() { download("vaultlink-owner-insights.json", JSON.stringify(reportForExport(), null, 2), "application/json"); setStatus("Privacy-safe JSON exported.", "good"); }
    function exportCsv() {
      const rows = [["id","category","title","value","unit","state","detail"], ...state.visible.map((item) => [item.id,item.category,item.title,item.value,item.unit || "",item.state,item.detail])];
      download("vaultlink-owner-insights.csv", rows.map((row) => row.map(csvCell).join(",")).join("\\r\\n"), "text/csv");
      setStatus("Privacy-safe CSV exported.", "good");
    }
    async function copySummary() {
      const lines = [`VaultLink Owner Command Center`, `Updated: ${state.payload.updated_at_utc}`, `Showing: ${state.visible.length} of 50`, "", ...state.visible.map((item) => `${item.title}: ${item.value}${item.unit ? ` ${item.unit}` : ""}`)];
      try { await navigator.clipboard.writeText(lines.join("\\n")); setStatus("Privacy-safe summary copied.", "good"); }
      catch (_) { setStatus("Browser clipboard access was blocked.", "bad"); }
    }

    $("connect").addEventListener("click", connect);
    $("clear").addEventListener("click", () => { state.token=""; state.payload=null; state.visible=[]; $("token").value=""; $("content").innerHTML='<div class="empty">Connect with the owner admin token to load the 50-point report.</div>'; $("showing").textContent="Showing 0 of 50"; $("updated").textContent="Not loaded"; setConnected(false); setStatus("Admin token cleared from page memory."); });
    $("refresh").addEventListener("click", load);
    $("copy").addEventListener("click", copySummary);
    $("json").addEventListener("click", exportJson);
    $("csv").addEventListener("click", exportCsv);
    $("search").addEventListener("input", render);
    $("category").addEventListener("change", render);
    $("stateFilter").addEventListener("change", render);
    $("token").addEventListener("keydown", (event) => { if (event.key === "Enter") connect(); });
  </script>
</body>
</html>"""


def public_plans():
    return [public_plan_payload(item) for item in sorted(PLAN_TIERS, key=lambda item: item["rank"])]


def preview_license(payload):
    """Check signed-license status without activating or consuming a device seat."""
    license_key = str(payload.get("license_key", "")).strip()
    if not license_key:
        raise ValueError("license_key is required.")
    license_payload = verify_token(license_key, LICENSE_KEY_PREFIX)
    plan = current_plan_for_license(license_payload)
    status = "active"
    message = "This signed license is active. Use the Windows app to activate it on a PC."
    limited_until = ""
    if license_is_revoked(license_payload):
        status = "revoked"
        message = "This license is blocked from licensed premium features. Local unlock and recovery remain available."
    else:
        limit = license_limit_payload(license_payload)
        if limit:
            status = "limited"
            limited_until = limit["limited_until_utc"]
            message = f"Premium access is limited until {limited_until}: {limit['reason']}"
        elif license_is_expired(license_payload):
            status = "expired"
            message = "This license has expired. Local unlock and recovery remain available."
    release = {
        "latest_version": "",
        "minimum_supported_version": "",
        "published": False,
    }
    try:
        manifest, _package_path = load_windows_update_release()
        release = {
            "latest_version": manifest.get("version", ""),
            "minimum_supported_version": manifest.get("minimum_supported_version", ""),
            "published": True,
            "download_path": manifest.get("download_path", ""),
            "sha256": manifest.get("sha256", ""),
        }
    except (FileNotFoundError, OSError, ValueError):
        pass
    license_id = str(license_payload.get("license_id", ""))
    maximum_devices = max(1, int(license_payload.get("max_devices", 1) or 1))
    used_devices = active_device_count(license_id)
    ordered_plans = sorted(PLAN_TIERS, key=lambda item: item["rank"])
    next_plan = next((item for item in ordered_plans if item["rank"] > plan["rank"]), None)
    actions = [
        "Keep the master USB key and recovery material in separate safe locations.",
        "Use the Windows app for activation, local unlock, recovery, and licensed support messaging.",
        "Verify downloaded update hashes before replacing an installed app folder.",
    ]
    if status == "limited":
        actions.insert(0, "Local unlock and recovery remain available while premium controls are limited.")
    elif status == "revoked":
        actions.insert(0, "Use local unlock or recovery if needed, then contact the license owner about access.")
    elif status == "expired":
        actions.insert(0, "Use local unlock or recovery if needed, then contact the license owner about renewal.")
    return {
        "ok": True,
        "status": status,
        "active": status == "active",
        "message": message,
        "license": {
            "license_id": license_id,
            "plan_id": plan["id"],
            "plan_name": plan["name"],
            "issued_at_utc": license_payload.get("issued_at_utc", ""),
            "expires_at_utc": license_payload.get("expires_at_utc", ""),
        },
        "plan": public_plan_payload(plan),
        "rank_progress": {
            "current": plan["rank"],
            "maximum": len(PLAN_TIERS),
            "percent": round((plan["rank"] / len(PLAN_TIERS)) * 100),
        },
        "device_usage": {
            "active": used_devices,
            "maximum": maximum_devices,
            "available": max(0, maximum_devices - used_devices),
            "identities_excluded": True,
        },
        "next_rank": shop_plan_payload(next_plan) if next_plan else None,
        "customer_actions": actions,
        "limited_until_utc": limited_until,
        "service_status": service_status_payload(),
        "release": release,
        "does_not_activate": True,
        "privacy_notice": (
            "This response excludes customer labels, email addresses, owner notes, machine identifiers, "
            "activation receipts, USB secrets, PINs, paths, and file contents."
        ),
        "server_time_utc": utc_now(),
    }


def license_upgrade_options(payload):
    preview = preview_license(payload)
    current_rank = int(preview["plan"]["rank"])
    current_entitlements = set(preview["plan"]["entitlements"])
    options = []
    for plan in sorted(PLAN_TIERS, key=lambda item: item["rank"]):
        if plan["rank"] <= current_rank:
            continue
        item = shop_plan_payload(plan)
        added_entitlements = [
            feature_id
            for feature_id in item["entitlements"]
            if feature_id not in current_entitlements
        ]
        options.append(
            {
                "plan": item,
                "ranks_up": plan["rank"] - current_rank,
                "added_entitlements": added_entitlements,
                "added_entitlement_count": len(added_entitlements),
            }
        )
    return {
        "ok": True,
        "current_plan": preview["plan"],
        "count": len(options),
        "items": options,
        "highest_rank_reached": not options,
        "checkout_collects_card_data_on_vaultlink": False,
        "privacy_notice": (
            "Upgrade options exclude the license key, customer identity, owner notes, machine identifiers, "
            "activation receipts, payment data, paths, PINs, USB secrets, and file contents."
        ),
        "server_time_utc": utc_now(),
    }


def customer_rank_tools(payload):
    preview = preview_license(payload)
    current_rank = int(preview["plan"]["rank"])
    premium_available = preview["status"] == "active"

    def public_tool(tool, include_checklist):
        result = {
            "id": tool["id"],
            "rank": tool["rank"],
            "rank_name": PLAN_TIERS[tool["rank"] - 1]["name"],
            "name": tool["name"],
            "summary": tool["summary"],
            "category": rank_tool_category(tool["id"]),
            "estimated_minutes": RANK_TOOL_MINUTES[tool["rank"]],
        }
        if include_checklist:
            result["checklist"] = list(tool["checklist"])
        return result

    ordered_tools = sorted(RANK_EXCLUSIVE_TOOLS, key=lambda item: (item["rank"], item["name"]))
    unlocked = [
        public_tool(tool, include_checklist=True)
        for tool in ordered_tools
        if premium_available and tool["rank"] <= current_rank
    ]
    current_exclusive = [item for item in unlocked if item["rank"] == current_rank]
    locked = [
        public_tool(tool, include_checklist=False)
        for tool in ordered_tools
        if not premium_available or tool["rank"] > current_rank
    ]
    message = (
        f"Ranks 1 through {current_rank} unlocked {len(unlocked)} exclusive customer tools."
        if premium_available
        else (
            f"Rank-exclusive premium tools are unavailable while license status is {preview['status']}. "
            "Local unlock and recovery remain available in the Windows app."
        )
    )
    return {
        "ok": True,
        "active": premium_available,
        "license_status": preview["status"],
        "current_rank": current_rank,
        "current_rank_name": preview["plan"]["name"],
        "unlocked_count": len(unlocked),
        "current_rank_exclusive_count": len(current_exclusive),
        "locked_count": len(locked),
        "total_checklist_steps": sum(len(item.get("checklist", [])) for item in unlocked),
        "categories": sorted({item["category"] for item in unlocked}),
        "items": unlocked,
        "current_rank_items": current_exclusive,
        "locked_previews": locked,
        "message": message,
        "recovery_always_available": True,
        "privacy_notice": (
            "Rank tool packs exclude license keys, license ids, customer identity, owner notes, machine identifiers, "
            "activation receipts, payment data, paths, PINs, USB secrets, and file contents."
        ),
        "server_time_utc": utc_now(),
    }


def customer_checkup(payload):
    preview = preview_license(payload)
    rank_tools = customer_rank_tools(payload)
    app_version = str(payload.get("app_version", "") or "").strip()
    if len(app_version) > 80:
        raise ValueError("app_version must be 80 characters or fewer.")

    def version_parts(value):
        parts = []
        for part in str(value or "").replace("-", ".").split("."):
            digits = "".join(character for character in part if character.isdigit())
            parts.append(int(digits or 0))
        return tuple(parts)

    attention = []

    def add(identifier, severity, title, detail):
        attention.append(
            {"id": identifier, "severity": severity, "title": title, "detail": detail}
        )

    if preview["status"] == "active":
        add("license", "good", "License active", "Signed license status is active.")
    else:
        add("license", "action", f"License {preview['status']}", preview["message"])

    service = preview["service_status"]
    if service.get("mode") == "normal":
        add("service", "good", "Service normal", service.get("message", "Service is operating normally."))
    else:
        add("service", "check", f"Service {service.get('mode', 'unknown')}", service.get("message", "Review service status."))

    devices = preview["device_usage"]
    if devices["available"] > 0:
        add("devices", "good", "Device seat available", f"{devices['available']} of {devices['maximum']} anonymous seats remain available.")
    else:
        add("devices", "check", "Device seats full", f"All {devices['maximum']} anonymous device seats are in use.")

    expires_at = parse_utc(preview["license"].get("expires_at_utc"))
    if expires_at is None:
        add("expiration", "info", "No expiration set", "This signed license does not include an expiration time.")
    else:
        days_left = max(0, int((expires_at - datetime.now(timezone.utc)).total_seconds() // 86400))
        if days_left <= 7:
            add("expiration", "action", "Expiration close", f"The license expires in {days_left} day(s).")
        elif days_left <= 30:
            add("expiration", "check", "Expiration approaching", f"The license expires in {days_left} day(s).")
        else:
            add("expiration", "good", "Expiration not close", f"The license expires in {days_left} day(s).")

    release = preview["release"]
    latest_version = str(release.get("latest_version", ""))
    if not release.get("published"):
        add("update", "check", "No signed update published", "The owner has not published a Windows update package.")
    elif not app_version:
        add("update", "info", "App version not entered", f"Latest signed release is {latest_version}.")
    elif version_parts(app_version) < version_parts(latest_version):
        add("update", "check", "Update available", f"Installed {app_version}; latest signed release is {latest_version}.")
    else:
        add("update", "good", "App version current", f"Installed version {app_version} is current against {latest_version}.")

    if rank_tools["active"]:
        add("rank-tools", "good", "Rank tools available", f"{rank_tools['unlocked_count']} rank-exclusive tools are unlocked.")
    else:
        add("rank-tools", "action", "Rank tools unavailable", rank_tools["message"])

    counts = {severity: sum(item["severity"] == severity for item in attention) for severity in ("good", "info", "check", "action")}
    overall = "action" if counts["action"] else "check" if counts["check"] else "good"
    return {
        "ok": True,
        "overall": overall,
        "counts": counts,
        "attention_count": counts["check"] + counts["action"],
        "items": attention,
        "app_version": app_version,
        "server_time_utc": utc_now(),
        "limitations": [
            "This is a license, service, seat, release, and rank-tool checkup, not an antivirus scan.",
            "It is not a security certification, compliance determination, or guarantee against data loss.",
            "It cannot inspect, lock, unlock, execute, or modify anything on the customer PC.",
        ],
        "privacy_notice": (
            "Customer checkup responses exclude license keys, license ids, customer identity, owner notes, "
            "machine identifiers, activation receipts, payment data, paths, PINs, USB secrets, and file contents."
        ),
    }


def require_json_object(payload):
    if not isinstance(payload, dict):
        raise ValueError("Body must be a JSON object.")
    return payload


def issue_license(payload):
    plan_id = canonical_plan_id(payload.get("plan_id", ""))
    if plan_id not in PLAN_INDEX:
        raise ValueError("Choose a valid plan id.")
    expires_at = parse_utc(payload.get("expires_at_utc"))
    if expires_at and expires_at <= datetime.now(timezone.utc):
        raise ValueError("expires_at_utc must be in the future.")
    max_devices = int(payload.get("max_devices", 1) or 1)
    if max_devices < 1 or max_devices > 1000:
        raise ValueError("max_devices must be between 1 and 1000.")
    plan = PLAN_INDEX[plan_id]
    customer_label = str(payload.get("customer_label", "")).strip()
    customer_email = str(payload.get("customer_email", "")).strip()
    if len(customer_label) > 160:
        raise ValueError("customer_label must be 160 characters or fewer.")
    if len(customer_email) > 254:
        raise ValueError("customer_email must be 254 characters or fewer.")
    license_note = clean_license_note(payload.get("license_note", ""))
    license_id = validated_license_id(
        payload.get("license_id") or f"LIC-{secrets.token_hex(8).upper()}"
    )
    if read_license_record(license_id):
        raise ValueError("That license_id already exists.")
    license_payload = {
        "license_id": license_id,
        "product": "USB File Locker",
        "plan_id": plan["id"],
        "plan_name": plan["name"],
        "entitlements": plan_entitlements(plan["id"]),
        "customer_label": customer_label,
        "customer_email": customer_email,
        "issued_at_utc": utc_now(),
        "expires_at_utc": format_utc(expires_at) if expires_at else "",
        "max_devices": max_devices,
        "issuer": API_NAME,
    }
    license_key = sign_token(LICENSE_KEY_PREFIX, license_payload)
    write_license_record(license_payload, license_key, license_note=license_note, status="active")
    record_api_activity("license_issue", "ok", "license", license_id)
    return {
        "ok": True,
        "issued": True,
        "license_key": license_key,
        "license": license_payload,
        "plan": public_plan_payload(plan),
        "server_time_utc": utc_now(),
        "limitations": [
            "Signed keys are checked against the server revocation ledger.",
            "Device seats are enforced by the persistent anonymous activation ledger.",
        ],
    }


def activate_license(payload):
    license_key = str(payload.get("license_key", "")).strip()
    machine_id = str(payload.get("machine_id", "")).strip()
    machine_name = str(payload.get("machine_name", "")).strip()
    if not license_key:
        raise ValueError("license_key is required.")
    if not machine_id:
        raise ValueError("machine_id is required.")
    if len(machine_id) > 256:
        raise ValueError("machine_id must be 256 characters or fewer.")
    if len(machine_name) > 160:
        raise ValueError("machine_name must be 160 characters or fewer.")
    license_payload = verify_token(license_key, LICENSE_KEY_PREFIX)
    if license_is_revoked(license_payload):
        plan = current_plan_for_license(license_payload)
        return {
            "ok": True,
            "active": False,
            "status": "revoked",
            "plan": public_plan_payload(plan),
            "license": {
                "license_id": license_payload.get("license_id", ""),
                "plan_id": plan["id"],
                "plan_name": plan["name"],
                "expires_at_utc": license_payload.get("expires_at_utc", ""),
            },
            "message": "This license was revoked by its owner.",
            "server_time_utc": utc_now(),
        }
    limit = license_limit_payload(license_payload)
    if limit:
        plan = current_plan_for_license(license_payload)
        return {
            "ok": True,
            "active": False,
            "status": "limited",
            "plan": public_plan_payload(plan),
            "license": {
                "license_id": license_payload.get("license_id", ""),
                "plan_id": plan["id"],
                "plan_name": plan["name"],
                "expires_at_utc": license_payload.get("expires_at_utc", ""),
            },
            "limited_until_utc": limit["limited_until_utc"],
            "message": f"Limited access until {limit['limited_until_utc']}: {limit['reason']}",
            "server_time_utc": utc_now(),
        }
    if license_is_expired(license_payload):
        plan = current_plan_for_license(license_payload)
        return {
            "ok": True,
            "active": False,
            "status": "expired",
            "plan": public_plan_payload(plan),
            "license": {
                "license_id": license_payload.get("license_id", ""),
                "plan_id": plan["id"],
                "plan_name": plan["name"],
                "expires_at_utc": license_payload.get("expires_at_utc", ""),
            },
            "message": "This license has expired.",
            "server_time_utc": utc_now(),
        }
    plan = current_plan_for_license(license_payload)
    activated_at = datetime.now(timezone.utc)
    valid_until = activated_at + timedelta(days=30)
    receipt_payload = {
        "receipt_id": f"RCT-{secrets.token_hex(8).upper()}",
        "license_id": license_payload.get("license_id", ""),
        "plan_id": plan["id"],
        "machine_id": machine_id,
        "machine_name": machine_name,
        "activated_at_utc": format_utc(activated_at),
        "valid_until_utc": format_utc(valid_until),
        "app_version": str(payload.get("app_version", "")).strip(),
    }
    receipt = sign_token(LICENSE_RECEIPT_PREFIX, receipt_payload)
    registered, used_devices = register_activation_receipt(
        license_payload,
        receipt,
        receipt_payload,
    )
    if not registered:
        return {
            "ok": True,
            "active": False,
            "status": "device_limit",
            "plan": public_plan_payload(plan),
            "license": {
                "license_id": license_payload.get("license_id", ""),
                "plan_id": plan["id"],
                "plan_name": plan["name"],
                "expires_at_utc": license_payload.get("expires_at_utc", ""),
            },
            "device_usage": {
                "active": used_devices,
                "maximum": int(license_payload.get("max_devices", 1) or 1),
            },
            "message": "This license has reached its active-device limit. Remove a device or ask the owner to reset device seats.",
            "server_time_utc": utc_now(),
        }
    return {
        "ok": True,
        "active": True,
        "status": "active",
        "plan": public_plan_payload(plan),
        "license": {
            "license_id": license_payload.get("license_id", ""),
            "plan_id": plan["id"],
            "plan_name": plan["name"],
            "expires_at_utc": license_payload.get("expires_at_utc", ""),
            "customer_label": license_payload.get("customer_label", ""),
            "customer_email": license_payload.get("customer_email", ""),
        },
        "activation": receipt_payload,
        "receipt": receipt,
        "device_usage": {
            "active": used_devices,
            "maximum": int(license_payload.get("max_devices", 1) or 1),
        },
        "server_time_utc": utc_now(),
    }


def verify_license(payload):
    license_key = str(payload.get("license_key", "")).strip()
    machine_id = str(payload.get("machine_id", "")).strip()
    receipt = str(payload.get("receipt", "")).strip()
    if not license_key:
        raise ValueError("license_key is required.")
    if not machine_id:
        raise ValueError("machine_id is required.")
    if len(machine_id) > 256:
        raise ValueError("machine_id must be 256 characters or fewer.")
    license_payload = verify_token(license_key, LICENSE_KEY_PREFIX)
    plan = current_plan_for_license(license_payload)
    license_view = {
        "license_id": license_payload.get("license_id", ""),
        "plan_id": plan["id"],
        "plan_name": plan["name"],
        "expires_at_utc": license_payload.get("expires_at_utc", ""),
        "customer_label": license_payload.get("customer_label", ""),
        "customer_email": license_payload.get("customer_email", ""),
    }
    if license_is_revoked(license_payload):
        return {
            "ok": True,
            "active": False,
            "status": "revoked",
            "plan": public_plan_payload(plan),
            "license": license_view,
            "message": "This license was revoked by its owner.",
            "server_time_utc": utc_now(),
        }
    limit = license_limit_payload(license_payload)
    if limit:
        return {
            "ok": True,
            "active": False,
            "status": "limited",
            "plan": public_plan_payload(plan),
            "license": license_view,
            "limited_until_utc": limit["limited_until_utc"],
            "message": f"Limited access until {limit['limited_until_utc']}: {limit['reason']}",
            "server_time_utc": utc_now(),
        }
    if license_is_expired(license_payload):
        return {
            "ok": True,
            "active": False,
            "status": "expired",
            "plan": public_plan_payload(plan),
            "license": license_view,
            "message": "This license has expired.",
            "server_time_utc": utc_now(),
        }
    if not receipt:
        return {
            "ok": True,
            "active": False,
            "status": "activation_required",
            "plan": public_plan_payload(plan),
            "license": license_view,
            "message": "Activate this license on this PC to get a machine-bound receipt.",
            "server_time_utc": utc_now(),
        }
    receipt_payload = verify_token(receipt, LICENSE_RECEIPT_PREFIX)
    if receipt_payload.get("license_id") != license_payload.get("license_id"):
        return {
            "ok": True,
            "active": False,
            "status": "receipt_mismatch",
            "plan": public_plan_payload(plan),
            "license": license_view,
            "message": "The saved activation receipt belongs to a different license.",
            "server_time_utc": utc_now(),
        }
    if receipt_payload.get("machine_id") != machine_id:
        return {
            "ok": True,
            "active": False,
            "status": "wrong_machine",
            "plan": public_plan_payload(plan),
            "license": license_view,
            "message": "The saved activation receipt belongs to a different PC.",
            "server_time_utc": utc_now(),
        }
    if receipt_is_deactivated(receipt):
        return {
            "ok": True,
            "active": False,
            "status": "deactivated",
            "plan": public_plan_payload(plan),
            "license": license_view,
            "activation": receipt_payload,
            "message": "This activation was removed from this PC. Activate again to create a new receipt.",
            "server_time_utc": utc_now(),
        }
    if receipt_is_expired(receipt_payload):
        return {
            "ok": True,
            "active": False,
            "status": "receipt_expired",
            "plan": public_plan_payload(plan),
            "license": license_view,
            "activation": receipt_payload,
            "message": "The saved activation receipt expired. Activate again on this PC.",
            "server_time_utc": utc_now(),
        }
    activation_allowed, activation_status, used_devices = verify_activation_receipt(
        license_payload,
        receipt,
        receipt_payload,
        app_version=payload.get("app_version", ""),
    )
    if not activation_allowed:
        messages = {
            "device_limit": "This license has reached its active-device limit.",
            "reset": "The owner reset this license's device seats. Activate again on this PC.",
            "deactivated": "This activation was removed from this PC. Activate again to create a new receipt.",
            "receipt_replaced": "A newer activation receipt replaced this one on the same PC.",
            "removed": "The owner removed this device seat. Activate again only if the owner permits it.",
        }
        return {
            "ok": True,
            "active": False,
            "status": activation_status,
            "plan": public_plan_payload(plan),
            "license": license_view,
            "activation": receipt_payload,
            "device_usage": {
                "active": used_devices,
                "maximum": int(license_payload.get("max_devices", 1) or 1),
            },
            "message": messages.get(activation_status, "This activation is no longer active."),
            "server_time_utc": utc_now(),
        }
    return {
        "ok": True,
        "active": True,
        "status": "active",
        "plan": public_plan_payload(plan),
        "license": license_view,
        "activation": receipt_payload,
        "device_usage": {
            "active": used_devices,
            "maximum": int(license_payload.get("max_devices", 1) or 1),
        },
        "server_time_utc": utc_now(),
    }


def sync_license(payload):
    result = dict(verify_license(payload))
    decision = str(result.get("status", "unknown") or "unknown")
    result["api_version"] = API_VERSION
    result["sync"] = {
        "automatic": True,
        "recommended_interval_seconds": LICENSE_SYNC_INTERVAL_SECONDS,
        "decision": decision,
        "decision_id": secrets.token_hex(8),
        "api_version": API_VERSION,
        "revocation_enforced": True,
        "device_seats_enforced": True,
    }
    try:
        manifest, _package_path = load_windows_update_release()
        current_parts = tuple(
            int(part) if part.isdigit() else 0
            for part in str(payload.get("app_version", "")).split(".")
        )
        latest_parts = tuple(
            int(part) if part.isdigit() else 0
            for part in str(manifest.get("version", "")).split(".")
        )
        result["release"] = {
            "latest_version": manifest.get("version", ""),
            "minimum_supported_version": manifest.get("minimum_supported_version", ""),
            "update_available": bool(latest_parts and latest_parts > current_parts),
        }
    except (FileNotFoundError, OSError, ValueError):
        result["release"] = {
            "latest_version": "",
            "minimum_supported_version": "",
            "update_available": False,
        }
    result["server_time_utc"] = utc_now()
    result["service_status"] = service_status_payload()
    plan_rank = int((result.get("plan") or {}).get("rank", 1) or 1)
    announcement_items = (
        active_announcements_for_rank(plan_rank, limit=5)
        if result.get("active") or result.get("status") == "limited"
        else []
    )
    result["announcements"] = {
        "count": len(announcement_items),
        "items": announcement_items,
    }
    return result


def deactivate_license(payload):
    verification = verify_license(payload)
    receipt = str(payload.get("receipt", "")).strip()
    if verification.get("status") == "deactivated":
        return {
            **verification,
            "deactivated": True,
            "message": "This activation was already removed from this PC.",
        }
    if not verification.get("active"):
        return {
            **verification,
            "deactivated": False,
        }
    receipt_payload = verify_token(receipt, LICENSE_RECEIPT_PREFIX)
    deactivation = mark_receipt_deactivated(
        receipt,
        receipt_payload,
        app_version=payload.get("app_version", ""),
    )
    deactivate_activation_record(receipt_payload)
    used_devices = active_device_count(receipt_payload.get("license_id", ""))
    return {
        "ok": True,
        "active": False,
        "deactivated": True,
        "status": "deactivated",
        "license": verification.get("license", {}),
        "plan": verification.get("plan", {}),
        "deactivation": {
            "receipt_id": deactivation["receipt_id"],
            "deactivated_at_utc": deactivation["deactivated_at_utc"],
        },
        "device_usage": {
            "active": used_devices,
            "maximum": int((verification.get("device_usage") or {}).get("maximum", 1) or 1),
        },
        "message": "This license activation was removed from this PC.",
        "server_time_utc": utc_now(),
    }


def require_admin_license_key(payload):
    license_key = str(payload.get("license_key", "")).strip()
    if not license_key:
        raise ValueError("license_key is required.")
    license_payload = verify_token(license_key, LICENSE_KEY_PREFIX)
    current_plan_for_license(license_payload)
    validated_license_id(license_payload.get("license_id"))
    return license_key, license_payload


def revoke_license(payload):
    license_key, license_payload = require_admin_license_key(payload)
    note = clean_license_note(payload.get("revocation_note", ""))
    record = write_license_record(
        license_payload,
        license_key,
        license_note=None,
        status="revoked",
        revocation_note=note,
    )
    record_api_activity("license_revoke", "ok", "license", license_payload.get("license_id"))
    return {
        "ok": True,
        "revoked": True,
        "license": admin_license_record_view(record, include_private=False),
        "message": "The license is revoked. Existing and future activation checks will fail.",
        "server_time_utc": utc_now(),
    }


def restore_license(payload):
    license_key, license_payload = require_admin_license_key(payload)
    record = write_license_record(
        license_payload,
        license_key,
        license_note=None,
        status="active",
        revocation_note="",
    )
    record_api_activity("license_restore", "ok", "license", license_payload.get("license_id"))
    return {
        "ok": True,
        "restored": True,
        "license": admin_license_record_view(record, include_private=False),
        "message": "The license is active again. Individually deactivated receipts remain deactivated.",
        "server_time_utc": utc_now(),
    }


def limit_license(payload):
    _license_key, license_payload = require_admin_license_key(payload)
    try:
        hours = int(payload.get("hours", 24) or 24)
    except (TypeError, ValueError) as exc:
        raise ValueError("hours must be a whole number from 1 to 8760.") from exc
    if not 1 <= hours <= 8760:
        raise ValueError("hours must be a whole number from 1 to 8760.")
    reason = "".join(
        character if ord(character) >= 32 else " "
        for character in str(payload.get("reason", "Limited by the license owner."))
    ).strip()[:240]
    if len(reason) < 3:
        raise ValueError("reason must be at least 3 characters.")
    now = datetime.now(timezone.utc)
    record = {
        "schema_version": 1,
        "license_id": validated_license_id(license_payload.get("license_id")),
        "reason": reason,
        "limited_at_utc": format_utc(now),
        "limited_until_utc": format_utc(now + timedelta(hours=hours)),
    }
    write_private_json(license_limit_path(record["license_id"]), record)
    record_api_activity("license_limit", "ok", "license", record["license_id"])
    return {
        "ok": True,
        "limited": True,
        "license_id": record["license_id"],
        "reason": reason,
        "limited_until_utc": record["limited_until_utc"],
        "message": "Licensed premium controls are temporarily limited. Unlock and recovery access are not remotely disabled.",
        "server_time_utc": utc_now(),
    }


def unlimit_license(payload):
    _license_key, license_payload = require_admin_license_key(payload)
    license_id = validated_license_id(license_payload.get("license_id"))
    path = license_limit_path(license_id)
    existed = path.is_file()
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        raise ValueError("The limited-status record could not be removed.") from exc
    record_api_activity("license_unlimit", "ok", "license", license_id)
    return {
        "ok": True,
        "limited": False,
        "restored": existed,
        "license_id": license_id,
        "message": "Temporary limited status was removed. The next customer sync can restore licensed premium controls.",
        "server_time_utc": utc_now(),
    }


def update_license_note(payload):
    license_key, license_payload = require_admin_license_key(payload)
    note = clean_license_note(payload.get("license_note", ""))
    record = write_license_record(
        license_payload,
        license_key,
        license_note=note,
    )
    record_api_activity("license_note_update", "ok", "license", license_payload.get("license_id"))
    return {
        "ok": True,
        "saved": True,
        "license": admin_license_record_view(record),
        "message": "Private owner note saved.",
        "server_time_utc": utc_now(),
    }


def admin_reset_license_devices(payload):
    license_key, license_payload = require_admin_license_key(payload)
    reset_count = reset_license_devices(license_payload)
    license_id = validated_license_id(license_payload.get("license_id"))
    record_api_activity("license_device_reset", "ok", "license", license_id)
    return {
        "ok": True,
        "devices_reset": reset_count,
        "license": {
            "license_id": license_id,
            "active_devices": active_device_count(license_id),
            "max_devices": int(license_payload.get("max_devices", 1) or 1),
        },
        "message": f"Reset {reset_count} active device seat(s). Those PCs must activate again.",
        "server_time_utc": utc_now(),
    }


def admin_remove_license_device(payload):
    _license_key, license_payload = require_admin_license_key(payload)
    license_id = validated_license_id(license_payload.get("license_id"))
    machine_hash = validated_machine_hash(payload.get("machine_hash"))
    with LICENSE_STATE_LOCK:
        path = activation_folder(license_id) / f"{machine_hash}.json"
        if not path.is_file():
            raise FileNotFoundError("That anonymous device seat was not found.")
        record = json.loads(path.read_text(encoding="utf-8"))
        if record.get("license_id") != license_id or record.get("machine_hash") != machine_hash:
            raise ValueError("Stored activation record identity did not verify.")
        was_active = activation_record_is_active(record)
        record["status"] = "removed"
        record["removed_at_utc"] = utc_now()
        record["updated_at_utc"] = record["removed_at_utc"]
        write_private_json(path, record)
    record_api_activity("license_device_remove", "ok", "device", machine_hash)
    return {
        "ok": True,
        "removed": True,
        "was_active": was_active,
        "license": {
            "license_id": license_id,
            "active_devices": active_device_count(license_id),
            "max_devices": int(license_payload.get("max_devices", 1) or 1),
        },
        "device": {"machine_hash": machine_hash, "status": "removed"},
        "message": "The anonymous device seat was removed. Its saved receipt will fail at the next automatic sync.",
        "server_time_utc": utc_now(),
    }


def clean_support_text(value, limit, field_name, required=False, minimum=1):
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    text = "".join(
        character if ord(character) >= 32 or character in {"\n", "\t"} else " "
        for character in text
    ).strip()
    if len(text) > limit:
        raise ValueError(f"{field_name} must be {limit} characters or fewer.")
    if required and len(text) < minimum:
        raise ValueError(f"{field_name} must be at least {minimum} characters.")
    return text


def validated_support_ticket_id(value):
    text = str(value or "").strip().upper()
    if (
        not text.startswith("TKT-")
        or not 12 <= len(text) <= 64
        or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for character in text)
    ):
        raise ValueError("Choose a valid support ticket id.")
    return text


def support_ticket_path(ticket_id):
    return LICENSE_STATE_DIR / "support_tickets" / f"{validated_support_ticket_id(ticket_id)}.json"


def read_support_ticket(ticket_id):
    clean_ticket_id = validated_support_ticket_id(ticket_id)
    path = support_ticket_path(clean_ticket_id)
    if not path.is_file():
        raise FileNotFoundError("Support ticket was not found.")
    record = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(record, dict) or record.get("ticket_id") != clean_ticket_id:
        raise ValueError("Stored support ticket identity did not verify.")
    return record


def support_ticket_private_fields(record):
    return decrypt_support_private_fields(record)


def support_ticket_view(record, audience="admin"):
    private = support_ticket_private_fields(record)
    item = {
        "ticket_id": str(record.get("ticket_id", "")),
        "category": str(record.get("category", "other")),
        "status": str(record.get("status", "open")),
        "created_at_utc": str(record.get("created_at_utc", "")),
        "updated_at_utc": str(record.get("updated_at_utc", "")),
        "acknowledged_at_utc": str(record.get("acknowledged_at_utc", "")),
        "resolved_at_utc": str(record.get("resolved_at_utc", "")),
        "closed_at_utc": str(record.get("closed_at_utc", "")),
        "app_version": str(record.get("app_version", "")),
        "subject": str(private.get("subject", "")),
        "message": str(private.get("message", "")),
        "steps": str(private.get("steps", "")),
        "owner_reply": str(private.get("owner_reply", "")),
        "history": list(record.get("history", []))[-50:],
    }
    if audience == "admin":
        item.update(
            {
                "license_id": str(record.get("license_id", "")),
                "plan_id": str(record.get("plan_id", "")),
                "machine_hash": str(record.get("machine_hash", "")),
                "owner_note": str(private.get("owner_note", "")),
            }
        )
    return item


def support_ticket_records():
    folder = LICENSE_STATE_DIR / "support_tickets"
    if not folder.is_dir():
        return []
    paths = sorted(
        folder.glob("TKT-*.json"),
        key=lambda path: path.stat().st_mtime if path.exists() else 0,
        reverse=True,
    )[:MAX_SUPPORT_TICKETS]
    records = []
    for path in paths:
        try:
            records.append(read_support_ticket(path.stem))
        except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
            continue
    return records


def require_active_support_license(payload):
    try:
        verification = verify_license(payload)
    except ValueError as exc:
        raise PermissionError(f"License verification failed: {exc}") from exc
    if not verification.get("active"):
        raise PermissionError(verification.get("message") or "An active license is required to contact support.")
    return verification


def create_support_ticket(payload):
    verification = require_active_support_license(payload)
    category = str(payload.get("category", "bug") or "bug").strip().lower()
    if category not in SUPPORT_TICKET_CATEGORIES:
        raise ValueError("Choose a valid support category.")
    subject = clean_support_text(payload.get("subject"), 160, "subject", required=True, minimum=3)
    message = clean_support_text(payload.get("message"), 4000, "message", required=True, minimum=10)
    steps = clean_support_text(payload.get("steps"), 6000, "steps")
    app_version = clean_support_text(payload.get("app_version"), 80, "app_version")
    machine_hash = anonymous_machine_hash(payload.get("machine_id", ""))
    license_view = verification.get("license") or {}
    plan = verification.get("plan") or {}
    license_id = validated_license_id(license_view.get("license_id"))
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=1)
    with LICENSE_STATE_LOCK:
        recent_count = sum(
            record.get("machine_hash") == machine_hash
            and (parse_utc(record.get("created_at_utc")) or datetime.min.replace(tzinfo=timezone.utc)) >= cutoff
            for record in support_ticket_records()
        )
        if recent_count >= MAX_SUPPORT_TICKETS_PER_DAY:
            raise PermissionError("This PC has reached the daily support-ticket limit. Try again later.")
        ticket_id = f"TKT-{secrets.token_hex(8).upper()}"
        now_text = format_utc(now)
        private = {
            "subject": subject,
            "message": message,
            "steps": steps,
            "owner_reply": "",
            "owner_note": "",
        }
        record = {
            "schema_version": 1,
            "ticket_id": ticket_id,
            "license_id": license_id,
            "plan_id": str(plan.get("id", ""))[:40],
            "machine_hash": machine_hash,
            "category": category,
            "status": "open",
            "app_version": app_version,
            "created_at_utc": now_text,
            "updated_at_utc": now_text,
            "acknowledged_at_utc": "",
            "resolved_at_utc": "",
            "closed_at_utc": "",
            "history": [{"time_utc": now_text, "action": "created", "status": "open"}],
            "private_blob": encrypt_support_private_fields(private),
        }
        write_private_json(support_ticket_path(ticket_id), record)
    return {
        "ok": True,
        "created": True,
        "ticket": support_ticket_view(record, audience="customer"),
        "message": "Bug report sent to the VaultLink owner.",
        "privacy_notice": "No files or local logs were attached automatically.",
        "server_time_utc": utc_now(),
    }


def list_my_support_tickets(payload):
    verification = require_active_support_license(payload)
    license_id = str((verification.get("license") or {}).get("license_id", ""))
    machine_hash = anonymous_machine_hash(payload.get("machine_id", ""))
    items = []
    for record in support_ticket_records():
        if record.get("license_id") != license_id or record.get("machine_hash") != machine_hash:
            continue
        try:
            items.append(support_ticket_view(record, audience="customer"))
        except (InvalidTag, OSError, ValueError, json.JSONDecodeError):
            continue
        if len(items) >= 50:
            break
    return {
        "ok": True,
        "count": len(items),
        "items": items,
        "server_time_utc": utc_now(),
    }


def list_admin_support_tickets():
    items = []
    damaged_count = 0
    for record in support_ticket_records():
        try:
            items.append(support_ticket_view(record, audience="admin"))
        except (InvalidTag, OSError, ValueError, json.JSONDecodeError):
            damaged_count += 1
    return {
        "ok": True,
        "count": len(items),
        "damaged_count": damaged_count,
        "items": items,
        "storage": "persistent_configured" if license_state_storage_is_persistent() else "local_ephemeral",
        "privacy_notice": "Ticket text is encrypted at rest. Files, logs, secrets, and raw machine ids are never attached automatically.",
        "server_time_utc": utc_now(),
    }


def admin_update_support_ticket(payload):
    ticket_id = validated_support_ticket_id(payload.get("ticket_id"))
    status = str(payload.get("status", "") or "").strip().lower()
    if status not in SUPPORT_TICKET_STATUSES:
        raise ValueError("Choose a valid support ticket status.")
    owner_reply = clean_support_text(payload.get("owner_reply"), 4000, "owner_reply")
    owner_note = clean_support_text(payload.get("owner_note"), 4000, "owner_note")
    with LICENSE_STATE_LOCK:
        record = read_support_ticket(ticket_id)
        private = support_ticket_private_fields(record)
        private["owner_reply"] = owner_reply
        private["owner_note"] = owner_note
        now = utc_now()
        record["status"] = status
        record["updated_at_utc"] = now
        if status != "open" and not record.get("acknowledged_at_utc"):
            record["acknowledged_at_utc"] = now
        if status == "resolved":
            record["resolved_at_utc"] = now
            record["closed_at_utc"] = ""
        elif status == "closed":
            record["closed_at_utc"] = now
        elif status in {"open", "acknowledged", "in_progress"}:
            record["resolved_at_utc"] = ""
            record["closed_at_utc"] = ""
        history = list(record.get("history", []))[-49:]
        history.append({"time_utc": now, "action": "owner_update", "status": status})
        record["history"] = history
        record["private_blob"] = encrypt_support_private_fields(private)
        write_private_json(support_ticket_path(ticket_id), record)
    record_api_activity("support_ticket_update", "ok", "support_ticket", ticket_id)
    return {
        "ok": True,
        "saved": True,
        "ticket": support_ticket_view(record, audience="admin"),
        "message": f"Support ticket {ticket_id} updated.",
        "server_time_utc": utc_now(),
    }


def admin_delete_support_ticket(payload):
    ticket_id = validated_support_ticket_id(payload.get("ticket_id"))
    with LICENSE_STATE_LOCK:
        path = support_ticket_path(ticket_id)
        if not path.is_file():
            raise FileNotFoundError("Support ticket was not found.")
        path.unlink()
    record_api_activity("support_ticket_delete", "ok", "support_ticket", ticket_id)
    return {
        "ok": True,
        "deleted": True,
        "ticket_id": ticket_id,
        "message": f"Support ticket {ticket_id} permanently deleted.",
        "server_time_utc": utc_now(),
    }


def validated_announcement_id(value):
    text = str(value or "").strip().upper()
    if (
        not text.startswith("ANN-")
        or not 12 <= len(text) <= 64
        or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for character in text)
    ):
        raise ValueError("Choose a valid announcement id.")
    return text


def announcement_path(announcement_id):
    return LICENSE_STATE_DIR / "announcements" / f"{validated_announcement_id(announcement_id)}.json"


def read_announcement(announcement_id):
    clean_id = validated_announcement_id(announcement_id)
    path = announcement_path(clean_id)
    if not path.is_file():
        raise FileNotFoundError("Announcement was not found.")
    record = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(record, dict) or record.get("announcement_id") != clean_id:
        raise ValueError("Stored announcement identity did not verify.")
    return record


def announcement_records():
    folder = LICENSE_STATE_DIR / "announcements"
    if not folder.is_dir():
        return []
    paths = sorted(
        folder.glob("ANN-*.json"),
        key=lambda path: path.stat().st_mtime if path.exists() else 0,
        reverse=True,
    )[:MAX_ANNOUNCEMENTS]
    records = []
    for path in paths:
        try:
            records.append(read_announcement(path.stem))
        except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
            continue
    return records


def announcement_is_active(record, moment=None):
    if not bool(record.get("active", True)):
        return False
    now = moment or datetime.now(timezone.utc)
    starts_at = parse_utc(record.get("starts_at_utc"))
    expires_at = parse_utc(record.get("expires_at_utc"))
    if starts_at and starts_at > now:
        return False
    if expires_at and expires_at <= now:
        return False
    return True


def announcement_view(record):
    minimum_rank = int(record.get("minimum_rank", 1) or 1)
    audience = "All ranks" if minimum_rank == 1 else f"Rank {minimum_rank} and above"
    return {
        "announcement_id": str(record.get("announcement_id", "")),
        "severity": str(record.get("severity", "info")),
        "title": str(record.get("title", "")),
        "message": str(record.get("message", "")),
        "minimum_rank": minimum_rank,
        "audience": audience,
        "starts_at_utc": str(record.get("starts_at_utc", "")),
        "expires_at_utc": str(record.get("expires_at_utc", "")),
        "created_at_utc": str(record.get("created_at_utc", "")),
        "updated_at_utc": str(record.get("updated_at_utc", "")),
        "active": announcement_is_active(record),
    }


def admin_create_announcement(payload):
    severity = str(payload.get("severity", "info") or "info").strip().lower()
    if severity not in ANNOUNCEMENT_SEVERITIES:
        raise ValueError("Choose a valid announcement severity.")
    title = clean_support_text(payload.get("title"), 120, "title", required=True, minimum=3)
    message = clean_support_text(payload.get("message"), 2000, "message", required=True, minimum=5)
    try:
        minimum_rank = int(payload.get("minimum_rank", 1) or 1)
    except (TypeError, ValueError) as exc:
        raise ValueError("minimum_rank must be a whole number from 1 to 7.") from exc
    if not 1 <= minimum_rank <= len(PLAN_TIERS):
        raise ValueError("minimum_rank must be a whole number from 1 to 7.")
    starts_at = parse_utc(payload.get("starts_at_utc"))
    expires_at = parse_utc(payload.get("expires_at_utc"))
    now = datetime.now(timezone.utc)
    if expires_at and expires_at <= now:
        raise ValueError("expires_at_utc must be in the future.")
    if starts_at and expires_at and starts_at >= expires_at:
        raise ValueError("expires_at_utc must be later than starts_at_utc.")
    if expires_at and expires_at > now + timedelta(days=366):
        raise ValueError("expires_at_utc cannot be more than 366 days in the future.")
    announcement_id = f"ANN-{secrets.token_hex(8).upper()}"
    now_text = format_utc(now)
    record = {
        "schema_version": 1,
        "announcement_id": announcement_id,
        "severity": severity,
        "title": title,
        "message": message,
        "minimum_rank": minimum_rank,
        "starts_at_utc": format_utc(starts_at) if starts_at else "",
        "expires_at_utc": format_utc(expires_at) if expires_at else "",
        "created_at_utc": now_text,
        "updated_at_utc": now_text,
        "active": True,
    }
    with LICENSE_STATE_LOCK:
        write_private_json(announcement_path(announcement_id), record)
    record_api_activity("announcement_publish", "ok", "announcement", announcement_id)
    return {
        "ok": True,
        "created": True,
        "announcement": announcement_view(record),
        "message": f"Announcement {announcement_id} published.",
        "server_time_utc": utc_now(),
    }


def list_admin_announcements():
    items = []
    damaged_count = 0
    for record in announcement_records():
        try:
            items.append(announcement_view(record))
        except (OSError, TypeError, ValueError):
            damaged_count += 1
    return {
        "ok": True,
        "count": len(items),
        "active_count": sum(bool(item.get("active")) for item in items),
        "damaged_count": damaged_count,
        "items": items,
        "storage": "persistent_configured" if license_state_storage_is_persistent() else "local_ephemeral",
        "server_time_utc": utc_now(),
    }


def active_announcements_for_rank(plan_rank, limit=50):
    items = []
    for record in announcement_records():
        try:
            if announcement_is_active(record) and int(record.get("minimum_rank", 1) or 1) <= plan_rank:
                items.append(announcement_view(record))
        except (OSError, TypeError, ValueError):
            continue
        if len(items) >= limit:
            break
    return items


def list_my_announcements(payload):
    verification = require_active_support_license(payload)
    plan_rank = int((verification.get("plan") or {}).get("rank", 1) or 1)
    items = active_announcements_for_rank(plan_rank)
    return {
        "ok": True,
        "count": len(items),
        "items": items,
        "plan_rank": plan_rank,
        "service_status": service_status_payload(),
        "privacy_notice": "Announcements are read-only text and never execute commands or access local files.",
        "server_time_utc": utc_now(),
    }


def admin_delete_announcement(payload):
    announcement_id = validated_announcement_id(payload.get("announcement_id"))
    with LICENSE_STATE_LOCK:
        path = announcement_path(announcement_id)
        if not path.is_file():
            raise FileNotFoundError("Announcement was not found.")
        path.unlink()
    record_api_activity("announcement_delete", "ok", "announcement", announcement_id)
    return {
        "ok": True,
        "deleted": True,
        "announcement_id": announcement_id,
        "message": f"Announcement {announcement_id} deleted.",
        "server_time_utc": utc_now(),
    }


def clean_activity_identifier(value, limit=80):
    text = str(value or "").strip()
    cleaned = "".join(
        character
        for character in text
        if character.isalnum() or character in {"-", "_", ".", ":"}
    )
    return (cleaned or "none")[:limit]


def api_activity_log_path():
    return LICENSE_STATE_DIR / "api_activity" / "activity.jsonl"


def api_activity_signing_key():
    material = ("vaultlink-api-activity-v1\0" + license_records_secret()).encode("utf-8")
    return hashlib.sha256(material).digest()


def api_activity_hash(record):
    payload = dict(record)
    payload.pop("hash", None)
    return hmac.new(api_activity_signing_key(), canonical_json_bytes(payload), hashlib.sha256).hexdigest()


def read_api_activity_records():
    path = api_activity_log_path()
    if not path.is_file():
        return [], True, "No API activity has been recorded yet."
    try:
        if path.stat().st_size > MAX_API_ACTIVITY_BYTES:
            return [], False, "The API activity log is larger than the verification limit."
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return [], False, f"The API activity log could not be read: {exc}"
    if len(lines) > MAX_API_ACTIVITY_ITEMS:
        return [], False, "The API activity log contains too many records."
    records = []
    previous_hash = "0" * 64
    expected_sequence = 1
    expected_fields = {
        "schema_version",
        "sequence",
        "time_utc",
        "event_id",
        "actor",
        "action",
        "result",
        "resource_type",
        "resource_id",
        "previous_hash",
        "hash",
    }
    for line_number, line in enumerate(lines, start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return records, False, f"API activity record {line_number} is not valid JSON."
        if not isinstance(record, dict) or set(record) != expected_fields:
            return records, False, f"API activity record {line_number} has an invalid field set."
        if record.get("schema_version") != 1 or record.get("sequence") != expected_sequence:
            return records, False, f"API activity record {line_number} has an invalid sequence."
        if record.get("previous_hash") != previous_hash:
            return records, False, f"API activity record {line_number} broke the hash chain."
        stored_hash = str(record.get("hash", ""))
        expected_hash = api_activity_hash(record)
        if len(stored_hash) != 64 or not hmac.compare_digest(stored_hash, expected_hash):
            return records, False, f"API activity record {line_number} failed HMAC verification."
        records.append(record)
        previous_hash = stored_hash
        expected_sequence += 1
    return records, True, f"Verified {len(records)} HMAC-chained API activity record(s)."


def rotate_api_activity_if_needed():
    path = api_activity_log_path()
    if not path.is_file() or path.stat().st_size < MAX_API_ACTIVITY_BYTES:
        return
    archive_dir = path.parent / "archives"
    archive_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive = archive_dir / f"activity-{stamp}-{secrets.token_hex(3)}.jsonl"
    os.replace(path, archive)
    archives = sorted(
        archive_dir.glob("activity-*.jsonl"),
        key=lambda item: item.stat().st_mtime if item.exists() else 0,
        reverse=True,
    )
    for old_archive in archives[MAX_API_ACTIVITY_ARCHIVES:]:
        try:
            old_archive.unlink()
        except OSError:
            continue


def record_api_activity(action, result="ok", resource_type="service", resource_id="none", actor="owner"):
    try:
        with LICENSE_STATE_LOCK:
            path = api_activity_log_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(path.parent, 0o700)
            except OSError:
                pass
            rotate_api_activity_if_needed()
            records, valid, _message = read_api_activity_records()
            if not valid:
                return False
            sequence = len(records) + 1
            previous_hash = str(records[-1].get("hash")) if records else "0" * 64
            record = {
                "schema_version": 1,
                "sequence": sequence,
                "time_utc": utc_now(),
                "event_id": f"EVT-{secrets.token_hex(8).upper()}",
                "actor": clean_activity_identifier(actor, 24),
                "action": clean_activity_identifier(action, 64),
                "result": clean_activity_identifier(result, 24),
                "resource_type": clean_activity_identifier(resource_type, 40),
                "resource_id": clean_activity_identifier(resource_id, 80),
                "previous_hash": previous_hash,
            }
            record["hash"] = api_activity_hash(record)
            with path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        return True
    except (OSError, TypeError, ValueError):
        return False


def list_admin_api_activity():
    records, valid, message = read_api_activity_records()
    items = list(reversed(records[-500:]))
    return {
        "ok": True,
        "count": len(records),
        "items": items,
        "integrity": {"valid": valid, "message": message, "algorithm": "HMAC-SHA-256 hash chain"},
        "privacy_notice": "Activity records exclude tokens, license keys, notes, messages, customer labels, file paths, and file contents.",
        "storage": "persistent_configured" if license_state_storage_is_persistent() else "local_ephemeral",
        "server_time_utc": utc_now(),
    }


def create_api_activity_download_link():
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=2)
    token = sign_token(
        ACTIVITY_DOWNLOAD_PREFIX,
        {
            "purpose": "admin_api_activity_download",
            "expires_at_utc": format_utc(expires_at),
            "token_id": secrets.token_hex(8),
        },
    )
    record_api_activity("activity_download_link", "ok", "api_activity", "current")
    return {
        "ok": True,
        "download_path": f"/api/v1/admin/activity/download?token={token}",
        "filename": "vaultlink-api-activity.json",
        "expires_at_utc": format_utc(expires_at),
        "server_time_utc": utc_now(),
    }


def load_api_activity_download(token):
    try:
        payload = verify_token(token, ACTIVITY_DOWNLOAD_PREFIX)
    except ValueError as exc:
        raise PermissionError(f"Activity download token failed verification: {exc}") from exc
    if payload.get("purpose") != "admin_api_activity_download":
        raise PermissionError("Activity download token has the wrong purpose.")
    expires_at = parse_utc(payload.get("expires_at_utc"))
    if not expires_at or expires_at <= datetime.now(timezone.utc):
        raise PermissionError("Activity download token expired.")
    export = list_admin_api_activity()
    return json_bytes(export), "vaultlink-api-activity.json"


def default_service_status():
    return {
        "mode": "normal",
        "message": "All VaultLink services are operating normally.",
        "updated_at_utc": "",
        "expires_at_utc": "",
        "owner_set": False,
        "active": True,
    }


def service_status_path():
    return LICENSE_STATE_DIR / "service_status.json"


def service_status_payload():
    path = service_status_path()
    if not path.is_file():
        return default_service_status()
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(record, dict) or record.get("schema_version") != 1:
            raise ValueError("Stored service status is invalid.")
        mode = str(record.get("mode", "normal"))
        if mode not in SERVICE_STATUS_MODES:
            raise ValueError("Stored service status mode is invalid.")
        expires_at = parse_utc(record.get("expires_at_utc"))
        if expires_at and expires_at <= datetime.now(timezone.utc):
            status = default_service_status()
            status["previous_status_expired"] = True
            return status
        return {
            "mode": mode,
            "message": str(record.get("message", ""))[:240],
            "updated_at_utc": str(record.get("updated_at_utc", "")),
            "expires_at_utc": str(record.get("expires_at_utc", "")),
            "owner_set": True,
            "active": True,
        }
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        status = default_service_status()
        status["record_valid"] = False
        return status


def admin_update_service_status(payload):
    mode = str(payload.get("mode", "normal") or "normal").strip().lower()
    if mode not in SERVICE_STATUS_MODES:
        raise ValueError("Choose a valid service status mode.")
    message = clean_support_text(payload.get("message"), 240, "message")
    if mode != "normal" and len(message) < 5:
        raise ValueError("message must be at least 5 characters for degraded or maintenance status.")
    if mode == "normal" and not message:
        message = default_service_status()["message"]
    expires_at = parse_utc(payload.get("expires_at_utc"))
    now = datetime.now(timezone.utc)
    if expires_at and expires_at <= now:
        raise ValueError("expires_at_utc must be in the future.")
    if expires_at and expires_at > now + timedelta(days=30):
        raise ValueError("expires_at_utc cannot be more than 30 days in the future.")
    record = {
        "schema_version": 1,
        "mode": mode,
        "message": message,
        "updated_at_utc": format_utc(now),
        "expires_at_utc": format_utc(expires_at) if expires_at and mode != "normal" else "",
    }
    with LICENSE_STATE_LOCK:
        write_private_json(service_status_path(), record)
    record_api_activity("service_status_update", "ok", "service_status", mode)
    return {
        "ok": True,
        "saved": True,
        "service_status": service_status_payload(),
        "message": f"Service status changed to {mode}.",
        "server_time_utc": utc_now(),
    }


def clean_audit_text(value, limit):
    text = "".join(
        character if ord(character) >= 32 and ord(character) != 127 else " "
        for character in str(value or "")
    ).strip()
    return " ".join(text.split())[:limit]


def clean_audit_identifier(value, limit):
    text = clean_audit_text(value, limit)
    return "".join(
        character for character in text
        if character.isalnum() or character in {"-", "_", "."}
    )[:limit]


def clean_audit_time(value):
    text = clean_audit_text(value, 40)
    try:
        parsed = parse_utc(text)
    except (TypeError, ValueError):
        return ""
    return format_utc(parsed) if parsed else ""


def clean_audit_hash(value):
    text = clean_audit_text(value, 64).lower()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        return ""
    return text


def clean_audit_event(record):
    if not isinstance(record, dict):
        raise ValueError("Every audit event must be a JSON object.")
    try:
        sequence = max(int(record.get("sequence", 0)), 0)
    except (TypeError, ValueError):
        sequence = 0
    result = clean_audit_text(record.get("result"), 16).lower()
    if result not in {"success", "failure"}:
        result = "unknown"
    event_id = clean_audit_identifier(record.get("event_id"), 64).lower()
    if len(event_id) != 16 or any(character not in "0123456789abcdef" for character in event_id):
        event_id = hashlib.sha256(event_id.encode("utf-8")).hexdigest()[:16] if event_id else ""
    action = clean_audit_identifier(record.get("action"), 80).lower()
    if action not in ALLOWED_AUDIT_ACTIONS:
        action = "unknown_action"
    return {
        "sequence": sequence,
        "time_utc": clean_audit_time(record.get("time_utc")),
        "event_id": event_id,
        "action": action,
        "result": result,
        "hash": clean_audit_hash(record.get("hash")),
        "previous_hash": clean_audit_hash(record.get("previous_hash")),
    }


def clean_audit_section(section, remaining_events):
    if not isinstance(section, dict):
        section = {}
    events = section.get("events", [])
    if not isinstance(events, list):
        raise ValueError("Audit report events must be a JSON array.")
    if len(events) > remaining_events:
        raise ValueError(f"Audit report exceeds the {MAX_AUDIT_EVENTS} event limit.")
    safe_events = [clean_audit_event(record) for record in events]
    valid = bool(section.get("valid"))
    return {
        "valid": valid,
        "event_count": len(safe_events),
        "verification": (
            "Client reported that audit verification passed."
            if valid
            else "Client reported that audit verification failed or was unavailable."
        ),
        "events": safe_events,
    }


def clean_defender_status(status):
    if not isinstance(status, dict):
        return {"available": False}
    safe = {"available": bool(status.get("available"))}
    for name in (
        "AntivirusEnabled",
        "RealTimeProtectionEnabled",
        "BehaviorMonitorEnabled",
        "IoavProtectionEnabled",
        "ProtectedNow",
    ):
        if name in status:
            safe[name] = bool(status.get(name))
    if "AntivirusSignatureLastUpdated" in status:
        safe["AntivirusSignatureLastUpdated"] = clean_audit_time(
            status.get("AntivirusSignatureLastUpdated")
        )
    for name in ("QuickScanAge", "FullScanAge"):
        if name in status:
            try:
                age = int(status.get(name))
            except (TypeError, ValueError):
                age = -1
            safe[name] = age if 0 <= age <= 100000 else "unknown"
    for name in ("LastQuickScanSource", "LastFullScanSource"):
        if name in status:
            try:
                source = int(status.get(name))
            except (TypeError, ValueError):
                source = -1
            safe[name] = source if 0 <= source <= 20 else "unknown"
    return safe


def clean_audit_report(report):
    if not isinstance(report, dict):
        raise ValueError("report must be a JSON object.")
    usb_section = clean_audit_section(report.get("usb_file_locker_audit"), MAX_AUDIT_EVENTS)
    remaining = MAX_AUDIT_EVENTS - len(usb_section["events"])
    safety_section = clean_audit_section(report.get("pc_safety_check_audit"), remaining)
    return {
        "report_type": "Privacy Safety Audit Report",
        "exported_at_utc": clean_audit_time(report.get("exported_at_utc")),
        "privacy_notice": (
            "This report contains no keystrokes, passwords, PINs, USB secrets, "
            "file contents, client names, or full file paths."
        ),
        "defender_status": clean_defender_status(report.get("defender_status")),
        "usb_file_locker_audit": usb_section,
        "pc_safety_check_audit": safety_section,
        "limitations": [
            "A clean audit report does not prove that the computer is malware-free.",
            "Use Microsoft Defender or another trusted antivirus for malware scanning.",
            "This report is not a HIPAA certification or legal-compliance determination.",
        ],
    }


def summarize_audit_breach(report):
    usb_section = report.get("usb_file_locker_audit") or {}
    safety_section = report.get("pc_safety_check_audit") or {}
    usb_events = list(usb_section.get("events") or [])
    safety_events = list(safety_section.get("events") or [])
    events = usb_events + safety_events
    signals = []

    def add_signal(level, title, count, summary):
        signals.append(
            {
                "level": level,
                "title": title,
                "count": int(count),
                "summary": summary,
            }
        )

    usb_valid = bool(usb_section.get("valid"))
    safety_valid = bool(safety_section.get("valid"))
    if not usb_valid:
        add_signal(
            "critical",
            "USB File Locker audit verification failed",
            1,
            "Treat the audit trail as damaged or tampered with until it is reviewed locally.",
        )
    if safety_events and not safety_valid:
        add_signal(
            "critical",
            "PC Safety Check audit verification failed",
            1,
            "The PC Safety Check trail contains events but did not verify.",
        )

    suspicious_actions = {"failed_access", "unlock_double_click", "login", "load_recent_key"}
    suspicious_failures = [
        event
        for event in events
        if event.get("result") == "failure" and event.get("action") in suspicious_actions
    ]
    timed_failures = []
    for event in suspicious_failures:
        try:
            moment = parse_utc(event.get("time_utc"))
        except (TypeError, ValueError):
            moment = None
        if moment is not None:
            timed_failures.append(moment)
    timed_failures.sort()
    strongest_burst = 0
    start = 0
    for end, moment in enumerate(timed_failures):
        while start < end and (moment - timed_failures[start]).total_seconds() > 10 * 60:
            start += 1
        strongest_burst = max(strongest_burst, end - start + 1)
    if strongest_burst >= 3:
        level = "high" if strongest_burst >= 5 else "warning"
        add_signal(
            level,
            "Repeated failed access attempts",
            strongest_burst,
            f"{strongest_burst} failed access or unlock attempts occurred within about 10 minutes.",
        )

    owner_removed = sum(event.get("action") == "owner_usb_removed" for event in events)
    if owner_removed:
        add_signal(
            "high",
            "Owner USB removed or replaced",
            owner_removed,
            f"{owner_removed} owner-USB removal event(s) were reported.",
        )

    key_removed = sum(event.get("action") == "usb_key_removed" for event in events)
    if key_removed:
        add_signal(
            "warning",
            "Loaded USB key disappeared",
            key_removed,
            f"{key_removed} loaded-key removal event(s) were reported.",
        )

    restores = sum(
        event.get("action") == "restore_app_data" and event.get("result") == "success"
        for event in events
    )
    if restores:
        add_signal(
            "warning",
            "App data restored from backup",
            restores,
            f"{restores} successful app-data restore event(s) were reported.",
        )

    configuration_changes = sum(event.get("action") == "configuration_change" for event in events)
    if configuration_changes >= 4:
        add_signal(
            "warning",
            "Many security setting changes",
            configuration_changes,
            f"{configuration_changes} configuration-change events were reported.",
        )

    defender = report.get("defender_status") or {}
    if defender.get("available") and "ProtectedNow" in defender and not defender.get("ProtectedNow"):
        add_signal(
            "warning",
            "Microsoft Defender not fully protected",
            1,
            "At least one reported Defender protection component was off.",
        )

    level_order = {"clear": 0, "warning": 1, "high": 2, "critical": 3}
    level = "clear"
    for signal in signals:
        if level_order[signal["level"]] > level_order[level]:
            level = signal["level"]
    headlines = {
        "clear": "No suspicious breach pattern was found in this uploaded audit snapshot.",
        "warning": "Warning-level activity needs review.",
        "high": "High-risk activity needs prompt review.",
        "critical": "Critical audit problems may indicate tampering or compromise.",
    }
    return {
        "level": level,
        "headline": headlines[level],
        "signal_count": len(signals),
        "signals": signals,
        "event_count": len(events),
        "audit_valid": usb_valid and (safety_valid or not safety_events),
        "defender_protected_now": bool(defender.get("ProtectedNow")),
    }


def require_active_audit_license(payload):
    try:
        verification = verify_license(payload)
    except ValueError as exc:
        raise PermissionError(f"License verification failed: {exc}") from exc
    if not verification.get("active"):
        message = verification.get("message") or "An active machine license is required."
        raise PermissionError(message)
    entitlements = set((verification.get("plan") or {}).get("entitlements", []))
    if "audit-log-viewer" not in entitlements:
        raise PermissionError("This license plan does not include API audit exports.")
    return verification


def audit_storage_is_persistent():
    return bool(os.getenv("AUDIT_EXPORT_DIR", "").strip())


def valid_audit_export_id(export_id):
    text = str(export_id or "").strip()
    return (
        text.startswith("AUD-")
        and 8 <= len(text) <= 64
        and all(character.isalnum() or character in {"-", "_"} for character in text)
    )


def audit_export_path(export_id):
    if not valid_audit_export_id(export_id):
        raise ValueError("Invalid audit export id.")
    return AUDIT_EXPORT_DIR / f"{export_id}.json"


def cleanup_expired_audit_exports():
    if not AUDIT_EXPORT_DIR.exists():
        return
    cutoff = datetime.now(timezone.utc).timestamp() - (AUDIT_EXPORT_RETENTION_HOURS + 1) * 3600
    for path in AUDIT_EXPORT_DIR.glob("AUD-*.json"):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
        except OSError:
            continue


def write_private_audit_export(path, payload):
    AUDIT_EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(AUDIT_EXPORT_DIR, 0o700)
    except OSError:
        pass
    body = json_bytes(payload)
    if len(body) > MAX_AUDIT_REPORT_BYTES:
        raise ValueError("The privacy-safe audit report is too large to store.")
    temp_path = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    try:
        with temp_path.open("xb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temp_path, 0o600)
        except OSError:
            pass
        os.replace(temp_path, path)
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
    return body


def create_audit_export(payload):
    verification = require_active_audit_license(payload)
    report = clean_audit_report(payload.get("report"))
    breach_summary = summarize_audit_breach(report)
    cleanup_expired_audit_exports()
    export_id = f"AUD-{secrets.token_hex(12).upper()}"
    uploaded_at = datetime.now(timezone.utc)
    expires_at = uploaded_at + timedelta(hours=AUDIT_EXPORT_RETENTION_HOURS)
    machine_id = str(payload.get("machine_id", "")).strip()
    machine_hash = hashlib.sha256(machine_id.encode("utf-8")).hexdigest()[:16]
    license_view = verification.get("license") or {}
    plan = verification.get("plan") or {}
    stored = {
        "schema_version": 2,
        "export_id": export_id,
        "uploaded_at_utc": format_utc(uploaded_at),
        "expires_at_utc": format_utc(expires_at),
        "source": {
            "license_id": clean_audit_text(license_view.get("license_id"), 80),
            "plan_id": clean_audit_text(plan.get("id"), 40),
            "machine_hash": machine_hash,
            "app_version": clean_audit_text(payload.get("app_version"), 40),
        },
        "breach_summary": breach_summary,
        "report": report,
    }
    path = audit_export_path(export_id)
    body = write_private_audit_export(path, stored)
    token = sign_token(
        AUDIT_DOWNLOAD_PREFIX,
        {
            "export_id": export_id,
            "machine_hash": machine_hash,
            "expires_at_utc": format_utc(expires_at),
        },
    )
    filename = f"vaultlink-audit-{export_id}.json"
    return {
        "ok": True,
        "created": True,
        "export_id": export_id,
        "filename": filename,
        "download_path": f"/api/v1/audit-exports/{export_id}/download",
        "download_token": token,
        "expires_at_utc": format_utc(expires_at),
        "retention_hours": AUDIT_EXPORT_RETENTION_HOURS,
        "storage": "persistent_configured" if audit_storage_is_persistent() else "local_ephemeral",
        "size_bytes": len(body),
        "event_count": (
            report["usb_file_locker_audit"]["event_count"]
            + report["pc_safety_check_audit"]["event_count"]
        ),
        "breach_summary": breach_summary,
        "server_time_utc": utc_now(),
    }


def read_stored_audit_export(export_id):
    path = audit_export_path(export_id)
    if not path.exists():
        raise FileNotFoundError("The audit export was not found or the server restarted.")
    body = path.read_bytes()
    if len(body) > MAX_AUDIT_REPORT_BYTES:
        raise ValueError("Stored audit export is too large.")
    try:
        stored = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Stored audit export is damaged.") from exc
    if not isinstance(stored, dict) or stored.get("export_id") != export_id:
        raise ValueError("Stored audit export identity did not verify.")
    return stored, body


def audit_export_metadata(stored, size_bytes):
    report = stored.get("report") or {}
    source = stored.get("source") or {}
    breach_summary = summarize_audit_breach(report)
    return {
        "export_id": clean_audit_identifier(stored.get("export_id"), 64),
        "uploaded_at_utc": clean_audit_time(stored.get("uploaded_at_utc")),
        "expires_at_utc": clean_audit_time(stored.get("expires_at_utc")),
        "source": {
            "license_id": clean_audit_text(source.get("license_id"), 80),
            "plan_id": clean_audit_text(source.get("plan_id"), 40),
            "machine_hash": clean_audit_text(source.get("machine_hash"), 16),
            "app_version": clean_audit_text(source.get("app_version"), 40),
        },
        "event_count": int(breach_summary.get("event_count", 0) or 0),
        "breach_summary": breach_summary,
        "size_bytes": int(size_bytes),
        "download_path": f"/api/v1/admin/audit-exports/{stored.get('export_id', '')}/download",
    }


def list_admin_audit_exports():
    cleanup_expired_audit_exports()
    if not AUDIT_EXPORT_DIR.exists():
        paths = []
    else:
        def modified_time(path):
            try:
                return path.stat().st_mtime
            except OSError:
                return 0

        paths = sorted(
            AUDIT_EXPORT_DIR.glob("AUD-*.json"),
            key=modified_time,
            reverse=True,
        )[:MAX_AUDIT_LIST_ITEMS]
    items = []
    damaged_count = 0
    for path in paths:
        try:
            stored, body = read_stored_audit_export(path.stem)
            items.append(audit_export_metadata(stored, len(body)))
        except (FileNotFoundError, OSError, ValueError):
            damaged_count += 1
    return {
        "ok": True,
        "items": items,
        "count": len(items),
        "damaged_count": damaged_count,
        "retention_hours": AUDIT_EXPORT_RETENTION_HOURS,
        "storage": "persistent_configured" if audit_storage_is_persistent() else "local_ephemeral",
        "privacy_notice": (
            "Stored reports contain only approved privacy-safe audit fields and anonymous machine hashes."
        ),
        "server_time_utc": utc_now(),
    }


def admin_dashboard_summary():
    license_inventory = list_admin_license_records()
    audit_inventory = list_admin_audit_exports()
    support_inventory = list_admin_support_tickets()
    announcement_inventory = list_admin_announcements()
    activity_inventory = list_admin_api_activity()
    service_status = service_status_payload()
    shop = shop_payload()
    now = datetime.now(timezone.utc)
    active_licenses = 0
    revoked_licenses = 0
    expired_licenses = 0
    active_devices = 0
    device_capacity = 0
    notes_saved = 0
    active_client_records = []
    for item in license_inventory.get("items", []):
        if item.get("status") == "revoked":
            revoked_licenses += 1
        else:
            expires_at = parse_utc(item.get("expires_at_utc"))
            if expires_at and expires_at < now:
                expired_licenses += 1
            else:
                active_licenses += 1
                device_capacity += int(item.get("max_devices", 1) or 1)
                license_id = str(item.get("license_id", ""))
                if license_id:
                    active_client_records.extend(
                        record for record in activation_records(license_id) if activation_record_is_active(record)
                    )
        active_devices += int(item.get("active_devices", 0) or 0)
        notes_saved += bool(str(item.get("license_note", "")).strip())
    breach_levels = {"clear": 0, "warning": 0, "high": 0, "critical": 0}
    for item in audit_inventory.get("items", []):
        level = str((item.get("breach_summary") or {}).get("level", "clear")).lower()
        if level in breach_levels:
            breach_levels[level] += 1
    support_statuses = {status: 0 for status in SUPPORT_TICKET_STATUSES}
    for item in support_inventory.get("items", []):
        status = str(item.get("status", "open"))
        if status in support_statuses:
            support_statuses[status] += 1
    try:
        update_manifest, _package = load_windows_update_release()
        desktop_release = str(update_manifest.get("version", ""))
    except (FileNotFoundError, OSError, ValueError):
        desktop_release = ""
    version_counts = {}
    stale_24h = 0
    unknown_version_devices = 0
    for record in active_client_records:
        version = str(record.get("app_version", "")).strip()[:40]
        if version:
            version_counts[version] = version_counts.get(version, 0) + 1
        else:
            unknown_version_devices += 1
        last_seen = (
            parse_utc(record.get("last_seen_at_utc"))
            or parse_utc(record.get("updated_at_utc"))
            or parse_utc(record.get("activated_at_utc"))
        )
        if last_seen is None or (now - last_seen).total_seconds() > 24 * 60 * 60:
            stale_24h += 1
    current_release_devices = int(version_counts.get(desktop_release, 0)) if desktop_release else 0
    version_rows = [
        {
            "version": version,
            "devices": count,
            "current_release": bool(desktop_release and version == desktop_release),
        }
        for version, count in sorted(version_counts.items(), key=lambda pair: (-pair[1], pair[0]))
    ]
    return {
        "ok": True,
        "licenses": {
            "total": int(license_inventory.get("count", 0) or 0),
            "active": active_licenses,
            "revoked": revoked_licenses,
            "expired": expired_licenses,
            "notes_saved": notes_saved,
        },
        "devices": {
            "active": active_devices,
            "capacity": device_capacity,
        },
        "client_health": {
            "active_devices": len(active_client_records),
            "current_release": desktop_release,
            "current_release_devices": current_release_devices,
            "other_version_devices": max(0, len(active_client_records) - current_release_devices - unknown_version_devices),
            "unknown_version_devices": unknown_version_devices,
            "stale_24h": stale_24h,
            "version_counts": version_rows,
            "privacy": "Only anonymous device counts, reported app versions, and coarse sync freshness are shown.",
        },
        "audit_exports": {
            "total": int(audit_inventory.get("count", 0) or 0),
            "breach_levels": breach_levels,
        },
        "support_tickets": {
            "total": int(support_inventory.get("count", 0) or 0),
            "statuses": support_statuses,
            "needs_action": support_statuses.get("open", 0) + support_statuses.get("acknowledged", 0),
        },
        "announcements": {
            "total": int(announcement_inventory.get("count", 0) or 0),
            "active": int(announcement_inventory.get("active_count", 0) or 0),
            "damaged": int(announcement_inventory.get("damaged_count", 0) or 0),
        },
        "api_activity": {
            "total": int(activity_inventory.get("count", 0) or 0),
            "integrity_valid": bool((activity_inventory.get("integrity") or {}).get("valid")),
            "integrity_message": str((activity_inventory.get("integrity") or {}).get("message", "")),
        },
        "service_status": service_status,
        "shop": {
            "configured": int(shop.get("configured_count", 0) or 0),
            "total": int(shop.get("count", 0) or 0),
            "ready": bool(shop.get("ready")),
            "card_data_collected_by_vaultlink": False,
        },
        "storage": {
            "licenses": license_inventory.get("storage", "local_ephemeral"),
            "audit_exports": audit_inventory.get("storage", "local_ephemeral"),
            "support_tickets": support_inventory.get("storage", "local_ephemeral"),
            "announcements": announcement_inventory.get("storage", "local_ephemeral"),
            "api_activity": activity_inventory.get("storage", "local_ephemeral"),
        },
        "release": {
            "api_version": API_VERSION,
            "desktop_version": desktop_release,
            "license_sync_seconds": LICENSE_SYNC_INTERVAL_SECONDS,
        },
        "server_time_utc": utc_now(),
    }


def admin_owner_insights():
    """Build a fixed 50-point, aggregate-only owner operations report."""
    dashboard = admin_dashboard_summary()
    inventory = list_admin_license_records()
    records = list(inventory.get("items", []))
    now = datetime.now(timezone.utc)
    active_records = []
    limited_count = 0
    expiring_7d = 0
    expiring_30d = 0
    non_expiring = 0
    at_capacity = 0
    without_devices = 0
    plan_counts = {plan["id"]: 0 for plan in PLAN_TIERS}

    for record in records:
        plan_id = canonical_plan_id(record.get("plan_id", ""))
        if plan_id in plan_counts:
            plan_counts[plan_id] += 1
        expires_at = parse_utc(record.get("expires_at_utc"))
        is_active = record.get("status") != "revoked" and not (expires_at and expires_at < now)
        if not is_active:
            continue
        active_records.append(record)
        if record.get("limited"):
            limited_count += 1
        active_devices = int(record.get("active_devices", 0) or 0)
        max_devices = max(1, int(record.get("max_devices", 1) or 1))
        if active_devices >= max_devices:
            at_capacity += 1
        if active_devices == 0:
            without_devices += 1
        if expires_at is None:
            non_expiring += 1
        else:
            seconds_left = (expires_at - now).total_seconds()
            if 0 <= seconds_left <= 7 * 86400:
                expiring_7d += 1
            if 0 <= seconds_left <= 30 * 86400:
                expiring_30d += 1

    licenses = dashboard["licenses"]
    devices = dashboard["devices"]
    clients = dashboard["client_health"]
    support = dashboard["support_tickets"]
    announcements = dashboard["announcements"]
    audits = dashboard["audit_exports"]
    activity = dashboard["api_activity"]
    release = dashboard["release"]
    storage = dashboard["storage"]
    shop = dashboard["shop"]
    support_statuses = support.get("statuses", {})
    breach_levels = audits.get("breach_levels", {})

    def percent(part, total):
        return round((float(part) / float(total)) * 100) if total else 0

    active_devices = int(devices.get("active", 0) or 0)
    device_capacity = int(devices.get("capacity", 0) or 0)
    active_clients = int(clients.get("active_devices", 0) or 0)
    current_clients = int(clients.get("current_release_devices", 0) or 0)
    support_total = int(support.get("total", 0) or 0)
    support_finished = int(support_statuses.get("resolved", 0) or 0) + int(
        support_statuses.get("closed", 0) or 0
    )
    persistent_stores = sum(value == "persistent_configured" for value in storage.values())
    insights = []

    def add(identifier, category, title, value, state, detail, unit=""):
        insights.append(
            {
                "id": identifier,
                "category": category,
                "title": title,
                "value": value,
                "unit": unit,
                "state": state,
                "detail": detail,
            }
        )

    add("licenses-total", "Licensing", "Total licenses", licenses.get("total", 0), "info", "Every stored license record.")
    add("licenses-active", "Licensing", "Active licenses", licenses.get("active", 0), "good", "Usable licenses that are not expired or blocked.")
    add("licenses-limited", "Licensing", "Limited licenses", limited_count, "warn" if limited_count else "good", "Temporary premium-access limits; unlock and recovery stay available.")
    add("licenses-revoked", "Licensing", "Blocked licenses", licenses.get("revoked", 0), "warn" if licenses.get("revoked") else "info", "Licenses blocked from licensed premium features.")
    add("licenses-expired", "Licensing", "Expired licenses", licenses.get("expired", 0), "warn" if licenses.get("expired") else "good", "Licenses past their configured expiration time.")
    add("licenses-notes", "Licensing", "Licenses with notes", licenses.get("notes_saved", 0), "info", "Private owner notes saved in encrypted records.")
    add("licenses-note-coverage", "Licensing", "Note coverage", percent(licenses.get("notes_saved", 0), licenses.get("total", 0)), "info", "Share of license records with an owner note.", "%")
    add("devices-active", "Devices", "Active device seats", active_devices, "info", "Anonymous active machine-bound seats.")
    add("devices-capacity", "Devices", "Device capacity", device_capacity, "info", "Total seats available across active licenses.")
    add("devices-available", "Devices", "Seats available", max(0, device_capacity - active_devices), "good", "Unused seats across active licenses.")
    add("devices-utilization", "Devices", "Seat utilization", percent(active_devices, device_capacity), "warn" if device_capacity and active_devices >= device_capacity else "good", "Percent of available device seats currently active.", "%")
    add("licenses-at-capacity", "Devices", "Licenses at capacity", at_capacity, "warn" if at_capacity else "good", "Active licenses with every device seat in use.")
    add("licenses-without-devices", "Devices", "Licenses without devices", without_devices, "info", "Active licenses that have not activated a device.")
    add("licenses-expiring-7d", "Renewals", "Expiring in 7 days", expiring_7d, "warn" if expiring_7d else "good", "Active licenses expiring within seven days.")
    add("licenses-expiring-30d", "Renewals", "Expiring in 30 days", expiring_30d, "warn" if expiring_30d else "good", "Active licenses expiring within thirty days.")
    add("licenses-no-expiry", "Renewals", "No expiration set", non_expiring, "info", "Active licenses without an expiration date.")

    for plan in sorted(PLAN_TIERS, key=lambda item: item["rank"]):
        add(
            f"rank-{plan['rank']}-licenses",
            "Ranks",
            f"Rank {plan['rank']} licenses",
            plan_counts.get(plan["id"], 0),
            "info",
            f"Stored licenses assigned to {plan['name']}.",
        )

    add("clients-active", "Releases", "Reporting clients", active_clients, "info", "Anonymous active devices included in release health.")
    add("clients-current", "Releases", "Current-release clients", current_clients, "good", "Devices reporting the published desktop release.")
    add("clients-adoption", "Releases", "Release adoption", percent(current_clients, active_clients), "good" if not active_clients or current_clients == active_clients else "warn", "Share of reporting devices on the current release.", "%")
    add("clients-other", "Releases", "Other-version clients", clients.get("other_version_devices", 0), "warn" if clients.get("other_version_devices") else "good", "Devices reporting a different known app version.")
    add("clients-unknown", "Releases", "Unknown-version clients", clients.get("unknown_version_devices", 0), "warn" if clients.get("unknown_version_devices") else "good", "Devices that did not report an app version.")
    add("clients-stale", "Releases", "Stale clients, 24h", clients.get("stale_24h", 0), "warn" if clients.get("stale_24h") else "good", "Active devices not seen during the last 24 hours.")
    add("clients-version-count", "Releases", "Version variants", len(clients.get("version_counts", [])), "info", "Number of distinct app versions reported.")
    add("release-desktop", "Releases", "Desktop release", release.get("desktop_version") or "none", "good" if release.get("desktop_version") else "warn", "Published signed Windows package version.")
    add("release-api", "Releases", "API version", release.get("api_version") or API_VERSION, "info", "Currently running API release.")
    add("release-sync", "Releases", "Client sync interval", release.get("license_sync_seconds", LICENSE_SYNC_INTERVAL_SECONDS), "info", "Recommended licensed client heartbeat interval.", "seconds")
    add("support-total", "Support", "Support tickets", support_total, "info", "Encrypted customer bug reports visible to the owner.")
    add("support-open", "Support", "Open tickets", support_statuses.get("open", 0), "warn" if support_statuses.get("open") else "good", "New reports waiting for review.")
    add("support-acknowledged", "Support", "Acknowledged tickets", support_statuses.get("acknowledged", 0), "info", "Reports confirmed by the owner.")
    add("support-resolved", "Support", "Resolved tickets", support_statuses.get("resolved", 0), "good", "Reports marked resolved.")
    add("support-closed", "Support", "Closed tickets", support_statuses.get("closed", 0), "good", "Reports marked closed.")
    add("support-needs-action", "Support", "Tickets needing action", support.get("needs_action", 0), "warn" if support.get("needs_action") else "good", "Open or acknowledged reports requiring owner attention.")
    add("support-completion", "Support", "Support completion", percent(support_finished, support_total), "good" if not support_total or support_finished == support_total else "info", "Share of tickets resolved or closed.", "%")
    add("announcements-total", "Messaging", "Published messages", announcements.get("total", 0), "info", "All stored owner announcements.")
    add("announcements-active", "Messaging", "Active messages", announcements.get("active", 0), "info", "Messages currently visible to eligible licensed customers.")
    add("announcements-damaged", "Messaging", "Damaged messages", announcements.get("damaged", 0), "bad" if announcements.get("damaged") else "good", "Announcement records that failed validation.")
    add("audits-total", "Security", "Audit exports", audits.get("total", 0), "info", "Privacy-safe customer audit reports stored by the API.")
    high_critical = int(breach_levels.get("high", 0) or 0) + int(breach_levels.get("critical", 0) or 0)
    add("audits-high-critical", "Security", "High and critical audits", high_critical, "bad" if high_critical else "good", "Reports whose server summary needs urgent review.")
    add("activity-total", "Security", "API activity events", activity.get("total", 0), "info", "Aggregate count of tamper-evident owner API events.")
    add("activity-integrity", "Security", "Activity chain", "valid" if activity.get("integrity_valid") else "check", "good" if activity.get("integrity_valid") else "bad", activity.get("integrity_message") or "Hash-chain verification status.")
    service_mode = str((dashboard.get("service_status") or {}).get("mode", "unknown"))
    add("service-mode", "Operations", "Service mode", service_mode, "good" if service_mode == "normal" else "warn", "Public customer-facing service status.")
    add("shop-configured", "Operations", "Shop checkouts configured", shop.get("configured", 0), "good" if shop.get("ready") else "warn", f"Validated provider-hosted checkout links out of {shop.get('total', 0)}.")
    add("storage-persistent", "Operations", "Persistent stores", persistent_stores, "good" if persistent_stores == len(storage) else "warn", f"Restart-safe stores out of {len(storage)} configured data areas.")

    if len(insights) != 50:
        raise RuntimeError(f"Owner insight contract expected 50 items, built {len(insights)}.")
    categories = sorted({item["category"] for item in insights})
    return {
        "ok": True,
        "count": len(insights),
        "items": insights,
        "categories": categories,
        "updated_at_utc": utc_now(),
        "privacy_notice": (
            "This report contains aggregate operational counts only. It excludes license keys, customer labels, "
            "emails, private notes, machine identifiers, file paths, PINs, USB secrets, and file contents."
        ),
    }


def load_admin_audit_export_download(export_id):
    cleanup_expired_audit_exports()
    _stored, body = read_stored_audit_export(export_id)
    return body, f"vaultlink-audit-{export_id}.json"


def create_admin_audit_download_link(payload):
    export_id = clean_audit_identifier(payload.get("export_id"), 64)
    if not valid_audit_export_id(export_id):
        raise ValueError("Choose a valid audit export id.")
    stored, _body = read_stored_audit_export(export_id)
    machine_hash = str((stored.get("source") or {}).get("machine_hash", ""))
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=2)
    token = sign_token(
        AUDIT_DOWNLOAD_PREFIX,
        {
            "export_id": export_id,
            "machine_hash": machine_hash,
            "expires_at_utc": format_utc(expires_at),
            "scope": "owner_audit_download",
        },
    )
    record_api_activity("audit_download_link", "ok", "audit_export", export_id)
    return {
        "ok": True,
        "export_id": export_id,
        "filename": f"vaultlink-audit-{export_id}.json",
        "download_path": f"/api/v1/audit-exports/{export_id}/download?token={token}",
        "expires_at_utc": format_utc(expires_at),
        "message": "Created a two-minute report-only download link.",
        "server_time_utc": utc_now(),
    }


def load_audit_export_download(export_id, token):
    if not token:
        raise PermissionError("The signed audit download token is required.")
    try:
        token_payload = verify_token(token, AUDIT_DOWNLOAD_PREFIX)
    except ValueError as exc:
        raise PermissionError(f"Audit download token did not verify: {exc}") from exc
    if token_payload.get("export_id") != export_id:
        raise PermissionError("Audit download token does not match this export.")
    expires_at = parse_utc(token_payload.get("expires_at_utc"))
    if not expires_at or expires_at <= datetime.now(timezone.utc):
        try:
            audit_export_path(export_id).unlink(missing_ok=True)
        except OSError:
            pass
        raise PermissionError("This audit download link has expired.")
    stored, body = read_stored_audit_export(export_id)
    stored_machine_hash = ((stored.get("source") or {}).get("machine_hash", ""))
    if not hmac.compare_digest(
        str(stored_machine_hash),
        str(token_payload.get("machine_hash", "")),
    ):
        raise PermissionError("Audit download token does not match the stored machine receipt.")
    return body, f"vaultlink-audit-{export_id}.json"


class ApiHandler(BaseHTTPRequestHandler):
    def send_json(self, payload, status=HTTPStatus.OK):
        body = json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html, status=HTTPStatus.OK):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def send_download(self, body, filename, content_type="application/json; charset=utf-8"):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self, max_bytes):
        if self.headers.get("Transfer-Encoding", "").strip():
            raise ValueError("Chunked request bodies are not supported.")
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError as exc:
            raise ValueError("Content-Length must be a whole number.") from exc
        if length < 0:
            raise ValueError("Content-Length cannot be negative.")
        if length > max_bytes:
            if length <= MAX_REJECTED_BODY_DRAIN_BYTES:
                self.rfile.read(length)
            else:
                self.close_connection = True
            raise RequestTooLarge(f"Request body exceeds the {max_bytes}-byte limit for this route.")
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if length and content_type != "application/json":
            raise UnsupportedMediaType("Content-Type must be application/json.")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return require_json_object(json.loads(raw.decode("utf-8")))
        except UnicodeDecodeError as exc:
            raise ValueError("Body must be valid UTF-8 JSON.") from exc
        except json.JSONDecodeError as exc:
            raise ValueError("Body must be valid JSON.") from exc

    def require_admin_token(self):
        configured = os.getenv("LICENSE_ADMIN_TOKEN", "").strip()
        if not configured:
            raise PermissionError("LICENSE_ADMIN_TOKEN is not configured on this server.")
        provided = self.headers.get("X-License-Admin-Token", "").strip()
        if not provided or not hmac.compare_digest(provided, configured):
            raise PermissionError("Admin token was missing or incorrect.")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/":
            self.send_html(homepage_html())
            return
        if path == "/shop":
            self.send_html(shop_html())
            return
        if path == "/customer":
            self.send_html(customer_license_center_html())
            return
        if path == "/status":
            self.send_html(customer_status_html())
            return
        if path == "/terms":
            self.send_html(legal_document_html("terms"))
            return
        if path == "/privacy":
            self.send_html(legal_document_html("privacy"))
            return
        if path == "/docs":
            self.send_json(docs_payload())
            return
        if path == "/owner":
            self.send_html(owner_portal_html())
            return
        if path == "/owner/insights":
            self.send_html(owner_insights_html())
            return
        if path == "/health":
            self.send_json(
                {
                    "ok": True,
                    "service": API_NAME,
                    "version": API_VERSION,
                    "time_utc": utc_now(),
                    "license_admin_configured": admin_token_configured(),
                    "using_default_signing_secret": using_default_signing_secret(),
                    "license_state_storage": (
                        "persistent_configured" if license_state_storage_is_persistent() else "local_ephemeral"
                    ),
                    "license_private_fields_encrypted": True,
                    "device_seat_enforcement": True,
                    "automatic_license_sync": True,
                    "license_sync_interval_seconds": LICENSE_SYNC_INTERVAL_SECONDS,
                    "audit_exports_enabled": True,
                    "audit_export_storage": (
                        "persistent_configured" if audit_storage_is_persistent() else "local_ephemeral"
                    ),
                    "audit_export_retention_hours": AUDIT_EXPORT_RETENTION_HOURS,
                    "support_inbox_enabled": True,
                    "support_ticket_storage": (
                        "persistent_configured" if license_state_storage_is_persistent() else "local_ephemeral"
                    ),
                    "support_ticket_private_fields_encrypted": True,
                    "owner_announcements_enabled": True,
                    "owner_announcement_storage": (
                        "persistent_configured" if license_state_storage_is_persistent() else "local_ephemeral"
                    ),
                    "service_status": service_status_payload(),
                    "api_activity_enabled": True,
                    "api_activity_integrity": list_admin_api_activity()["integrity"],
                    "shop_enabled": True,
                    "customer_license_center_enabled": True,
                    "anonymous_plan_advisor_enabled": True,
                    "shop_checkout_links_configured": shop_payload()["configured_count"],
                    "shop_card_data_collected_by_vaultlink": False,
                    "windows_update_published": UPDATE_MANIFEST_PATH.exists(),
                }
            )
            return
        if path == "/api/v1/product":
            self.send_json(product_payload())
            return
        if path == "/api/v1/features":
            self.send_json({"items": FEATURES, "count": len(FEATURES)})
            return
        if path == "/api/v1/companions":
            self.send_json({"items": COMPANION_APPS, "count": len(COMPANION_APPS)})
            return
        if path == "/api/v1/plans":
            self.send_json({"items": public_plans(), "count": len(PLAN_TIERS)})
            return
        if path == "/api/v1/ranks":
            self.send_json({"items": public_plans(), "count": len(PLAN_TIERS)})
            return
        if path == "/api/v1/shop":
            self.send_json(shop_payload())
            return
        if path == "/api/v1/legal":
            self.send_json(legal_payload())
            return
        if path == "/api/v1/service-status":
            self.send_json({"ok": True, "service_status": service_status_payload(), "server_time_utc": utc_now()})
            return
        if path == "/api/v1/security":
            self.send_json(
                {
                    "license_mode": "signed_tokens_with_revocation_ledger",
                    "notes": SECURITY_NOTES,
                    "remote_actions_allowed": [
                        "admin license issue",
                        "license activate",
                        "license verify",
                        "automatic license heartbeat and revocation sync",
                        "customer device deactivation",
                        "admin license revoke, restore, note, device reset, individual device removal, inventory, and dashboard",
                        "license-authenticated privacy-safe audit export upload",
                        "signed short-lived audit export download",
                        "admin-protected audit export list and download",
                        "licensed encrypted bug reports and customer-visible owner replies",
                        "admin support-ticket status, reply, private note, and deletion actions",
                        "admin rank-targeted read-only owner announcements",
                        "admin informational service status and tamper-evident API activity export",
                        "public shop catalog and validated provider-hosted checkout links",
                        "anonymous plan recommendations and rank comparisons",
                        "read-only customer license preview without device activation",
                        "privacy-safe customer upgrade options and added-entitlement comparisons",
                        "license-gated rank-exclusive customer checklists and tool packs",
                        "privacy-safe customer checkup for license, seat, service, update, and rank-tool status",
                    ],
                    "banned_remote_actions": [
                        "remote unlock",
                        "remote key creation",
                        "remote PIN capture",
                        "remote file reads",
                        "remote vault secret retrieval",
                        "automatic file or local-log attachment to support tickets",
                        "card-number collection or payment-secret storage",
                    ],
                    "license_limitations": [
                        "Device seats are enforced through anonymous machine hashes; no hardware names are stored in the activation ledger.",
                        "Configure LICENSE_STATE_DIR on a Railway Volume so revocations, activations, keys, and notes survive restarts.",
                        "LICENSE_RECORDS_SECRET should be configured separately and retained for encrypted-record recovery.",
                        "Support ticket text is encrypted with a key derived separately from LICENSE_RECORDS_SECRET.",
                    ],
                    "admin_authentication": "X-License-Admin-Token header only; never accepted in a JSON body.",
                    "audit_export_controls": [
                        "Only approved privacy-safe fields are retained.",
                        "Upload requires an active machine-bound license with Audit Log Viewer access.",
                        "Client downloads require a signed expiring bearer link.",
                        "Owner listing and downloads require the admin token in a request header.",
                        "Each stored report includes a server-calculated breach summary.",
                        "Configure AUDIT_EXPORT_DIR on a Railway Volume for restart-safe retention.",
                    ],
                    "support_ticket_controls": [
                        "Submission requires an active machine-bound license.",
                        "No files, local logs, secrets, raw machine ids, or PC names are attached automatically.",
                        "A per-device daily submission limit reduces spam.",
                        "Only the admin token can read all tickets, add private notes, reply, change status, or delete tickets.",
                    ],
                    "announcement_controls": [
                        "Only the admin token can publish or delete announcements.",
                        "Customers need an active machine-bound license and receive only notices allowed for their rank.",
                        "Announcements are plain read-only text; they cannot run commands, open files, or change settings.",
                        "Scheduled and expired notices are filtered by the server.",
                    ],
                    "owner_operations_controls": [
                        "Service status is informational only and cannot lock, unlock, execute, or modify customer PCs.",
                        "The API activity feed uses an HMAC-SHA-256 hash chain and excludes sensitive payloads.",
                        "Activity downloads use a two-minute scoped token instead of placing the admin token in a URL.",
                    ],
                    "shop_controls": [
                        "VaultLink never collects card numbers; checkout occurs on a separately hosted payment page.",
                        "Only HTTPS links on the configured checkout-host allowlist are published.",
                        "Missing or invalid links leave that tier visibly unavailable.",
                        "License delivery remains an owner action after independent payment confirmation.",
                        "Plan advice and comparisons do not request or store customer or payment information.",
                    ],
                    "customer_center_controls": [
                        "The license key is sent only in a JSON request body and is never placed in a URL.",
                        "Preview responses exclude customer labels, email addresses, private notes, machine identifiers, receipts, paths, PINs, and file contents.",
                        "Preview is read-only and does not activate or consume a device seat.",
                        "Rank-exclusive premium tools require an active signed license; limited, revoked, and expired licenses retain local unlock and recovery only.",
                        "Customer checkups are informational and cannot inspect, execute, lock, unlock, or modify a customer PC.",
                    ],
                }
            )
            return
        if path == "/api/v1/deploy":
            self.send_json(
                {
                    "provider": "Railway",
                    "root_directory": "/",
                    "start_command": "python main.py",
                    "port_env": os.getenv("PORT", "8000"),
                    "recommended_env": [
                        "LICENSE_SIGNING_SECRET",
                        "LICENSE_ADMIN_TOKEN",
                        "LICENSE_STATE_DIR",
                        "LICENSE_RECORDS_SECRET",
                        "AUDIT_EXPORT_DIR",
                        "AUDIT_EXPORT_RETENTION_HOURS",
                        "SHOP_CHECKOUT_STARTER_URL",
                        "SHOP_CHECKOUT_HOME_URL",
                        "SHOP_CHECKOUT_PERSONAL_PLUS_URL",
                        "SHOP_CHECKOUT_FAMILY_SAFETY_URL",
                        "SHOP_CHECKOUT_SMALL_OFFICE_URL",
                        "SHOP_CHECKOUT_FAMILY_OFFICE_URL",
                        "SHOP_CHECKOUT_PRO_BASELINE_URL",
                        "SHOP_CHECKOUT_ALLOWED_HOSTS",
                    ],
                }
            )
            return
        if path == "/api/v1/updates/windows":
            try:
                self.send_json(windows_update_payload())
            except (FileNotFoundError, OSError, ValueError) as exc:
                self.send_json(
                    {"ok": False, "error": "update_unavailable", "message": str(exc)},
                    status=HTTPStatus.SERVICE_UNAVAILABLE,
                )
            return
        if path == "/api/v1/updates/windows/download":
            try:
                manifest, package_path = load_windows_update_release()
                self.send_download(
                    package_path.read_bytes(),
                    manifest["package_filename"],
                    content_type="application/zip",
                )
            except (FileNotFoundError, OSError, ValueError) as exc:
                self.send_json(
                    {"ok": False, "error": "update_unavailable", "message": str(exc)},
                    status=HTTPStatus.SERVICE_UNAVAILABLE,
                )
            return
        if path == "/api/v1/admin/activity/download":
            token = (parse_qs(parsed.query).get("token") or [""])[0]
            try:
                body, filename = load_api_activity_download(token)
                self.send_download(body, filename)
            except PermissionError as exc:
                self.send_json(
                    {"ok": False, "error": "forbidden", "message": str(exc)},
                    status=HTTPStatus.FORBIDDEN,
                )
            except Exception:
                self.send_json(
                    {"ok": False, "error": "server_error", "message": "Internal server error."},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            return
        parts = path.strip("/").split("/")
        if path == "/api/v1/admin/audit-exports":
            try:
                self.require_admin_token()
                self.send_json(list_admin_audit_exports())
            except PermissionError as exc:
                self.send_json(
                    {"ok": False, "error": "forbidden", "message": str(exc)},
                    status=HTTPStatus.FORBIDDEN,
                )
            except Exception:
                self.send_json(
                    {"ok": False, "error": "server_error", "message": "Internal server error."},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            return
        if path == "/api/v1/admin/licenses":
            try:
                self.require_admin_token()
                self.send_json(list_admin_license_records())
            except PermissionError as exc:
                self.send_json(
                    {"ok": False, "error": "forbidden", "message": str(exc)},
                    status=HTTPStatus.FORBIDDEN,
                )
            except Exception:
                self.send_json(
                    {"ok": False, "error": "server_error", "message": "Internal server error."},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            return
        if path == "/api/v1/admin/support-tickets":
            try:
                self.require_admin_token()
                self.send_json(list_admin_support_tickets())
            except PermissionError as exc:
                self.send_json(
                    {"ok": False, "error": "forbidden", "message": str(exc)},
                    status=HTTPStatus.FORBIDDEN,
                )
            except Exception:
                self.send_json(
                    {"ok": False, "error": "server_error", "message": "Internal server error."},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            return
        if path == "/api/v1/admin/announcements":
            try:
                self.require_admin_token()
                self.send_json(list_admin_announcements())
            except PermissionError as exc:
                self.send_json(
                    {"ok": False, "error": "forbidden", "message": str(exc)},
                    status=HTTPStatus.FORBIDDEN,
                )
            except Exception:
                self.send_json(
                    {"ok": False, "error": "server_error", "message": "Internal server error."},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            return
        if path == "/api/v1/admin/activity":
            try:
                self.require_admin_token()
                self.send_json(list_admin_api_activity())
            except PermissionError as exc:
                self.send_json(
                    {"ok": False, "error": "forbidden", "message": str(exc)},
                    status=HTTPStatus.FORBIDDEN,
                )
            except Exception:
                self.send_json(
                    {"ok": False, "error": "server_error", "message": "Internal server error."},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            return
        if path == "/api/v1/admin/dashboard":
            try:
                self.require_admin_token()
                self.send_json(admin_dashboard_summary())
            except PermissionError as exc:
                self.send_json(
                    {"ok": False, "error": "forbidden", "message": str(exc)},
                    status=HTTPStatus.FORBIDDEN,
                )
            except Exception:
                self.send_json(
                    {"ok": False, "error": "server_error", "message": "Internal server error."},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            return
        if path == "/api/v1/admin/insights":
            try:
                self.require_admin_token()
                self.send_json(admin_owner_insights())
            except PermissionError as exc:
                self.send_json(
                    {"ok": False, "error": "forbidden", "message": str(exc)},
                    status=HTTPStatus.FORBIDDEN,
                )
            except Exception:
                self.send_json(
                    {"ok": False, "error": "server_error", "message": "Internal server error."},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            return
        if (
            len(parts) == 6
            and parts[:4] == ["api", "v1", "admin", "licenses"]
            and parts[5] == "devices"
        ):
            try:
                self.require_admin_token()
                self.send_json(admin_license_devices(parts[4]))
            except PermissionError as exc:
                self.send_json(
                    {"ok": False, "error": "forbidden", "message": str(exc)},
                    status=HTTPStatus.FORBIDDEN,
                )
            except FileNotFoundError as exc:
                self.send_json(
                    {"ok": False, "error": "not_found", "message": str(exc)},
                    status=HTTPStatus.NOT_FOUND,
                )
            except ValueError as exc:
                self.send_json(
                    {"ok": False, "error": "bad_request", "message": str(exc)},
                    status=HTTPStatus.BAD_REQUEST,
                )
            except Exception:
                self.send_json(
                    {"ok": False, "error": "server_error", "message": "Internal server error."},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            return
        if (
            len(parts) == 6
            and parts[:4] == ["api", "v1", "admin", "audit-exports"]
            and parts[5] == "download"
        ):
            try:
                self.require_admin_token()
                body, filename = load_admin_audit_export_download(parts[4])
                self.send_download(body, filename)
            except PermissionError as exc:
                self.send_json(
                    {"ok": False, "error": "forbidden", "message": str(exc)},
                    status=HTTPStatus.FORBIDDEN,
                )
            except FileNotFoundError as exc:
                self.send_json(
                    {"ok": False, "error": "not_found", "message": str(exc)},
                    status=HTTPStatus.NOT_FOUND,
                )
            except ValueError as exc:
                self.send_json(
                    {"ok": False, "error": "bad_request", "message": str(exc)},
                    status=HTTPStatus.BAD_REQUEST,
                )
            except Exception:
                self.send_json(
                    {"ok": False, "error": "server_error", "message": "Internal server error."},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            return
        if (
            len(parts) == 5
            and parts[:3] == ["api", "v1", "audit-exports"]
            and parts[4] == "download"
        ):
            try:
                authorization = self.headers.get("Authorization", "").strip()
                token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
                if not token:
                    token = self.headers.get("X-Audit-Download-Token", "").strip()
                if not token and parsed.query:
                    query = parse_qs(parsed.query, keep_blank_values=False, max_num_fields=4)
                    token = str((query.get("token") or [""])[0]).strip()
                body, filename = load_audit_export_download(parts[3], token)
                self.send_download(body, filename)
            except PermissionError as exc:
                self.send_json(
                    {"ok": False, "error": "forbidden", "message": str(exc)},
                    status=HTTPStatus.FORBIDDEN,
                )
            except FileNotFoundError as exc:
                self.send_json(
                    {"ok": False, "error": "not_found", "message": str(exc)},
                    status=HTTPStatus.NOT_FOUND,
                )
            except ValueError as exc:
                self.send_json(
                    {"ok": False, "error": "bad_request", "message": str(exc)},
                    status=HTTPStatus.BAD_REQUEST,
                )
            except Exception:
                self.send_json(
                    {"ok": False, "error": "server_error", "message": "Internal server error."},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            return

        self.send_json(
            {
                "error": "not_found",
                "message": "Route not found.",
                "docs": "/docs",
            },
            status=HTTPStatus.NOT_FOUND,
        )

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        route_limits = {
            "/api/v1/licenses/issue": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/activate": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/verify": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/preview": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/upgrade-options": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/rank-tools": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/customer-checkup": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/sync": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/deactivate": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/revoke": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/restore": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/limit": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/unlimit": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/note": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/reset-devices": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/remove-device": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/support-tickets": MAX_SUPPORT_JSON_BODY_BYTES,
            "/api/v1/support-tickets/mine": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/admin/support-tickets/action": MAX_SUPPORT_JSON_BODY_BYTES,
            "/api/v1/admin/support-tickets/delete": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/announcements/mine": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/admin/announcements/create": MAX_SUPPORT_JSON_BODY_BYTES,
            "/api/v1/admin/announcements/delete": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/admin/service-status": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/admin/activity/download-link": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/admin/audit-exports/download-link": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/audit-exports": MAX_AUDIT_JSON_BODY_BYTES,
            "/api/v1/shop/recommend": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/shop/compare": MAX_LICENSE_JSON_BODY_BYTES,
        }
        if path not in route_limits:
            self.send_json(
                {
                    "error": "not_found",
                    "message": "Route not found.",
                    "docs": "/docs",
                },
                status=HTTPStatus.NOT_FOUND,
            )
            return
        try:
            payload = self.read_json(route_limits[path])
            if path == "/api/v1/licenses/issue":
                self.require_admin_token()
                self.send_json(issue_license(payload), status=HTTPStatus.CREATED)
                return
            if path == "/api/v1/licenses/activate":
                self.send_json(activate_license(payload))
                return
            if path == "/api/v1/licenses/verify":
                self.send_json(verify_license(payload))
                return
            if path == "/api/v1/licenses/preview":
                self.send_json(preview_license(payload))
                return
            if path == "/api/v1/licenses/upgrade-options":
                self.send_json(license_upgrade_options(payload))
                return
            if path == "/api/v1/licenses/rank-tools":
                self.send_json(customer_rank_tools(payload))
                return
            if path == "/api/v1/licenses/customer-checkup":
                self.send_json(customer_checkup(payload))
                return
            if path == "/api/v1/licenses/sync":
                self.send_json(sync_license(payload))
                return
            if path == "/api/v1/licenses/deactivate":
                self.send_json(deactivate_license(payload))
                return
            if path == "/api/v1/licenses/revoke":
                self.require_admin_token()
                self.send_json(revoke_license(payload))
                return
            if path == "/api/v1/licenses/restore":
                self.require_admin_token()
                self.send_json(restore_license(payload))
                return
            if path == "/api/v1/licenses/limit":
                self.require_admin_token()
                self.send_json(limit_license(payload))
                return
            if path == "/api/v1/licenses/unlimit":
                self.require_admin_token()
                self.send_json(unlimit_license(payload))
                return
            if path == "/api/v1/licenses/note":
                self.require_admin_token()
                self.send_json(update_license_note(payload))
                return
            if path == "/api/v1/licenses/reset-devices":
                self.require_admin_token()
                self.send_json(admin_reset_license_devices(payload))
                return
            if path == "/api/v1/licenses/remove-device":
                self.require_admin_token()
                self.send_json(admin_remove_license_device(payload))
                return
            if path == "/api/v1/support-tickets":
                self.send_json(create_support_ticket(payload), status=HTTPStatus.CREATED)
                return
            if path == "/api/v1/support-tickets/mine":
                self.send_json(list_my_support_tickets(payload))
                return
            if path == "/api/v1/admin/support-tickets/action":
                self.require_admin_token()
                self.send_json(admin_update_support_ticket(payload))
                return
            if path == "/api/v1/admin/support-tickets/delete":
                self.require_admin_token()
                self.send_json(admin_delete_support_ticket(payload))
                return
            if path == "/api/v1/announcements/mine":
                self.send_json(list_my_announcements(payload))
                return
            if path == "/api/v1/admin/announcements/create":
                self.require_admin_token()
                self.send_json(admin_create_announcement(payload), status=HTTPStatus.CREATED)
                return
            if path == "/api/v1/admin/announcements/delete":
                self.require_admin_token()
                self.send_json(admin_delete_announcement(payload))
                return
            if path == "/api/v1/admin/service-status":
                self.require_admin_token()
                self.send_json(admin_update_service_status(payload))
                return
            if path == "/api/v1/admin/activity/download-link":
                self.require_admin_token()
                self.send_json(create_api_activity_download_link())
                return
            if path == "/api/v1/admin/audit-exports/download-link":
                self.require_admin_token()
                self.send_json(create_admin_audit_download_link(payload))
                return
            if path == "/api/v1/audit-exports":
                self.send_json(create_audit_export(payload), status=HTTPStatus.CREATED)
                return
            if path == "/api/v1/shop/recommend":
                self.send_json(recommend_shop_plan(payload))
                return
            if path == "/api/v1/shop/compare":
                self.send_json(compare_shop_plans(payload))
                return
        except RequestTooLarge as exc:
            self.send_json(
                {
                    "ok": False,
                    "error": "request_too_large",
                    "message": str(exc),
                },
                status=413,
            )
        except UnsupportedMediaType as exc:
            self.send_json(
                {
                    "ok": False,
                    "error": "unsupported_media_type",
                    "message": str(exc),
                },
                status=HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            )
        except PermissionError as exc:
            self.send_json(
                {
                    "ok": False,
                    "error": "forbidden",
                    "message": str(exc),
                },
                status=HTTPStatus.FORBIDDEN,
            )
        except FileNotFoundError as exc:
            self.send_json(
                {
                    "ok": False,
                    "error": "not_found",
                    "message": str(exc),
                },
                status=HTTPStatus.NOT_FOUND,
            )
        except ValueError as exc:
            self.send_json(
                {
                    "ok": False,
                    "error": "bad_request",
                    "message": str(exc),
                },
                status=HTTPStatus.BAD_REQUEST,
            )
        except Exception:
            self.send_json(
                {
                    "ok": False,
                    "error": "server_error",
                    "message": "Internal server error.",
                },
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
            )

    def log_message(self, fmt, *args):
        return


def run():
    port = int(os.getenv("PORT", "8000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), ApiHandler)
    print(f"{API_NAME} listening on http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
