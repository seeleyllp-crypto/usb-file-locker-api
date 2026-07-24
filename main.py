import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone
from html import escape as html_escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backup_verification_catalog import fixed_backup_plans, fixed_restore_objectives
from backup_verification_page import customer_backup_verification_html
from data_control_catalog import fixed_data_classes, fixed_data_flow_steps, fixed_data_scopes
from data_control_page import customer_data_control_html
from customer_experience_pages import (
    customer_answers_html,
    customer_decision_wizard_html,
    customer_diagnostics_center_html,
    customer_incident_response_html,
    customer_recovery_drills_html,
    customer_trust_center_html,
    customer_workspace_html,
    owner_customer_experience_html,
    owner_trust_center_html,
)
from customer_answers_catalog import fixed_customer_answer_categories, fixed_customer_answers
from customer_decision_catalog import fixed_decision_nodes, fixed_decision_outcomes, fixed_decision_scenarios
from recovery_drill_catalog import fixed_recovery_drills
from recovery_kit_catalog import fixed_emergency_runbooks, fixed_recovery_kit_profiles, fixed_recovery_kit_sections
from recovery_kit_page import customer_recovery_kit_html
from maintenance_catalog import (
    CADENCE_DAYS,
    SCHEDULE_SCORE_WEIGHTS,
    fixed_maintenance_categories,
    fixed_planning_horizons,
    fixed_maintenance_routines,
    fixed_maintenance_tasks,
)
from maintenance_page import customer_maintenance_html
from owner_operations_page import owner_maintenance_operations_html
from retention_catalog import fixed_cleanup_flow, fixed_retention_areas, fixed_retention_practices
from retention_page import customer_retention_html
from account_pages import customer_account_html, owner_accounts_html


API_NAME = "VaultLink API"
API_VERSION = "0.65.0"
LEGAL_DOCUMENT_VERSION = "2026-07-12-draft-1"
ROOT_DIR = Path(__file__).resolve().parent
LICENSE_KEY_PREFIX = "vlk1"
LICENSE_RECEIPT_PREFIX = "vlr1"
ACCOUNT_SESSION_PREFIX = "vlas1"
AUDIT_DOWNLOAD_PREFIX = "vla1"
ACTIVITY_DOWNLOAD_PREFIX = "vlt1"
DEFAULT_SIGNING_SECRET = "vaultlink-dev-signing-secret-change-me"
UPDATE_DIR = ROOT_DIR / "updates"
UPDATE_MANIFEST_PATH = UPDATE_DIR / "windows-manifest.json"
UPDATE_SIGNING_KEY_ID = "4f8fb9b8dbffd4c0"
UPDATE_SIGNING_PUBLIC_KEY_B64 = "UhQt7KyhSd6na6ZL5zmvOTKMgQqdY3FUEdoKRX-iGKU"
MAX_UPDATE_MANIFEST_BYTES = 64 * 1024
MAX_UPDATE_PACKAGE_BYTES = 50 * 1024 * 1024
MAX_LICENSE_JSON_BODY_BYTES = 64 * 1024
MAX_ACCOUNT_JSON_BODY_BYTES = 16 * 1024
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
        "backup_checkpoint_save",
        "backup_folder_verify",
        "backup_history_export",
        "backup_summary_copy",
        "backup_verification_center_open",
        "backup_verification_export",
        "backup_verification_online_open",
        "data_control_center_open",
        "data_control_center_refresh",
        "data_control_export_json",
        "data_control_export_text",
        "data_control_folder_open",
        "data_control_online_open",
        "data_control_receipt_save",
        "data_control_summary_copy",
        "recovery_kit_calendar_export",
        "recovery_kit_center_open",
        "recovery_kit_export_json",
        "recovery_kit_export_text",
        "recovery_kit_online_open",
        "recovery_kit_runbook_copy",
        "recovery_kit_snapshot_save",
        "backup_app_data",
        "backup_master_key",
        "check_lock_format",
        "compare_backup_key",
        "configuration_change",
        "customer_center_verify",
        "diagnostics_center_copy",
        "diagnostics_center_export",
        "diagnostics_center_open",
        "diagnostics_center_run",
        "incident_center_copy",
        "incident_center_export",
        "incident_center_open",
        "incident_center_refresh",
        "incident_playbook_progress",
        "incident_windows_security_open",
        "support_redactor_copy",
        "support_redactor_load",
        "support_redactor_open",
        "support_redactor_paste",
        "support_redactor_run",
        "support_redactor_save",
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
        "local_control_center_open",
        "local_control_desktop_lock",
        "local_control_launch",
        "local_control_login",
        "local_control_logout",
        "local_control_pin_change",
        "local_control_report_export",
        "local_control_start",
        "local_control_stop",
        "local_control_usb_removed",
        "lock",
        "lock_note",
        "lock_remove_original",
        "locked_file_browser_scan",
        "login",
        "maintenance_calendar_export",
        "maintenance_archive_export",
        "maintenance_center_open",
        "maintenance_center_refresh",
        "maintenance_history_export",
        "maintenance_online_open",
        "maintenance_report_export",
        "maintenance_routine_complete",
        "maintenance_snapshot_compare",
        "maintenance_snapshot_save",
        "maintenance_summary_copy",
        "maintenance_task_complete",
        "maintenance_task_reopen",
        "maintenance_trusted_tool_open",
        "open_temp_unlocked_file",
        "open_temp_unlocked_text",
        "owner_usb_removed",
        "owner_announcement_view",
        "panic_lock",
        "perm_unlock_workbench_relock",
        "perm_unlock_workbench_relock_copy",
        "perm_unlock_workbench_relock_remove",
        "quick_lock_note",
        "recovery_drill_center_open",
        "recovery_drill_copy",
        "recovery_drill_export",
        "recovery_drill_history_export",
        "recovery_drill_online_open",
        "recovery_drill_progress",
        "recovery_drill_result",
        "recovery_drill_schedule",
        "recovery_drill_windows_security",
        "recovery_self_test",
        "retention_center_open",
        "retention_center_refresh",
        "retention_export_json",
        "retention_export_text",
        "retention_online_open",
        "retention_receipt_save",
        "retention_summary_copy",
        "retention_temp_cleanup",
        "restore_app_data",
        "save_personal_vault",
        "scan_personal_files",
        "support_ticket_submit",
        "support_ticket_view",
        "trust_center_export",
        "trust_center_open",
        "trust_center_refresh",
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
ACCOUNT_RECORD_AAD = b"VaultLinkAccountRecordV1"
MAX_ACCOUNTS = 5000
ACCOUNT_SESSION_HOURS = 12
ACCOUNT_LOGIN_WINDOW_SECONDS = 15 * 60
ACCOUNT_LOGIN_MAX_FAILURES = 8
ACCOUNT_REGISTER_WINDOW_SECONDS = 60 * 60
ACCOUNT_REGISTER_MAX_ATTEMPTS = 10
ACCOUNT_AVAILABILITY_WINDOW_SECONDS = 60
ACCOUNT_AVAILABILITY_MAX_CHECKS = 120
ACCOUNT_LOGIN_FAILURES = {}
ACCOUNT_REGISTER_ATTEMPTS = {}
ACCOUNT_AVAILABILITY_CHECKS = {}
ACCOUNT_RATE_LOCK = threading.Lock()
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
READINESS_CHECKS = (
    {"id": "backup_current", "label": "Current backup exists", "weight": 20, "critical": True, "action": "Create and verify a current backup before locking important data."},
    {"id": "master_usb_tested", "label": "Master USB key tested", "weight": 20, "critical": True, "action": "Test the master USB key with a disposable non-private file."},
    {"id": "recovery_copy_separate", "label": "Recovery copy stored separately", "weight": 15, "critical": False, "action": "Store a recovery copy away from both the PC and primary USB key."},
    {"id": "pin_stored_separately", "label": "PIN stored separately from USB", "weight": 10, "critical": False, "action": "Keep the optional PIN separate from the USB key and locked files."},
    {"id": "defender_enabled", "label": "Microsoft Defender active", "weight": 10, "critical": False, "action": "Confirm Microsoft Defender is active and run a current scan."},
    {"id": "test_file_roundtrip", "label": "Disposable file lock and unlock tested", "weight": 15, "critical": True, "action": "Complete a lock and unlock round trip using a disposable non-private file."},
    {"id": "update_current", "label": "VaultLink version checked", "weight": 10, "critical": False, "action": "Use Update Center to compare the installed app with the latest signed release."},
)


class RequestTooLarge(ValueError):
    pass


class UnsupportedMediaType(ValueError):
    pass


FEATURES = [
    {
        "id": "security-maintenance-center",
        "title": "Security Maintenance Center",
        "summary": "Schedule thirty-two fixed defensive tasks, use six routines, review 7/30/90-day planning, compare hash-chained local snapshots, and export verified privacy-safe archives.",
        "category": "starter",
    },
    {
        "id": "storage-retention-center",
        "title": "Storage & Retention Center",
        "summary": "Review eight fixed storage areas, verify ten protection controls, preview only the exact VaultLink temp workspace, and clean expired temporary copies with typed confirmation and hash-chained coarse receipts.",
        "category": "starter",
    },
    {
        "id": "data-control-center",
        "title": "Local Data Control Center",
        "summary": "Review fourteen fixed data classes, coarse allowlisted local storage bands, protection controls, retention, and hash-chained privacy receipts without scanning customer folders.",
        "category": "starter",
    },
    {
        "id": "recovery-kit-builder",
        "title": "Recovery Kit Builder",
        "summary": "Build a fixed emergency recovery card, rehearse five first-hour runbooks, schedule reviews, and keep hash-chained coarse local snapshots without storing identity or secrets.",
        "category": "starter",
    },
    {
        "id": "backup-verification-center",
        "title": "Backup Verification Center",
        "summary": "Verify recognized app-data backup folders, compare hash-chained coarse checkpoints, choose fixed restore objectives, and follow twelve privacy-safe backup plans.",
        "category": "starter",
    },
    {
        "id": "recovery-drill-center",
        "title": "Recovery Drill Center",
        "summary": "Practice sixteen fixed recovery and continuity drills, score ten local readiness checks, keep hash-chained local-only results, and export reviewed privacy-safe reports.",
        "category": "starter",
    },
    {
        "id": "incident-response-center",
        "title": "Incident Response Center",
        "summary": "Use twelve fixed safety playbooks, local readiness checks, trusted Windows tools, and reviewed privacy-safe exports without remote PC control.",
        "category": "starter",
    },
    {
        "id": "diagnostics-center",
        "title": "Diagnostics Center",
        "summary": "Run privacy-safe read-only runtime, storage, Defender, audit, USB, licensing, update, and recovery checks with concrete next steps.",
        "category": "starter",
    },
    {
        "id": "trust-recovery-center",
        "title": "Trust and Recovery Center",
        "summary": "Review privacy-safe local and online trust checks, signed-release evidence, recovery guidance, and service boundaries without uploading files or secrets.",
        "category": "starter",
    },
    {
        "id": "customer-hub",
        "title": "Customer Workspace",
        "summary": "Combine privacy-safe account health, seats, releases, prioritized actions, rank tools, milestones, upgrades, and customer routes without displaying license proof or machine identity.",
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
    {"name": "Security Maintenance Center", "script": "security_maintenance_center.py", "purpose": "Track thirty-two fixed defensive tasks, task-specific due dates, six routines, schedule coverage, priority planning, snapshots, and privacy-safe hash-chained local history."},
    {"name": "Storage & Retention Center", "script": "storage_retention_center.py", "purpose": "Review eight fixed storage areas and safely clean only expired entries in VaultLink's exact temporary workspace after a fresh bounded preview and typed confirmation."},
    {"name": "Local Data Control Center", "script": "local_data_control_center.py", "purpose": "Map fixed VaultLink data boundaries, verify eleven protection controls, and export reviewed coarse privacy receipts without arbitrary file discovery."},
    {"name": "Recovery Kit Builder", "script": "recovery_kit_builder.py", "purpose": "Build a fixed privacy-safe emergency card, score local readiness, export a calendar reminder, and keep hash-chained coarse snapshots."},
    {"name": "Backup Verification Center", "script": "backup_verification_center.py", "purpose": "Verify recognized app-data backups, score twelve fixed checks, compare privacy-safe checkpoints, and follow a fixed restore order."},
    {"name": "Recovery Drill Center", "script": "recovery_drill_center.py", "purpose": "Practice eighty fixed recovery steps, score local readiness, schedule reviews, and keep privacy-safe hash-chained results locally."},
    {"name": "Incident Response Center", "script": "incident_response_center.py", "purpose": "Use fixed incident playbooks, local readiness checks, Windows Security shortcuts, and reviewed safe reports."},
    {"name": "Diagnostics Center", "script": "diagnostics_center.py", "purpose": "Run eighteen read-only local checks and export a privacy-safe troubleshooting report."},
    {"name": "Trust and Recovery Center", "script": "trust_recovery_center.py", "purpose": "Combine local Defender, audit-chain, USB-policy, license, update, and API trust status in a privacy-safe report."},
    {"name": "Customer Workspace", "script": "customer_hub.py", "purpose": "Load the saved license into a privacy-safe customer action center and safe export."},
    {"name": "Privacy Safety Hub", "script": "privacy_safety_hub.py", "purpose": "Launch dashboard for the toolkit."},
    {"name": "Locked File Browser", "script": "locked_file_browser.py", "purpose": "Find .locked files quickly and jump into unlock mode."},
    {"name": "Quick Lock Note", "script": "quick_lock_note.py", "purpose": "Turn pasted text into a locked note fast."},
    {"name": "Key Inspector", "script": "key_inspector.py", "purpose": "Inspect a USB master key and owner-key matching."},
    {"name": "PERM UNLOCK Workbench", "script": "perm_unlock_workbench.py", "purpose": "Manage edit-and-relock items in the PERM UNLOCK folder."},
    {"name": "Personal Vault Pad", "script": "personal_vault_pad.py", "purpose": "Use the vault in a simpler note-style window."},
    {"name": "Audit Log Viewer", "script": "audit_log_viewer.py", "purpose": "Read and export the privacy-safe signed audit trail."},
    {"name": "VaultLink License Issuer", "script": "license_issuer.py", "purpose": "Issue customer licenses through the admin-protected API."},
    {"name": "Text Log Processor", "script": "text_log_processor.py", "purpose": "Parse table-style text logs into a cleaner summary."},
    {"name": "Support Redactor", "script": "support_redactor.py", "purpose": "Remove common secrets and personal details from explicitly pasted or opened support text without automatic upload."},
    {"name": "Download Verification Center", "script": "download_verification_center.py", "purpose": "Calculate SHA-256, export locally sealed receipts, inspect or compare one sanitized prior receipt, run a bounded non-recursive aggregate receipt-folder audit with a single local review window and scrollable small-screen review surface, bounded row and review-ID consumption, cancellable search debounce, keyboard review controls, a fixed active-view indicator without query text, stable empty and complete states, selection preservation with visible and pending queue positions, priority-level and session-state filtering, fixed triage with privacy-safe fixed guidance and aggregate summary copy, temporary single-row, review-and-next, and bounded bulk-visible review or reopen marks, Ctrl+Enter review-and-next, Ctrl+Z undo, 100-action one-step bulk undo, aggregate completion progress with a determinate bar, an aggregate level breakdown, and visible pending and reviewed counts, failure-first navigation, and forward and reverse pending navigation, inspect file structure, and explicitly run Defender without extracting, executing, or uploading selected files, folders, names, search text, active-view state, queue positions, clipboard text, delayed-callback state, review IDs, action history, bulk mark state, session state, progress, selected positions, visible counts, selections, navigation, guidance state, summary contents, level filters, result filters, sorting, results, receipts, keys, or reports."},
    {"name": "Global Breach Guard", "script": "global_breach_guard.py", "purpose": "Run a topmost global breach watcher."},
]


SECURITY_NOTES = [
    "The public API never unlocks files, never receives USB secrets, and never stores PINs or vault contents.",
    "Desktop encryption and USB-key logic stay in the Windows app instead of moving onto the internet-facing service.",
    "Signed keys and receipts are checked against persistent revocation and anonymous device-seat ledgers.",
    "Owner license keys and private notes are encrypted at rest and available only through admin-token routes.",
    "Audit exports are reduced to privacy-safe fields, require an active licensed machine, and use short-lived signed download links.",
    "Ranks are software and service package descriptions, not HIPAA certification, legal approval, guaranteed protection, or proof of professional review.",
    "The Storage & Retention Center can clean only the exact local VaultLink temporary workspace; it rejects links and never accepts remote cleanup commands or customer storage inventories.",
    "The Security Maintenance Center stores fixed task completion and reopen events locally; the public guide receives no progress, local result, reminder, or history.",
    "Security Maintenance schedule scores and snapshot comparisons measure reminder coverage only and are not antivirus, backup, key, recovery, compliance, or security-health results.",
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
            "Security Maintenance Center",
            "Storage & Retention Center",
            "Local Data Control Center",
            "Recovery Kit Builder",
            "Backup Verification Center",
            "Portable locking tools",
            "Quick lock notes",
            "Recovery Drill Center",
            "Incident Response Center",
            "Diagnostics Center",
            "Trust and Recovery Center",
            "Microsoft Defender package scan",
            "Signed purchase verification",
            "Core PIN, recovery, and audit tools",
        ],
        "features": [
            "security-maintenance-center",
            "storage-retention-center",
            "data-control-center",
            "recovery-kit-builder",
            "backup-verification-center",
            "recovery-drill-center",
            "incident-response-center",
            "diagnostics-center",
            "trust-recovery-center",
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


def account_record_encryption_key():
    material = ("vaultlink-account-records-v1\0" + license_records_secret()).encode("utf-8")
    return hashlib.sha256(material).digest()


def encrypt_account_private_fields(payload):
    nonce = os.urandom(12)
    encrypted = AESGCM(account_record_encryption_key()).encrypt(
        nonce,
        canonical_json_bytes(payload),
        ACCOUNT_RECORD_AAD,
    )
    return b64url_encode(nonce + encrypted)


def decrypt_account_private_fields(record):
    encoded = str(record.get("private_blob", "")).strip()
    if not encoded:
        raise ValueError("Stored account private data is missing.")
    packed = b64url_decode(encoded)
    if len(packed) < 29:
        raise ValueError("Stored account private data is damaged.")
    plain = AESGCM(account_record_encryption_key()).decrypt(
        packed[:12],
        packed[12:],
        ACCOUNT_RECORD_AAD,
    )
    payload = json.loads(plain.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Stored account private data is invalid.")
    return payload


def validated_account_id(value):
    account_id = str(value or "").strip()
    if not re.fullmatch(r"acct_[A-Za-z0-9_-]{20,80}", account_id):
        raise ValueError("account_id is invalid.")
    return account_id


def validated_account_username(value):
    username = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{2,31}", username):
        raise ValueError(
            "Username must be 3 to 32 characters and use only letters, numbers, underscores, or hyphens."
        )
    return username, username.casefold()


def validated_account_password(value):
    if not isinstance(value, str):
        raise ValueError("Password must be text.")
    password = value
    if len(password) < 10 or len(password) > 128 or len(password.encode("utf-8")) > 512:
        raise ValueError("Password must be between 10 and 128 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in password):
        raise ValueError("Password cannot contain control characters.")
    classes = (
        any(character.islower() for character in password),
        any(character.isupper() for character in password),
        any(character.isdigit() for character in password),
        any(not character.isalnum() for character in password),
    )
    if sum(classes) < 3:
        raise ValueError("Password must use at least three of: lowercase, uppercase, numbers, and symbols.")
    return password


def account_username_hash(normalized_username):
    return hmac.new(
        account_record_encryption_key(),
        ("username\0" + str(normalized_username)).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def account_password_fields(password):
    password = validated_account_password(password)
    salt = os.urandom(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        maxmem=64 * 1024 * 1024,
        dklen=32,
    )
    return {
        "password_algorithm": "scrypt",
        "password_salt": b64url_encode(salt),
        "password_hash": b64url_encode(digest),
        "password_n": 2**14,
        "password_r": 8,
        "password_p": 1,
    }


def account_password_matches(password, private_fields):
    try:
        password = validated_account_password(password)
        if private_fields.get("password_algorithm") != "scrypt":
            return False
        salt = b64url_decode(str(private_fields["password_salt"]))
        expected = b64url_decode(str(private_fields["password_hash"]))
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(private_fields.get("password_n", 0)),
            r=int(private_fields.get("password_r", 0)),
            p=int(private_fields.get("password_p", 0)),
            maxmem=64 * 1024 * 1024,
            dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)
    except (KeyError, TypeError, ValueError):
        return False


def account_record_path(account_id):
    return private_record_path("accounts", validated_account_id(account_id))


def read_account_record(account_id):
    clean_id = validated_account_id(account_id)
    path = account_record_path(clean_id)
    if not path.is_file():
        return None
    record = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(record, dict) or record.get("account_id") != clean_id:
        raise ValueError("Stored account identity did not verify.")
    return record


def write_account_record(record, private_fields=None):
    account_id = validated_account_id(record.get("account_id"))
    stored = dict(record)
    stored["schema_version"] = 1
    stored["account_id"] = account_id
    if private_fields is not None:
        stored["private_blob"] = encrypt_account_private_fields(private_fields)
    if not str(stored.get("private_blob", "")).strip():
        raise ValueError("Account private data is required.")
    stored["updated_at_utc"] = utc_now()
    write_private_json(account_record_path(account_id), stored)
    return stored


def list_account_records():
    folder = LICENSE_STATE_DIR / "accounts"
    if not folder.is_dir():
        return []
    records = []
    for path in sorted(folder.glob("*.json")):
        if len(records) >= MAX_ACCOUNTS:
            raise ValueError("Account inventory exceeds the configured safety limit.")
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(record, dict) and record.get("account_id"):
                validated_account_id(record["account_id"])
                records.append(record)
        except Exception:
            continue
    return records


def find_account_by_username(username):
    display, normalized = validated_account_username(username)
    expected_hash = account_username_hash(normalized)
    for record in list_account_records():
        if hmac.compare_digest(str(record.get("username_hash", "")), expected_hash):
            private_fields = decrypt_account_private_fields(record)
            if hmac.compare_digest(str(private_fields.get("username_normalized", "")), normalized):
                return record, private_fields
    return None, {"username": display, "username_normalized": normalized}


def account_license_view(record, include_license_key=False):
    license_id = str(record.get("assigned_license_id", "")).strip()
    if not license_id:
        return {"assigned": False, "status": "unassigned"}
    license_record = read_license_record(license_id)
    if not license_record:
        return {
            "assigned": True,
            "license_id": license_id,
            "status": "missing",
            "message": "The assigned license record is missing.",
        }
    bound_account_id = str(license_record.get("account_id", "")).strip()
    if bound_account_id and bound_account_id != str(record.get("account_id", "")):
        return {
            "assigned": True,
            "license_id": license_id,
            "status": "binding_mismatch",
            "message": "The license is bound to a different customer account.",
        }
    plan = PLAN_INDEX.get(str(license_record.get("plan_id", "")))
    private_fields = stored_license_private_fields(license_record)
    license_key = str(private_fields.get("license_key", ""))
    payload = {
        "assigned": True,
        "license_id": license_id,
        "plan_id": str(license_record.get("plan_id", "")),
        "plan_name": str(license_record.get("plan_name", "")),
        "rank": int(plan.get("rank", 0)) if plan else 0,
        "status": str(license_record.get("status", "unknown")),
        "expires_at_utc": str(license_record.get("expires_at_utc", "")),
        "max_devices": int(license_record.get("max_devices", 1) or 1),
        "active_devices": active_device_count(license_id),
        "masked_license_key": masked_license_key(license_key),
    }
    if include_license_key:
        payload["license_key"] = license_key
    return payload


def account_view(record, include_license_key=False):
    private_fields = decrypt_account_private_fields(record)
    return {
        "account_id": str(record.get("account_id", "")),
        "username": str(private_fields.get("username", "")),
        "status": str(record.get("status", "active")),
        "created_at_utc": str(record.get("created_at_utc", "")),
        "updated_at_utc": str(record.get("updated_at_utc", "")),
        "last_login_at_utc": str(record.get("last_login_at_utc", "")),
        "license": account_license_view(record, include_license_key=include_license_key),
    }


def issue_account_session(record):
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=ACCOUNT_SESSION_HOURS)
    token = sign_token(
        ACCOUNT_SESSION_PREFIX,
        {
            "account_id": validated_account_id(record.get("account_id")),
            "session_version": int(record.get("session_version", 1) or 1),
            "issued_at_utc": format_utc(now),
            "expires_at_utc": format_utc(expires),
            "nonce": secrets.token_hex(8),
        },
    )
    return token, format_utc(expires)


def verify_account_session(token):
    try:
        payload = verify_token(token, ACCOUNT_SESSION_PREFIX)
        account_id = validated_account_id(payload.get("account_id"))
        expires = parse_utc(payload.get("expires_at_utc"))
        if not expires or expires <= datetime.now(timezone.utc):
            raise PermissionError("Account session expired. Sign in again.")
        record = read_account_record(account_id)
        if not record or record.get("status") != "active":
            raise PermissionError("Account access is disabled.")
        if int(payload.get("session_version", 0) or 0) != int(record.get("session_version", 1) or 1):
            raise PermissionError("Account session is no longer valid. Sign in again.")
        return record
    except PermissionError:
        raise
    except Exception as exc:
        raise PermissionError("Account session was missing or invalid.") from exc


def account_rate_key(remote_key, username=""):
    remote = str(remote_key or "unknown")[:120]
    normalized = str(username or "").casefold()[:64]
    return hashlib.sha256((remote + "\0" + normalized).encode("utf-8")).hexdigest()


def account_rate_allowed(bucket, key, limit, window_seconds, consume=False):
    now = datetime.now(timezone.utc).timestamp()
    with ACCOUNT_RATE_LOCK:
        recent = [moment for moment in bucket.get(key, []) if now - moment < window_seconds]
        if len(recent) >= limit:
            bucket[key] = recent
            return False
        if consume:
            recent.append(now)
        if recent:
            bucket[key] = recent
        else:
            bucket.pop(key, None)
        return True


def register_account(payload, remote_key="unknown"):
    username, normalized = validated_account_username(payload.get("username"))
    password = validated_account_password(payload.get("password"))
    rate_key = account_rate_key(remote_key)
    if not account_rate_allowed(
        ACCOUNT_REGISTER_ATTEMPTS,
        rate_key,
        ACCOUNT_REGISTER_MAX_ATTEMPTS,
        ACCOUNT_REGISTER_WINDOW_SECONDS,
        consume=True,
    ):
        raise PermissionError("Too many account registrations from this connection. Try again later.")
    with LICENSE_STATE_LOCK:
        if len(list_account_records()) >= MAX_ACCOUNTS:
            raise ValueError("Account capacity has been reached.")
        existing, _private = find_account_by_username(username)
        if existing:
            raise ValueError("That username is not available.")
        private_fields = {
            "username": username,
            "username_normalized": normalized,
            **account_password_fields(password),
        }
        now = utc_now()
        record = write_account_record(
            {
                "account_id": f"acct_{secrets.token_urlsafe(18)}",
                "username_hash": account_username_hash(normalized),
                "status": "active",
                "created_at_utc": now,
                "last_login_at_utc": now,
                "session_version": 1,
                "assigned_license_id": "",
            },
            private_fields,
        )
    token, expires_at = issue_account_session(record)
    record_api_activity("account_register", "ok", "account", record["account_id"])
    return {
        "ok": True,
        "created": True,
        "session_token": token,
        "session_expires_at_utc": expires_at,
        "account": account_view(record, include_license_key=True),
    }


def login_account(payload, remote_key="unknown"):
    username = str(payload.get("username", "")).strip()
    password = payload.get("password")
    rate_key = account_rate_key(remote_key, username)
    if not account_rate_allowed(
        ACCOUNT_LOGIN_FAILURES,
        rate_key,
        ACCOUNT_LOGIN_MAX_FAILURES,
        ACCOUNT_LOGIN_WINDOW_SECONDS,
    ):
        raise PermissionError("Too many failed sign-in attempts. Try again later.")
    try:
        record, private_fields = find_account_by_username(username)
    except ValueError:
        record, private_fields = None, {}
    if (
        not record
        or record.get("status") != "active"
        or not account_password_matches(password, private_fields)
    ):
        account_rate_allowed(
            ACCOUNT_LOGIN_FAILURES,
            rate_key,
            ACCOUNT_LOGIN_MAX_FAILURES,
            ACCOUNT_LOGIN_WINDOW_SECONDS,
            consume=True,
        )
        raise PermissionError("Username or password was incorrect.")
    with ACCOUNT_RATE_LOCK:
        ACCOUNT_LOGIN_FAILURES.pop(rate_key, None)
    record["last_login_at_utc"] = utc_now()
    write_account_record(record)
    token, expires_at = issue_account_session(record)
    record_api_activity("account_login", "ok", "account", record["account_id"])
    return {
        "ok": True,
        "session_token": token,
        "session_expires_at_utc": expires_at,
        "account": account_view(record, include_license_key=True),
    }


def account_me(token):
    record = verify_account_session(token)
    session_payload = verify_token(token, ACCOUNT_SESSION_PREFIX)
    return {
        "ok": True,
        "account": account_view(record, include_license_key=True),
        "session_expires_at_utc": str(session_payload.get("expires_at_utc", "")),
        "server_time_utc": utc_now(),
    }


def account_username_availability(value, remote_key="unknown"):
    username, _normalized = validated_account_username(value)
    rate_key = account_rate_key(remote_key)
    if not account_rate_allowed(
        ACCOUNT_AVAILABILITY_CHECKS,
        rate_key,
        ACCOUNT_AVAILABILITY_MAX_CHECKS,
        ACCOUNT_AVAILABILITY_WINDOW_SECONDS,
        consume=True,
    ):
        raise PermissionError("Too many username checks from this connection. Try again shortly.")
    record, _private_fields = find_account_by_username(username)
    return {
        "ok": True,
        "username": username,
        "available": record is None,
        "requirements": {
            "minimum_characters": 3,
            "maximum_characters": 32,
            "allowed": "letters, numbers, underscores, and hyphens",
        },
        "server_time_utc": utc_now(),
    }


def logout_all_account_sessions(token):
    record = verify_account_session(token)
    record["session_version"] = int(record.get("session_version", 1) or 1) + 1
    write_account_record(record)
    record_api_activity("account_logout_all", "ok", "account", record["account_id"])
    return {
        "ok": True,
        "signed_out_all": True,
        "server_time_utc": utc_now(),
    }


def change_account_username(payload, token):
    record = verify_account_session(token)
    private_fields = decrypt_account_private_fields(record)
    if not account_password_matches(payload.get("current_password"), private_fields):
        raise PermissionError("Current password was incorrect.")
    username, normalized = validated_account_username(payload.get("new_username"))
    current_username = str(private_fields.get("username", ""))
    if username == current_username:
        raise ValueError("New username must be different from the current username.")
    existing, _existing_private = find_account_by_username(username)
    if existing and existing.get("account_id") != record.get("account_id"):
        raise ValueError("That username is not available.")
    private_fields["username"] = username
    private_fields["username_normalized"] = normalized
    record["username_hash"] = account_username_hash(normalized)
    record["session_version"] = int(record.get("session_version", 1) or 1) + 1
    record = write_account_record(record, private_fields)
    new_token, expires_at = issue_account_session(record)
    record_api_activity("account_username_change", "ok", "account", record["account_id"])
    return {
        "ok": True,
        "session_token": new_token,
        "session_expires_at_utc": expires_at,
        "account": account_view(record, include_license_key=True),
    }


def change_account_password(payload, token):
    record = verify_account_session(token)
    private_fields = decrypt_account_private_fields(record)
    if not account_password_matches(payload.get("current_password"), private_fields):
        raise PermissionError("Current password was incorrect.")
    new_password = validated_account_password(payload.get("new_password"))
    if account_password_matches(new_password, private_fields):
        raise ValueError("New password must be different from the current password.")
    private_fields.update(account_password_fields(new_password))
    record["session_version"] = int(record.get("session_version", 1) or 1) + 1
    write_account_record(record, private_fields)
    new_token, expires_at = issue_account_session(record)
    record_api_activity("account_password_change", "ok", "account", record["account_id"])
    return {
        "ok": True,
        "session_token": new_token,
        "session_expires_at_utc": expires_at,
        "account": account_view(record, include_license_key=True),
    }


def list_admin_accounts():
    accounts = [account_view(record, include_license_key=False) for record in list_account_records()]
    accounts.sort(key=lambda item: (item["username"].casefold(), item["account_id"]))
    return {
        "ok": True,
        "count": len(accounts),
        "items": accounts,
        "passwords_readable": False,
        "server_time_utc": utc_now(),
    }


def assign_account_license(payload):
    account_id = validated_account_id(payload.get("account_id"))
    requested_plan = str(payload.get("plan_id", "")).strip()
    requested_license = str(payload.get("license_id", "")).strip()
    if bool(requested_plan) == bool(requested_license):
        raise ValueError("Choose exactly one plan_id or license_id.")
    transfer = payload.get("transfer") is True
    with LICENSE_STATE_LOCK:
        account = read_account_record(account_id)
        if not account:
            raise FileNotFoundError("Account was not found.")
        if account.get("status") != "active":
            raise ValueError("Enable the customer account before assigning a license.")
        if requested_plan:
            issued = issue_license(
                {
                    "account_id": account_id,
                    "plan_id": requested_plan,
                    "max_devices": int(payload.get("max_devices", 1) or 1),
                    "expires_at_utc": payload.get("expires_at_utc", ""),
                    "license_note": clean_license_note(payload.get("license_note", "")),
                }
            )
            return {
                "ok": True,
                "assigned": True,
                "transferred": False,
                "account": issued["account"],
                "issued_license_key": issued["license_key"],
            }
        license_id = validated_license_id(requested_license)
        if not read_license_record(license_id):
            raise FileNotFoundError("License was not found.")
        previous_owners = [
            other
            for other in list_account_records()
            if (
                other.get("account_id") != account_id
                and str(other.get("assigned_license_id", "")) == license_id
            )
        ]
        if previous_owners and not transfer:
            raise ValueError("That license is already assigned to another account.")
        for previous_owner in previous_owners:
            previous_owner["assigned_license_id"] = ""
            previous_owner["session_version"] = int(previous_owner.get("session_version", 1) or 1) + 1
            write_account_record(previous_owner)
        previous_license_id = str(account.get("assigned_license_id", "")).strip()
        if previous_license_id and previous_license_id != license_id:
            update_license_account_binding(previous_license_id, "")
        account["assigned_license_id"] = license_id
        update_license_account_binding(license_id, account_id)
        write_account_record(account)
    record_api_activity("account_license_assign", "ok", "account", account_id)
    result = {
        "ok": True,
        "assigned": True,
        "transferred": bool(previous_owners),
        "account": account_view(account, include_license_key=False),
    }
    return result


def update_account_status(payload):
    account_id = validated_account_id(payload.get("account_id"))
    status = str(payload.get("status", "")).strip().lower()
    if status not in {"active", "disabled"}:
        raise ValueError("status must be active or disabled.")
    with LICENSE_STATE_LOCK:
        account = read_account_record(account_id)
        if not account:
            raise FileNotFoundError("Account was not found.")
        account["status"] = status
        account["session_version"] = int(account.get("session_version", 1) or 1) + 1
        write_account_record(account)
    record_api_activity("account_status_update", "ok", "account", account_id)
    return {"ok": True, "account": account_view(account, include_license_key=False)}


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
    account_id = str(license_payload.get("account_id") or existing.get("account_id") or "").strip()
    if account_id:
        account_id = validated_account_id(account_id)
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
        "account_id": account_id,
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


def update_license_account_binding(license_id, account_id):
    clean_license_id = validated_license_id(license_id)
    clean_account_id = str(account_id or "").strip()
    if clean_account_id:
        clean_account_id = validated_account_id(clean_account_id)
    record = read_license_record(clean_license_id)
    if not record:
        raise FileNotFoundError("License was not found.")
    record["account_id"] = clean_account_id
    record["updated_at_utc"] = utc_now()
    write_private_json(license_record_path(clean_license_id), record)
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
        "account_id": str(record.get("account_id", "")),
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
            "download_verification_center.py",
            "support_redactor.py",
            "text_log_processor.py",
            "locked_file_browser.py",
            "perm_unlock_workbench.py",
            "key_inspector.py",
            "quick_lock_note.py",
            "customer_hub.py",
            "diagnostics_center.py",
            "security_maintenance_center.py",
            "storage_retention_center.py",
            "local_data_control_center.py",
            "incident_response_center.py",
            "recovery_drill_center.py",
            "backup_verification_center.py",
            "recovery_kit_builder.py",
            "trust_recovery_center.py",
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
            {"method": "GET", "path": "/account", "purpose": "Customer registration, sign-in, assigned rank, and password-change app"},
            {"method": "GET", "path": "/workspace", "purpose": "Unified privacy-safe customer action, rank, release, and recovery workspace"},
            {"method": "GET", "path": "/QNA", "purpose": "Searchable fixed customer answer center with current-tab-only saved answers"},
            {"method": "GET", "path": "/decision", "purpose": "Branching recovery decision wizard with current-tab-only yes-or-no choices"},
            {"method": "GET", "path": "/maintenance", "purpose": "Public thirty-two-task maintenance planner with priority sorting, four cadence horizons, coverage dashboard, and current-tab-only review"},
            {"method": "GET", "path": "/retention", "purpose": "Public fixed storage map, retention practices, cleanup boundaries, and current-tab-only review receipt"},
            {"method": "GET", "path": "/data-control", "purpose": "Public fixed data map, protection boundaries, retention guidance, and current-tab-only review receipt"},
            {"method": "GET", "path": "/recovery-kit", "purpose": "Public fixed emergency kit, first-hour runbooks, calendar reminder, and current-tab-only progress"},
            {"method": "GET", "path": "/backup-verification", "purpose": "Public fixed backup plans, restore objectives, and current-tab-only progress"},
            {"method": "GET", "path": "/recovery-drills", "purpose": "Public fixed recovery and continuity exercises with current-tab-only progress"},
            {"method": "GET", "path": "/incident-response", "purpose": "Public fixed incident playbooks with session-only progress"},
            {"method": "GET", "path": "/diagnostics", "purpose": "Public fixed-step troubleshooting workspace with session-only progress"},
            {"method": "GET", "path": "/trust", "purpose": "Public trust, signed-release, privacy-boundary, and recovery center"},
            {"method": "GET", "path": "/status", "purpose": "Public customer service and signed-release status"},
            {"method": "GET", "path": "/terms", "purpose": "Draft Terms of Use for adult and legal review"},
            {"method": "GET", "path": "/privacy", "purpose": "Public privacy notice and data-handling summary"},
            {"method": "GET", "path": "/owner", "purpose": "Owner-only key and note web console"},
            {"method": "GET", "path": "/owner/accounts", "purpose": "Owner-only customer account, rank, and license assignment console"},
            {"method": "GET", "path": "/owner/insights", "purpose": "Owner-only 50-point operations and readiness command center"},
            {"method": "GET", "path": "/owner/customers", "purpose": "Owner-only aggregate customer-experience console"},
            {"method": "GET", "path": "/owner/trust", "purpose": "Owner-only trust, release, storage, audit, and service operations gate"},
            {"method": "GET", "path": "/owner/operations", "purpose": "Owner-only maintenance cockpit with approval gates, decision queue, current-tab review session, briefing, change watch, planner, evidence receipt, and 40 fixed checks"},
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
            {"method": "GET", "path": "/api/v1/customer-answers", "purpose": "Public thirty-answer catalog with no question or customer data collection"},
            {"method": "GET", "path": "/api/v1/customer-decisions", "purpose": "Public seven-situation recovery decision catalog with no customer data collection"},
            {"method": "GET", "path": "/api/v1/security", "purpose": "Public security and licensing notes"},
            {"method": "GET", "path": "/api/v1/trust-center", "purpose": "Public privacy-safe trust posture and recovery boundaries"},
            {"method": "GET", "path": "/api/v1/maintenance-guide", "purpose": "Public eight-category, thirty-two-task, six-routine, four-horizon maintenance catalog with no customer progress collection"},
            {"method": "GET", "path": "/api/v1/retention-guide", "purpose": "Public eight-area retention catalog and ten fixed practices with no local inventory or cleanup control"},
            {"method": "GET", "path": "/api/v1/data-map", "purpose": "Public fourteen-class data map with no customer inventory or progress collection"},
            {"method": "GET", "path": "/api/v1/diagnostics-guide", "purpose": "Public fixed troubleshooting categories and forty safe steps"},
            {"method": "GET", "path": "/api/v1/incident-guide", "purpose": "Public twelve-playbook incident guide with seventy-two fixed safe steps"},
            {"method": "GET", "path": "/api/v1/recovery-drills", "purpose": "Public sixteen-drill catalog with eighty fixed safe steps and no customer progress collection"},
            {"method": "GET", "path": "/api/v1/backup-verification", "purpose": "Public twelve-plan backup catalog with sixty fixed steps and no customer backup collection"},
            {"method": "GET", "path": "/api/v1/recovery-kit", "purpose": "Public five-profile recovery-kit catalog with fifty fixed items and no customer progress collection"},
            {"method": "GET", "path": "/api/v1/deploy", "purpose": "Railway deploy hints"},
            {"method": "POST", "path": "/api/v1/accounts/register", "purpose": "Create an encrypted username account with a one-way scrypt password hash"},
            {"method": "POST", "path": "/api/v1/accounts/login", "purpose": "Rate-limited account sign-in with a twelve-hour signed session"},
            {"method": "GET", "path": "/api/v1/accounts/me", "purpose": "Signed-session account and assigned-license view"},
            {"method": "GET", "path": "/api/v1/accounts/username-availability", "purpose": "Validate a proposed username and report whether it is available"},
            {"method": "POST", "path": "/api/v1/accounts/change-username", "purpose": "Change the authenticated username after current-password verification"},
            {"method": "POST", "path": "/api/v1/accounts/change-password", "purpose": "Authenticated password change with session invalidation"},
            {"method": "POST", "path": "/api/v1/accounts/logout-all", "purpose": "Invalidate every signed session for the authenticated account"},
            {"method": "POST", "path": "/api/v1/licenses/issue", "purpose": "Admin-only issuance bound to an existing active customer account"},
            {"method": "POST", "path": "/api/v1/licenses/activate", "purpose": "Machine-bound license activation"},
            {"method": "POST", "path": "/api/v1/licenses/verify", "purpose": "License and receipt verification"},
            {"method": "POST", "path": "/api/v1/licenses/preview", "purpose": "Read-only signed-license status without device activation"},
            {"method": "POST", "path": "/api/v1/licenses/upgrade-options", "purpose": "Privacy-safe higher-rank and added-entitlement comparison"},
            {"method": "POST", "path": "/api/v1/licenses/rank-tools", "purpose": "License-gated cumulative rank-exclusive customer tool packs"},
            {"method": "POST", "path": "/api/v1/licenses/customer-checkup", "purpose": "Privacy-safe license, seat, service, update, and rank-tool attention check"},
            {"method": "POST", "path": "/api/v1/licenses/support-guide", "purpose": "Fixed-category privacy-safe customer troubleshooting guide"},
            {"method": "POST", "path": "/api/v1/licenses/timeline", "purpose": "Read-only license milestones and local renewal-reminder metadata"},
            {"method": "POST", "path": "/api/v1/licenses/customer-workspace", "purpose": "Composite customer workspace without activation or identity fields"},
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
            {"method": "GET", "path": "/api/v1/admin/accounts", "purpose": "Admin-only account inventory without password hashes or license keys"},
            {"method": "POST", "path": "/api/v1/admin/accounts/assign", "purpose": "Admin-only new-rank issuance or existing-license assignment and transfer"},
            {"method": "POST", "path": "/api/v1/admin/accounts/status", "purpose": "Admin-only account enable or disable with session invalidation"},
            {"method": "GET", "path": "/api/v1/admin/licenses/{license_id}/devices", "purpose": "Admin-only anonymous device-seat inventory"},
            {"method": "GET", "path": "/api/v1/admin/dashboard", "purpose": "Admin-only license, device, audit, breach, and release totals"},
            {"method": "GET", "path": "/api/v1/admin/updates/windows/status", "purpose": "Admin-only live Ed25519, SHA-256, package-size, and app-data release test"},
            {"method": "GET", "path": "/api/v1/admin/insights", "purpose": "Admin-only set of exactly 50 privacy-safe owner operations insights"},
            {"method": "GET", "path": "/api/v1/admin/customer-experience", "purpose": "Admin-only aggregate customer experience, rank, release, and support health"},
            {"method": "GET", "path": "/api/v1/admin/trust-center", "purpose": "Admin-only trust gate with concrete operational actions"},
            {"method": "GET", "path": "/api/v1/admin/maintenance-operations", "purpose": "Admin-only approval-gate, decision-queue, review-lane, briefing, watch, planner, and fixed 40-check operations report"},
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
            {"method": "POST", "path": "/api/v1/updates/windows/check", "purpose": "Anonymous installed-version compatibility and update decision"},
            {"method": "POST", "path": "/api/v1/readiness/check", "purpose": "Anonymous fixed-field recovery-readiness score and action plan"},
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


def customer_answers_payload():
    categories = fixed_customer_answer_categories()
    answers = fixed_customer_answers()
    counts = {
        category["id"]: sum(answer["category_id"] == category["id"] for answer in answers)
        for category in categories
    }
    return {
        "ok": True,
        "schema_version": 1,
        "api_version": API_VERSION,
        "title": "VaultLink Customer Answers",
        "category_count": len(categories),
        "count": len(answers),
        "category_counts": counts,
        "categories": categories,
        "items": answers,
        "search_storage": "current_browser_tab_only",
        "saved_answer_storage": "current_browser_tab_only",
        "accepts_customer_questions": False,
        "collects_customer_data": False,
        "privacy_boundaries": [
            "The answer API is public and accepts no request body, license key, identity, machine identity, file, path, PIN, USB secret, local result, or free-form question.",
            "Search text, selected category, opened answers, and saved-answer choices stay only in the current browser tab and are never uploaded.",
            "Every answer and next-step route is fixed in the reviewed server catalog; answer text cannot execute commands or control a customer PC.",
            "The answer center is guidance, not antivirus analysis, legal advice, compliance certification, or proof that a problem is resolved.",
        ],
        "server_time_utc": utc_now(),
    }


def customer_decisions_payload():
    scenarios = fixed_decision_scenarios()
    nodes = fixed_decision_nodes()
    outcomes = fixed_decision_outcomes()
    return {
        "ok": True,
        "schema_version": 1,
        "api_version": API_VERSION,
        "title": "VaultLink Recovery Decision Wizard",
        "scenario_count": len(scenarios),
        "decision_count": len(nodes),
        "outcome_count": len(outcomes),
        "scenarios": scenarios,
        "nodes": nodes,
        "outcomes": outcomes,
        "choice_storage": "current_browser_tab_only",
        "accepts_free_form_input": False,
        "collects_customer_data": False,
        "controls_customer_pc": False,
        "privacy_boundaries": [
            "The decision API is public and accepts no request body, license key, identity, machine identity, file, path, filename, PIN, USB secret, local result, or free-form problem description.",
            "Selected situation, yes-or-no choices, decision trail, and outcome stay only in the current browser tab and are never uploaded or stored in browser storage.",
            "Every decision, outcome, action step, warning, and guide route is fixed in the reviewed server catalog.",
            "The wizard cannot inspect, scan, execute, lock, unlock, install, delete, quarantine, or control a customer PC.",
            "A decision result is guidance, not antivirus analysis, compliance certification, a recovery guarantee, or proof that the problem is resolved.",
        ],
        "server_time_utc": utc_now(),
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


def decode_update_base64url(value):
    text = str(value or "").strip()
    if not text or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in text):
        raise ValueError("The update signature encoding is invalid.")
    try:
        return base64.urlsafe_b64decode(text + "=" * ((4 - len(text) % 4) % 4))
    except Exception as exc:
        raise ValueError("The update signature encoding is invalid.") from exc


def canonical_update_manifest_bytes(manifest):
    payload = dict(manifest)
    payload.pop("signature", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def verify_windows_update_manifest_signature(manifest):
    if manifest.get("signing_key_id") != UPDATE_SIGNING_KEY_ID:
        raise ValueError("The update manifest signing key is not recognized.")
    try:
        Ed25519PublicKey.from_public_bytes(decode_update_base64url(UPDATE_SIGNING_PUBLIC_KEY_B64)).verify(
            decode_update_base64url(manifest.get("signature")),
            canonical_update_manifest_bytes(manifest),
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("The update manifest signature did not verify.") from exc


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
    if not 40 <= len(signature) <= 160:
        raise ValueError("The update manifest signature format is invalid.")
    verify_windows_update_manifest_signature(manifest)
    return manifest, package_path


def windows_update_release_status():
    try:
        manifest, package_path = load_windows_update_release()
        return {
            "ok": True,
            "ready": True,
            "version": manifest["version"],
            "minimum_supported_version": manifest["minimum_supported_version"],
            "published_at_utc": manifest["published_at_utc"],
            "package_filename": manifest["package_filename"],
            "size_bytes": package_path.stat().st_size,
            "sha256": manifest["sha256"],
            "signing_key_id": manifest["signing_key_id"],
            "checks": {
                "manifest_schema": "passed",
                "ed25519_signature": "passed",
                "package_size": "passed",
                "package_sha256": "passed",
                "app_data_preservation": "passed",
            },
            "tested_at_utc": utc_now(),
        }
    except (FileNotFoundError, OSError, ValueError) as exc:
        return {
            "ok": True,
            "ready": False,
            "message": str(exc),
            "checks": {
                "manifest_schema": "failed",
                "ed25519_signature": "failed",
                "package_size": "failed",
                "package_sha256": "failed",
                "app_data_preservation": "failed",
            },
            "tested_at_utc": utc_now(),
        }


def trust_center_payload():
    """Return public operational posture without customer or license records."""
    release = windows_update_release_status()
    service = service_status_payload()
    license_persistent = license_state_storage_is_persistent()
    audit_persistent = audit_storage_is_persistent()
    release_checks = release.get("checks") or {}
    checks = []

    def add(identifier, category, title, passed, weight, detail, action=""):
        checks.append(
            {
                "id": identifier,
                "category": category,
                "title": title,
                "state": "good" if passed else "attention",
                "passed": bool(passed),
                "weight": int(weight),
                "detail": detail,
                "action": action,
            }
        )

    add("api-online", "Service", "API is responding", True, 10, f"VaultLink API {API_VERSION} is responding over this endpoint.")
    add(
        "service-normal",
        "Service",
        "Customer service mode",
        service.get("mode") == "normal",
        10,
        str(service.get("message", "No public service message is available.")),
        "Review the public service notice before relying on online licensing or updates.",
    )
    add(
        "admin-auth",
        "Access",
        "Owner API authentication configured",
        admin_token_configured(),
        10,
        "Owner mutations require the X-License-Admin-Token request header.",
        "Configure LICENSE_ADMIN_TOKEN before using owner operations.",
    )
    add(
        "license-signing",
        "Cryptography",
        "Dedicated license signing secret",
        not using_default_signing_secret(),
        10,
        "Signed license and receipt tokens use a configured HMAC secret." if not using_default_signing_secret() else "The development signing-secret fallback is active.",
        "Configure a strong LICENSE_SIGNING_SECRET and retain it for license continuity.",
    )
    add(
        "license-storage",
        "Durability",
        "Persistent license storage",
        license_persistent,
        10,
        "License, revocation, device-seat, support, and announcement records use configured persistent storage." if license_persistent else "License records currently use local ephemeral storage.",
        "Mount a persistent volume and configure LICENSE_STATE_DIR.",
    )
    add(
        "audit-storage",
        "Durability",
        "Persistent privacy-safe audit storage",
        audit_persistent,
        10,
        "Privacy-safe audit exports use configured persistent storage." if audit_persistent else "Audit exports currently use local ephemeral storage.",
        "Mount a persistent volume and configure AUDIT_EXPORT_DIR.",
    )
    add(
        "signed-release",
        "Updates",
        "Signed Windows release available",
        bool(release.get("ready")),
        15,
        f"Signed desktop release {release.get('version', 'unavailable')} is available." if release.get("ready") else str(release.get("message", "No signed Windows release is ready.")),
        "Publish only an owner-tested package with an Ed25519-signed manifest.",
    )
    add(
        "release-signature",
        "Updates",
        "Ed25519 manifest signature",
        release_checks.get("ed25519_signature") == "passed",
        10,
        "The current release manifest signature verified." if release_checks.get("ed25519_signature") == "passed" else "The current release manifest signature is not verified.",
        "Rebuild and sign the release through the owner Update Lab.",
    )
    add(
        "release-hash",
        "Updates",
        "SHA-256 package integrity",
        release_checks.get("package_sha256") == "passed",
        10,
        "The published package matches its signed SHA-256 digest." if release_checks.get("package_sha256") == "passed" else "The published package does not have a verified SHA-256 result.",
        "Remove the release and publish a package whose digest matches the signed manifest.",
    )
    add(
        "remote-boundary",
        "Privacy",
        "Remote unlock and secret collection disabled",
        True,
        5,
        "The internet-facing API cannot unlock files and does not accept PINs, USB secrets, file paths, or file contents.",
    )

    score = sum(item["weight"] for item in checks if item["passed"])
    maximum = sum(item["weight"] for item in checks)
    attention_count = sum(not item["passed"] for item in checks)
    label = "ready" if score >= 90 else "attention" if score >= 65 else "action"
    safe_release = {
        "ready": bool(release.get("ready")),
        "version": str(release.get("version", "")),
        "minimum_supported_version": str(release.get("minimum_supported_version", "")),
        "published_at_utc": str(release.get("published_at_utc", "")),
        "package_filename": str(release.get("package_filename", "")),
        "size_bytes": int(release.get("size_bytes", 0) or 0),
        "sha256": str(release.get("sha256", "")),
        "signing_key_id": str(release.get("signing_key_id", "")),
        "checks": dict(release_checks),
    }
    return {
        "ok": True,
        "trust_schema_version": 1,
        "api_version": API_VERSION,
        "score": {"value": score, "maximum": maximum, "label": label, "attention_count": attention_count},
        "checks": checks,
        "service_status": service,
        "signed_release": safe_release,
        "storage": {
            "license_state": "persistent_configured" if license_persistent else "local_ephemeral",
            "audit_exports": "persistent_configured" if audit_persistent else "local_ephemeral",
            "private_license_fields_encrypted": True,
            "support_private_fields_encrypted": True,
        },
        "cryptography": [
            {"purpose": "Desktop file locking", "control": "AES-256-GCM with scrypt key derivation for portable .locked files"},
            {"purpose": "Signed desktop updates", "control": "Ed25519 manifest signature plus SHA-256 package digest"},
            {"purpose": "API licenses and receipts", "control": "HMAC-signed tokens with persistent revocation and anonymous seat ledgers"},
            {"purpose": "Private API records", "control": "AES-GCM encrypted private fields with server-side access controls"},
        ],
        "data_boundaries": {
            "stays_on_customer_pc": [
                "USB key bytes and owner policy",
                "Encryption PINs and local control PIN verifier",
                "Locked and unlocked file contents",
                "Personal Vault contents and full local paths",
                "Local Control Center browser session",
            ],
            "may_reach_api_after_explicit_action": [
                "Signed license proof and anonymous machine hash",
                "App version and coarse sync time",
                "Customer-written support text after review",
                "Approved privacy-safe audit fields after export confirmation",
            ],
            "never_requested_by_api": [
                "Passwords or keystrokes",
                "Encryption PINs or USB secrets",
                "File contents or full local paths",
                "Payment-card numbers",
                "Remote lock or unlock permission",
            ],
        },
        "recovery_steps": [
            "Keep the original .locked item unchanged and make a second copy before troubleshooting.",
            "Use the original master USB key and exact optional encryption PIN only in the desktop app.",
            "Complete a disposable-file recovery drill before relying on the workflow for important data.",
            "Keep a separate offline recovery copy and do not store the PIN beside the USB key.",
            "Use Microsoft Defender for current malware scanning; this trust report is not an antivirus result.",
        ],
        "limitations": [
            "This score is operational guidance, not a security certification, HIPAA certification, legal opinion, or guarantee.",
            "The public service cannot inspect a customer PC, confirm backups, test a USB key, or prove that recovery will succeed.",
            "A valid signed update proves package integrity and publisher-key possession, not that software is free of every possible defect.",
        ],
        "safe_to_export": True,
        "customer_records_included": False,
        "server_time_utc": utc_now(),
    }


def maintenance_guide_payload():
    """Return fixed maintenance guidance without receiving customer progress or PC data."""
    categories = fixed_maintenance_categories()
    tasks = fixed_maintenance_tasks()
    routines = fixed_maintenance_routines()
    planning_horizons = fixed_planning_horizons()
    release = windows_update_release_status()
    receipt_fields = [
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
    ]
    return {
        "ok": True,
        "maintenance_schema_version": 2,
        "api_version": API_VERSION,
        "service_status": service_status_payload(),
        "signed_release": {
            "ready": bool(release.get("ready")),
            "version": str(release.get("version", "")),
            "minimum_supported_version": str(release.get("minimum_supported_version", "")),
            "published_at_utc": str(release.get("published_at_utc", "")),
        },
        "categories": categories,
        "category_count": len(categories),
        "tasks": tasks,
        "task_count": len(tasks),
        "routines": routines,
        "routine_count": len(routines),
        "cadence_days": list(CADENCE_DAYS),
        "planning_horizons": planning_horizons,
        "planning_horizon_count": len(planning_horizons),
        "schedule_scoring": {
            "purpose": "reminder_coverage_only",
            "weights": dict(SCHEDULE_SCORE_WEIGHTS),
            "minimum": 0,
            "maximum": 100,
            "security_health_claim": False,
        },
        "browser_receipt_fields": receipt_fields,
        "browser_receipt_field_count": len(receipt_fields),
        "accepts_free_text": False,
        "accepts_files": False,
        "accepts_paths": False,
        "accepts_progress": False,
        "accepts_local_results": False,
        "accepts_completion_history": False,
        "accepts_reminders": False,
        "accepts_snapshots": False,
        "accepts_schedule_scores": False,
        "accepts_maintenance_commands": False,
        "remote_maintenance_allowed": False,
        "progress_storage": "current_browser_tab_only",
        "privacy_boundaries": [
            "The public maintenance API receives no license key, receipt, identity, machine identifier, key, PIN, USB secret, path, filename, file content, local result, completion time, reminder, or history.",
            "Browser review state stays only in the current tab and is not uploaded or written to browser storage.",
            "Desktop completion history and coarse schedule snapshots stay local and contain only fixed IDs, fixed cadence, coarse counts, state, UTC time, anonymous event IDs, and hash-chain fields.",
            "Trusted-tool launches are desktop-only and limited to fixed Windows pages, fixed VaultLink scripts, the fixed app folder, and fixed public pages.",
        ],
        "limitations": [
            "A reviewed or completed task is a reminder record, not proof that Windows, Defender, a backup, a key, an update, or recovery is healthy.",
            "Browser review percentages and desktop schedule scores measure reminder coverage only; they are not security-health, compliance, antivirus, backup, or recovery scores.",
            "The browser cannot inspect, scan, update, launch, schedule, complete, or control anything on a customer PC.",
            "VaultLink does not replace Microsoft Defender, Windows Update, independent backups, professional incident response, legal advice, or compliance review.",
        ],
        "customer_records_included": False,
        "server_time_utc": utc_now(),
    }


def retention_guide_payload():
    """Return fixed storage policy without receiving local inventory or cleanup state."""
    areas = fixed_retention_areas()
    practices = fixed_retention_practices()
    cleanup_flow = fixed_cleanup_flow()
    release = windows_update_release_status()
    policies = [
        {"id": "cleanup-eligible", "label": "Cleanup eligible"},
        {"id": "preserve", "label": "Preserve"},
        {"id": "source-center-only", "label": "Source center only"},
        {"id": "owner-only", "label": "Owner only"},
        {"id": "not-inventoried", "label": "Not inventoried"},
    ]
    receipt_fields = [
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
    ]
    return {
        "ok": True,
        "retention_schema_version": 1,
        "api_version": API_VERSION,
        "service_status": service_status_payload(),
        "signed_release": {
            "ready": bool(release.get("ready")),
            "version": str(release.get("version", "")),
            "minimum_supported_version": str(release.get("minimum_supported_version", "")),
            "published_at_utc": str(release.get("published_at_utc", "")),
        },
        "areas": areas,
        "area_count": len(areas),
        "policies": policies,
        "policy_count": len(policies),
        "practices": practices,
        "practice_count": len(practices),
        "cleanup_flow": cleanup_flow,
        "cleanup_step_count": len(cleanup_flow),
        "browser_receipt_fields": receipt_fields,
        "browser_receipt_field_count": len(receipt_fields),
        "accepts_free_text": False,
        "accepts_files": False,
        "accepts_paths": False,
        "accepts_inventory": False,
        "accepts_progress": False,
        "accepts_cleanup_commands": False,
        "accepts_local_results": False,
        "remote_cleanup_allowed": False,
        "progress_storage": "current_browser_tab_only",
        "privacy_boundaries": [
            "The public retention API receives no license key, receipt, identity, machine identifier, PIN, USB secret, path, filename, file content, local inventory, age, size, or cleanup result.",
            "Browser review state stays only in the current tab and is not uploaded or written to browser storage.",
            "Only the desktop app can preview the exact VaultLink temporary workspace, and it rejects links, junctions, metadata errors, and previews above 5,000 entries.",
            "Cleanup requires a fresh preview, explicit yes/no approval, exact CLEAN TEMP text, and immediate boundary and age revalidation.",
        ],
        "limitations": [
            "Retention guidance is not secure erasure, forensic destruction, antivirus scanning, certification, legal advice, or a recovery guarantee.",
            "The browser cannot inspect, clean, delete, move, inventory, or control anything on a customer PC.",
            "Audit, recovery, vault, license, owner, update rollback, locked, backup, and external customer data are outside retention cleanup.",
        ],
        "customer_records_included": False,
        "server_time_utc": utc_now(),
    }


def diagnostics_guide_payload():
    """Return fixed troubleshooting guidance without receiving customer data."""
    release = windows_update_release_status()
    categories = [
        {
            "id": "app-start",
            "title": "App will not open",
            "summary": "Check the transparent app folder, Python runtime, dependencies, duplicate processes, and Windows permissions.",
            "steps": [
                {"id": "start-complete-folder", "title": "Use the complete app folder", "action": "Keep every signed app file and Run launcher together in one normal folder.", "expected": "The launcher can find Ensure Dependencies.cmd and the selected Python script."},
                {"id": "start-dependencies", "title": "Run dependency setup", "action": "Open Ensure Dependencies.cmd while online and let its Python and cryptography checks finish.", "expected": "The setup reports a supported Python runtime and a successful cryptography import."},
                {"id": "start-duplicates", "title": "Close duplicate app copies", "action": "Close older VaultLink windows before opening the intended signed folder again.", "expected": "Only the intended app version remains open."},
                {"id": "start-permissions", "title": "Check normal Windows access", "action": "Confirm the current Windows user can read the app folder and write its own LocalAppData.", "expected": "Diagnostics reports normal app-data access without requiring administrator rights."},
                {"id": "start-report", "title": "Run local diagnostics", "action": "Open Diagnostics Center and export its privacy-safe report after reviewing it.", "expected": "The report identifies a failed runtime or storage check without including paths or secrets."},
            ],
            "escalation": "Send the reviewed privacy-safe diagnostic summary and the exact visible error text to the owner. Do not attach keys, PINs, receipts, or private files.",
        },
        {
            "id": "usb-key",
            "title": "USB key is not recognized",
            "summary": "Protect old locked files by locating the original key instead of creating a replacement.",
            "steps": [
                {"id": "usb-original", "title": "Reconnect the original USB", "action": "Use the same removable USB and master key that created the locked item.", "expected": "Windows assigns the drive and the existing master key file remains readable."},
                {"id": "usb-no-replacement", "title": "Do not replace the key", "action": "Do not create a new master key for files locked with a missing key.", "expected": "The original locked copy and recovery options remain unchanged."},
                {"id": "usb-load", "title": "Load the existing key", "action": "Choose LOAD USB KEY in the desktop app and select the existing master key.", "expected": "The app reports the key loaded without changing it."},
                {"id": "usb-policy", "title": "Verify owner USB policy", "action": "Use VERIFY OWNER USB to confirm the removable-drive policy matches.", "expected": "The owner policy accepts the currently connected removable USB."},
                {"id": "usb-inspector", "title": "Use Key Inspector", "action": "Open Key Inspector for a local read-only key and drive check.", "expected": "The inspector explains key readability and policy matching without uploading key material."},
            ],
            "escalation": "If the original USB is lost, preserve all .locked copies and every possible key backup. VaultLink cannot derive or remotely recover the missing secret.",
        },
        {
            "id": "unlock",
            "title": "A file will not unlock",
            "summary": "Work from a copy and verify the original key, exact optional PIN, lock format, and output location.",
            "steps": [
                {"id": "unlock-copy", "title": "Protect the locked original", "action": "Make a second copy of the .locked item before troubleshooting.", "expected": "An unchanged recovery copy remains available if another attempt fails."},
                {"id": "unlock-key-pin", "title": "Use the exact key and PIN", "action": "Load the original master key and type the optional PIN exactly, including capitalization.", "expected": "Authenticated decryption succeeds only with the original secret combination."},
                {"id": "unlock-format", "title": "Check the lock format", "action": "Use CHECK LOCK FORMAT or Vault Health Center before changing the file.", "expected": "The app identifies portable, legacy, or unreadable structure without decrypting contents."},
                {"id": "unlock-output", "title": "Choose a writable output folder", "action": "Use UNLOCK TO FOLDER and select a normal folder with sufficient free space.", "expected": "The output can be written without replacing the .locked source."},
                {"id": "unlock-test", "title": "Run a disposable recovery test", "action": "Test the same key and PIN workflow on disposable non-private data.", "expected": "A fresh lock and unlock round trip succeeds before retrying important data."},
            ],
            "escalation": "Preserve the failed item and safe report. Never upload file contents, the master key, or the PIN to the API or a support ticket.",
        },
        {
            "id": "licensing",
            "title": "License or rank is not updating",
            "summary": "Check time, public service state, the saved license, anonymous seats, and owner support without exposing the key.",
            "steps": [
                {"id": "license-clock", "title": "Synchronize Windows time", "action": "Enable automatic date, time, and time-zone settings in Windows.", "expected": "The local clock is within five minutes of the public service time."},
                {"id": "license-status", "title": "Check public service status", "action": "Open Customer Status and confirm licensing is not under maintenance.", "expected": "The public service mode and message are visible without a license key."},
                {"id": "license-refresh", "title": "Refresh License Center", "action": "Open License Center and verify the saved key from the licensed PC.", "expected": "The API returns a current active, limited, expired, or revoked decision."},
                {"id": "license-seats", "title": "Review anonymous seats", "action": "Check the active and maximum seat counts before activating another PC.", "expected": "An available anonymous device seat exists or an old seat is removed by the owner."},
                {"id": "license-support", "title": "Use Bug Center safely", "action": "Send the category, visible error, and safe diagnostic summary after reviewing them.", "expected": "The owner receives useful text without keys, receipts, machine identity, or files."},
            ],
            "escalation": "The owner can manage license state and anonymous seats but cannot remotely disable local unlock or recovery.",
        },
        {
            "id": "updates",
            "title": "Signed update will not install",
            "summary": "Check duplicate apps, disk space, the published manifest, package integrity, and rollback backup.",
            "steps": [
                {"id": "update-close", "title": "Close duplicate app windows", "action": "Close every older VaultLink window before starting the verified installer.", "expected": "No running app holds a file that the updater needs to replace."},
                {"id": "update-center", "title": "Use Update Center", "action": "Fetch the published release only through the signed Update Center workflow.", "expected": "The Ed25519 manifest identifies the expected version and package."},
                {"id": "update-space", "title": "Check working space", "action": "Keep at least 500 MB free for the package, extraction, and rollback copy.", "expected": "The diagnostics storage check passes before installation."},
                {"id": "update-integrity", "title": "Verify signature and hash", "action": "Require both the Ed25519 signature and SHA-256 package digest to pass.", "expected": "The downloaded ZIP exactly matches the signed manifest."},
                {"id": "update-backup", "title": "Keep the rollback backup", "action": "Do not remove the updater backup until the new app opens and recovery tools work.", "expected": "App files can be restored while LocalAppData keys, settings, and logs remain preserved."},
            ],
            "escalation": "Do not bypass Defender or signature warnings. Preserve the package name and safe verification result for owner review.",
        },
        {
            "id": "performance",
            "title": "The PC or app is slow",
            "summary": "Reduce duplicate work, identify the responsible process, use bounded scans, and keep Defender enabled.",
            "steps": [
                {"id": "performance-duplicates", "title": "Close duplicate VaultLink apps", "action": "Keep one copy of each needed app open and stop unused background windows.", "expected": "Duplicate Python processes no longer repeat the same scan or watcher."},
                {"id": "performance-task-manager", "title": "Check Task Manager", "action": "Sort Task Manager by CPU, memory, and disk while the slowdown happens.", "expected": "The responsible process and resource type are identified before anything is removed."},
                {"id": "performance-defender", "title": "Run Microsoft Defender", "action": "Update Defender and run a scan if an unknown process is consuming resources.", "expected": "Windows Defender supplies the malware verdict instead of filename guessing."},
                {"id": "performance-bounded", "title": "Use bounded scans", "action": "Cancel broad file scans when they are no longer needed and scan one intended folder at a time.", "expected": "VaultLink stops after the current item and resource use falls."},
                {"id": "performance-restart", "title": "Restart after saving work", "action": "Save work and restart Windows if a stopped process left memory or handles behind.", "expected": "The PC returns to normal idle usage before VaultLink is reopened."},
            ],
            "escalation": "Report the process name and coarse CPU, memory, and disk observations. Do not send memory dumps, private file lists, or credentials.",
        },
        {
            "id": "audit-security",
            "title": "Audit or security warning",
            "summary": "Preserve evidence, verify the hash chain, export only approved fields, scan with Defender, and review false-positive risk.",
            "steps": [
                {"id": "audit-preserve", "title": "Preserve the audit folder", "action": "Do not edit or delete audit records while investigating an integrity warning.", "expected": "The original chain remains available for verification."},
                {"id": "audit-verify", "title": "Verify the chain", "action": "Use Audit Log Viewer to locate the first failed sequence or signature check.", "expected": "The viewer reports a valid chain or a specific anonymous event ID."},
                {"id": "audit-export", "title": "Export approved fields only", "action": "Use the privacy-safe JSON export and inspect it before sharing.", "expected": "No filenames, paths, client names, keys, PINs, receipts, or file contents are included."},
                {"id": "audit-defender", "title": "Use Defender for malware verdicts", "action": "Scan the relevant signed app folder or installer with Microsoft Defender.", "expected": "A current Defender detection name or no-threat result is recorded."},
                {"id": "audit-review", "title": "Review evidence before removal", "action": "Treat High or Critical labels as review priorities, not automatic proof of malware.", "expected": "False positives are separated from confirmed detections before removal."},
            ],
            "escalation": "Send anonymous event IDs, timestamps, action names, results, and the exact Defender detection name. Never send raw private logs or file contents.",
        },
        {
            "id": "backup-recovery",
            "title": "Backup or recovery preparation",
            "summary": "Keep separate copies, verify the key, back up app data, practice on disposable data, and document custody safely.",
            "steps": [
                {"id": "backup-locked-copy", "title": "Keep an unchanged locked copy", "action": "Store a second copy of important .locked items before maintenance or recovery.", "expected": "At least one original encrypted copy remains untouched."},
                {"id": "backup-key-copy", "title": "Back up the master key separately", "action": "Use the built-in key backup and store it away from the primary PC and locked files.", "expected": "The copied key verifies against the loaded key without exposing its bytes."},
                {"id": "backup-app-data", "title": "Back up app data", "action": "Create an app-data backup containing settings and audit state but no master USB key files.", "expected": "The backup completes and records a successful privacy-safe audit event."},
                {"id": "backup-drill", "title": "Practice with disposable data", "action": "Complete a lock and unlock round trip using non-private disposable content.", "expected": "The original key and optional PIN recover the test copy successfully."},
                {"id": "backup-custody", "title": "Document custody without secrets", "action": "Record where recovery materials are stored without writing the PIN beside the USB key.", "expected": "A trusted adult or business owner understands the recovery process without receiving secrets unnecessarily."},
            ],
            "escalation": "If a backup fails, preserve every existing key and locked copy, stop destructive changes, and obtain qualified help before retrying important data.",
        },
    ]
    return {
        "ok": True,
        "diagnostics_schema_version": 1,
        "api_version": API_VERSION,
        "service_status": service_status_payload(),
        "signed_release": {
            "ready": bool(release.get("ready")),
            "version": str(release.get("version", "")),
            "minimum_supported_version": str(release.get("minimum_supported_version", "")),
            "published_at_utc": str(release.get("published_at_utc", "")),
        },
        "categories": categories,
        "category_count": len(categories),
        "step_count": sum(len(category["steps"]) for category in categories),
        "accepts_free_text": False,
        "accepts_files": False,
        "session_progress_storage": "current_browser_tab_only",
        "privacy_boundaries": [
            "The public diagnostics API receives no license key, receipt, machine identity, PIN, USB secret, path, filename, or file content.",
            "Browser checklist progress stays only in the current tab and is not uploaded or saved in browser storage.",
            "The desktop safe report contains coarse checks and public metadata only; the customer reviews it before export.",
            "Remote diagnostics cannot inspect, lock, unlock, scan, install, remove, or execute anything on a customer PC.",
        ],
        "limitations": [
            "Troubleshooting guidance is not an antivirus scan, certification, legal advice, or guarantee.",
            "The API cannot confirm local key custody, backup quality, Defender state, or successful recovery.",
            "Microsoft Defender and qualified human review remain necessary for malware and high-impact security decisions.",
        ],
        "customer_records_included": False,
        "server_time_utc": utc_now(),
    }


def incident_guide_payload():
    """Return fixed incident playbooks without receiving customer data."""
    release = windows_update_release_status()

    def step(identifier, title, action, expected):
        return {"id": identifier, "title": title, "action": action, "expected": expected}

    playbooks = [
        {
            "id": "defender-alert",
            "title": "Microsoft Defender alert",
            "summary": "Handle a Defender detection without rerunning, sharing, or manually deleting the suspicious item.",
            "steps": [
                step("alert-stop-repeat", "Do not run it again", "Close the related app and do not reopen, copy, or send the detected item.", "The item stays untouched while Windows Security handles it."),
                step("alert-history", "Read Protection History", "Record only the visible detection name, severity, action, and approximate time.", "Useful evidence exists without private file contents or full paths."),
                step("alert-update", "Update security intelligence", "Use Windows Security to check for current Microsoft Defender protection updates.", "The signature date is current before another scan."),
                step("alert-scan", "Run the recommended scan", "Run Quick scan, then Full or Defender Offline scan only when Windows Security recommends it.", "Windows Security finishes and displays its own result."),
                step("alert-accounts", "Protect important accounts", "If theft is possible, use another trusted device to change passwords and review sign-ins.", "New passwords are not entered on the potentially affected PC."),
                step("alert-escalate", "Escalate safely", "Ask a trusted adult or qualified technician to review unresolved alerts and a reviewed safe report.", "No key, PIN, private file, or malware sample is sent to support."),
            ],
            "escalation": "Keep the detected item quarantined. Seek qualified help for repeated alerts, disabled protection, or possible account theft.",
        },
        {
            "id": "account-risk",
            "title": "Possible account theft",
            "summary": "Secure online accounts from a different trusted device and preserve a minimal safe timeline.",
            "steps": [
                step("account-trusted-device", "Move to a trusted device", "Stop entering passwords on the possibly affected PC and use another updated device.", "Password changes happen away from the possibly affected PC."),
                step("account-passwords", "Change important passwords", "Start with email, password manager, banking, Steam, Discord, and reused passwords.", "Each important account has a unique new password."),
                step("account-sessions", "Sign out other sessions", "Use each provider security page to remove unknown sessions and remembered devices.", "Only recognized devices remain signed in."),
                step("account-mfa", "Review recovery and MFA", "Check recovery email, phone, passkeys, authenticators, and backup codes for unknown changes.", "Recovery methods belong only to the account owner."),
                step("account-email", "Review email rules", "Check forwarding, filters, sent mail, and deleted mail for changes you did not make.", "No unknown forwarding or mailbox rule remains."),
                step("account-timeline", "Save a safe timeline", "Record provider name, approximate time, and actions without passwords, codes, or tokens.", "A support-safe timeline is ready if more help is needed."),
            ],
            "escalation": "Contact the provider and a trusted adult immediately for financial loss, identity theft, or an account you cannot recover.",
        },
        {
            "id": "lost-usb",
            "title": "Lost or stolen master USB",
            "summary": "Protect existing locked files and recover with the matching backup key instead of making a replacement key.",
            "steps": [
                step("usb-preserve", "Preserve every locked file", "Do not rename, edit, delete, or overwrite existing .locked files.", "Original encrypted files remain unchanged."),
                step("usb-backup", "Locate the matching backup key", "Find the protected backup created from the original master key.", "The backup belongs to the original key, not a newly generated key."),
                step("usb-compare", "Compare the backup locally", "Use Key Inspector or Compare Backup Key without sharing the key file or secret.", "The app confirms the key matches locally."),
                step("usb-recover", "Test one disposable recovery copy", "Unlock a copied non-private item first and verify it before bulk recovery.", "The copied item unlocks correctly with the backup key and PIN."),
                step("usb-policy", "Retire the missing owner USB", "After recovery, update owner USB policy to the intended replacement removable drive.", "The missing drive no longer satisfies owner-only controls."),
                step("usb-new-backup", "Create and verify a new backup", "Store a verified backup separately from the PC and daily-use USB.", "A second tested recovery copy exists in a protected location."),
            ],
            "escalation": "A new key cannot unlock data encrypted by a lost key. Preserve all copies and seek qualified help if no matching backup exists.",
        },
        {
            "id": "unlock-failure",
            "title": "Locked file will not unlock",
            "summary": "Troubleshoot without changing the encrypted original or guessing with replacement keys.",
            "steps": [
                step("unlock-preserve", "Keep the original unchanged", "Work from a copy and leave the original .locked file in place.", "An unchanged recovery source remains available."),
                step("unlock-key", "Reconnect the original key", "Load the same master key used when the file was locked and check it locally.", "The selected key is readable and has the expected key ID."),
                step("unlock-pin", "Check the optional PIN", "Use the exact original PIN or leave it blank only if no PIN was used.", "The PIN choice matches the original lock operation."),
                step("unlock-health", "Run Vault Health Center", "Perform read-only structure and compatibility checks on a copy.", "The app reports whether the container structure is readable."),
                step("unlock-test", "Run a disposable round trip", "Lock and unlock a new non-private test file with the loaded key and intended PIN.", "The current key and PIN workflow succeeds on disposable data."),
                step("unlock-report", "Export a safe report", "Export Diagnostics or Vault Health totals and review them before asking for support.", "The report has no filename, path, key, PIN, or file contents."),
            ],
            "escalation": "Never delete or overwrite the only encrypted copy. Recovery requires the original matching key and optional PIN.",
        },
        {
            "id": "unknown-behavior",
            "title": "Unknown popups or PC behavior",
            "summary": "Reduce risk, use Windows Security, and avoid destructive guesses about normal applications.",
            "steps": [
                step("behavior-close", "Close the unknown window", "Do not approve prompts, enter passwords, or click links in an unexpected window.", "The prompt closes without granting access."),
                step("behavior-network", "Disconnect only during active access", "If unauthorized control or transfers are active, disconnect Wi-Fi or Ethernet while preserving PC state.", "Ongoing network access is interrupted without deleting evidence."),
                step("behavior-security", "Open Windows Security", "Review Protection History, update signatures, and run the recommended scan.", "Microsoft Defender supplies the detection result."),
                step("behavior-startup", "Review startup apps", "Note unfamiliar startup entries in Settings or Task Manager; do not delete solely because they are unfamiliar.", "Unknown entries are documented without damaging normal apps."),
                step("behavior-updates", "Install trusted updates", "Update Windows and known software through signed built-in updaters or official sources.", "Windows and known apps are current."),
                step("behavior-report", "Create a reviewed safe report", "Run Diagnostics Center and review the coarse results before export.", "No key, password, path, screenshot, or private content uploads automatically."),
            ],
            "escalation": "Use qualified help for persistent remote-control signs, disabled security tools, repeated detections, or financial risk.",
        },
        {
            "id": "update-integrity",
            "title": "Update or integrity problem",
            "summary": "Recover the transparent app folder while preserving keys, licenses, settings, audit logs, and locked data.",
            "steps": [
                step("update-close", "Close duplicate app copies", "Leave only the intended VaultLink folder open before retrying.", "No older app holds files needed by the updater."),
                step("update-preserve", "Preserve LocalAppData", "Do not delete the USBFileLocker app-data folder, keys, settings, logs, or locked files.", "Customer data stays available to the repaired app."),
                step("update-center", "Use Update Center", "Check the signed release through the configured VaultLink API.", "The release version and signing identity are visible."),
                step("update-verify", "Require both verification checks", "Install only when the Ed25519 signature and package SHA-256 verify.", "The updater accepts the exact signed package."),
                step("update-readiness", "Check space and clock", "Keep 500 MB free and enable automatic Windows date, time, and time zone.", "Diagnostics reports normal storage and service-time checks."),
                step("update-rollback", "Use the rollback copy", "If a verified update fails, restore only app files from the updater backup.", "App data remains untouched while prior app files return."),
            ],
            "escalation": "Do not bypass Defender or signature warnings. Send the visible error and reviewed safe diagnostics to the owner.",
        },
        {
            "id": "device-loss",
            "title": "Lost PC or major data loss",
            "summary": "Secure accounts and recover from separately stored keys and backups without exposing secrets online.",
            "steps": [
                step("device-account", "Secure the Windows account", "Use official Microsoft account device and sign-in pages from a trusted device.", "Unknown sign-ins are removed and the password changes if needed."),
                step("device-seat", "Deactivate the lost license seat", "Use Customer Center to remove the lost anonymous device seat.", "The lost installation stops receiving licensed premium access."),
                step("device-online", "Rotate important online accounts", "Change passwords and review sessions for accounts available on the lost PC.", "Only recognized devices and recovery methods remain."),
                step("device-copies", "Locate separate recovery copies", "Gather the matching key backup, app-data backup, and independent locked-file copies.", "Recovery materials come from protected separate locations."),
                step("device-restore", "Restore on a trusted replacement PC", "Install the transparent signed app, verify Defender, then test one disposable recovery copy.", "The replacement passes a safe recovery test before bulk work."),
                step("device-timeline", "Document a safe timeline", "Record approximate times, provider actions, and recovery results without secrets.", "A minimal reviewed record is available for support or insurance."),
            ],
            "escalation": "Contact law enforcement, providers, financial institutions, or a qualified professional when theft or identity exposure is involved.",
        },
        {
            "id": "phishing-message",
            "title": "Suspicious email, text, or link",
            "summary": "Contain a possible phishing attempt without opening attachments, signing in through the message, or forwarding private content.",
            "steps": [
                step("phishing-stop", "Stop interacting with the message", "Do not click links, open attachments, reply, call listed numbers, or enter information.", "The suspicious message receives no additional interaction."),
                step("phishing-close", "Close the page or attachment", "Close the message and any page it opened without downloading or running anything else.", "The suspicious content is no longer open."),
                step("phishing-provider", "Use the provider directly", "Open the official app or type the known official address yourself to check the claimed alert.", "Any real account notice is reviewed outside the suspicious message."),
                step("phishing-credentials", "Protect exposed credentials", "If a password or code was entered, use another trusted device to change it and end unknown sessions.", "The exposed credential is replaced and unknown sessions are removed."),
                step("phishing-report", "Report through trusted controls", "Use the provider's built-in report-phishing control.", "The provider receives the original report without forwarding it to other people."),
                step("phishing-scan", "Check downloads safely", "If anything downloaded or ran, leave it closed and use Microsoft Defender to scan and review Protection History.", "Windows Security supplies the scan result."),
            ],
            "escalation": "Contact the real provider, a trusted adult, or a qualified professional for money loss, identity exposure, or an account you cannot recover.",
        },
        {
            "id": "ransomware-warning",
            "title": "Ransomware warning or changed files",
            "summary": "Limit further damage, preserve evidence, and use trusted recovery paths without paying, rerunning, or renaming affected files.",
            "steps": [
                step("ransomware-isolate", "Disconnect the affected PC", "Disconnect Wi-Fi and Ethernet if files are actively changing or a ransom message is visible.", "The affected PC no longer reaches network shares or cloud sync."),
                step("ransomware-stop", "Do not pay or rerun anything", "Do not contact payment addresses, run alleged decryptors, or reopen the suspected program.", "No payment or additional untrusted code is introduced."),
                step("ransomware-preserve", "Preserve affected files", "Do not rename, edit, delete, or overwrite encrypted files, notes, or the only backup copies.", "Original evidence and recovery candidates remain unchanged."),
                step("ransomware-security", "Use Windows Security", "Review Protection History and follow Microsoft Defender recommendations, including Offline scan when offered.", "Windows Security completes its recommended response."),
                step("ransomware-backups", "Protect separate backups", "Keep disconnected backups and matching VaultLink keys offline until the affected PC is reviewed.", "Known-good recovery material is not exposed to the affected PC."),
                step("ransomware-help", "Get qualified recovery help", "Use a trusted adult, organization administrator, insurer, law enforcement contact, or qualified responder as appropriate.", "Recovery decisions are reviewed before restoring or reconnecting the PC."),
            ],
            "escalation": "Treat active encryption, financial demands, or sensitive records as urgent. Do not reconnect or restore until a qualified responder says it is safe.",
        },
        {
            "id": "exposed-secret",
            "title": "Password, PIN, or key was exposed",
            "summary": "Replace exposed online credentials and protect VaultLink recovery material without copying secrets into reports or support messages.",
            "steps": [
                step("secret-stop", "Stop sharing the secret", "Do not paste it into chat, email, screenshots, bug reports, or the incident export.", "No new copy of the secret is intentionally shared."),
                step("secret-scope", "Identify the secret type", "Classify it only as password, one-time code, recovery code, PIN, API token, or VaultLink key without recording the value.", "The correct replacement process can be chosen without storing the secret."),
                step("secret-rotate", "Replace online credentials", "From a trusted device, change exposed passwords or tokens and revoke unknown sessions or app access.", "The exposed online credential no longer grants access."),
                step("secret-mfa", "Review account recovery", "Check MFA, passkeys, backup codes, recovery email, and recovery phone for unauthorized changes.", "Only approved recovery methods remain."),
                step("secret-vault", "Handle VaultLink keys separately", "If a master-key file was copied, preserve locked data and use a verified re-lock migration plan.", "Encrypted originals remain available while future access is moved carefully."),
                step("secret-monitor", "Watch for follow-on activity", "Review provider security alerts, sign-ins, and financial activity without entering details into VaultLink.", "Unexpected activity is reported directly to the relevant provider."),
            ],
            "escalation": "Contact the provider and a trusted adult immediately for financial, identity, school, work, or healthcare exposure. VaultLink cannot remotely rotate secrets.",
        },
        {
            "id": "browser-change",
            "title": "Suspicious browser change",
            "summary": "Review unexpected extensions, redirects, notifications, and search changes without deleting normal browser data by guesswork.",
            "steps": [
                step("browser-close", "Close suspicious tabs", "Close unexpected login, support, prize, warning, or download tabs without approving prompts.", "The suspicious page is no longer active."),
                step("browser-extensions", "Review installed extensions", "Open the browser extension page and disable unfamiliar items while recording only displayed names.", "Unrecognized extensions stop running without exposing browsing data."),
                step("browser-notifications", "Review notification permission", "Remove notification access for sites you do not recognize in browser privacy settings.", "Unknown sites can no longer send browser notifications."),
                step("browser-search", "Restore browser settings", "Use built-in settings to review startup pages, search provider, downloads, and proxy settings.", "Expected browser settings are restored through normal controls."),
                step("browser-security", "Run Windows Security checks", "Update Microsoft Defender and run the recommended scan if a download or installer may have run.", "Windows Security supplies the local result."),
                step("browser-account", "Review browser sync", "From the official account security page, remove unknown synced devices and review recent sign-ins.", "Only recognized devices remain connected to browser sync."),
            ],
            "escalation": "Use qualified help when redirects return, settings cannot be restored, extensions reinstall, or account and financial activity is affected.",
        },
        {
            "id": "backup-failure",
            "title": "Backup or restore failure",
            "summary": "Protect the only good copies, verify key compatibility, and test recovery on disposable data before bulk restoration.",
            "steps": [
                step("backup-stop", "Stop overwriting backups", "Pause backup or sync jobs that may replace known-good copies with damaged or incomplete data.", "Existing recovery copies remain unchanged."),
                step("backup-inventory", "Count recovery sources", "Identify separate app-data backups, locked-file copies, and matching key backups without listing names or paths.", "You know how many independent recovery sources exist."),
                step("backup-health", "Check storage health", "Use Windows drive error checking and Vault Health read-only checks before writing to the recovery drive.", "Basic storage and container checks finish without changing originals."),
                step("backup-key", "Verify the matching key", "Use Key Inspector or Compare Backup Key locally and never upload the key file.", "The recovery key matches the expected key ID and secret."),
                step("backup-test", "Restore one disposable copy", "Copy one non-private test item separately and verify its full lock-unlock round trip.", "The tested copy opens correctly before any bulk restore."),
                step("backup-record", "Record a recovery result", "Save only coarse totals, dates, and pass or fail status in the reviewed safe report.", "The record has no filenames, paths, keys, PINs, or contents."),
            ],
            "escalation": "Stop when drives disconnect, make unusual sounds, report hardware errors, or contain the only copy. Use qualified recovery help before further writes.",
        },
    ]
    return {
        "ok": True,
        "incident_schema_version": 1,
        "api_version": API_VERSION,
        "service_status": service_status_payload(),
        "signed_release": {
            "ready": bool(release.get("ready")),
            "version": str(release.get("version", "")),
            "minimum_supported_version": str(release.get("minimum_supported_version", "")),
        },
        "playbooks": playbooks,
        "playbook_count": len(playbooks),
        "step_count": sum(len(playbook["steps"]) for playbook in playbooks),
        "accepts_free_text": False,
        "accepts_files": False,
        "session_progress_storage": "current_browser_tab_only",
        "customer_records_included": False,
        "privacy_boundaries": [
            "The public incident API receives no license key, receipt, identity, PIN, USB secret, path, filename, screenshot, process list, or file content.",
            "Checklist progress stays only in the current tab and is not uploaded or saved in browser storage.",
            "The desktop readiness report contains coarse checks and public metadata only; the customer reviews it before export.",
            "Remote incident guidance cannot inspect, quarantine, delete, unlock, scan, install, remove, or control a customer PC.",
        ],
        "limitations": [
            "Incident guidance is not malware removal, certification, legal advice, emergency service, or a guarantee of recovery.",
            "The API cannot confirm local Defender state, key custody, account compromise, backup quality, or successful recovery.",
            "Microsoft Defender, account providers, trusted adults, and qualified human review remain necessary for high-impact decisions.",
        ],
        "server_time_utc": utc_now(),
    }


def recovery_drill_guide_payload():
    """Return the fixed recovery catalog without receiving customer progress or history."""
    release = windows_update_release_status()
    drills = fixed_recovery_drills()
    return {
        "ok": True,
        "recovery_drill_schema_version": 1,
        "api_version": API_VERSION,
        "service_status": service_status_payload(),
        "signed_release": {
            "ready": bool(release.get("ready")),
            "version": str(release.get("version", "")),
            "minimum_supported_version": str(release.get("minimum_supported_version", "")),
        },
        "drills": drills,
        "drill_count": len(drills),
        "step_count": sum(len(drill["steps"]) for drill in drills),
        "categories": sorted({drill["category"] for drill in drills}),
        "accepts_free_text": False,
        "accepts_files": False,
        "accepts_progress": False,
        "session_progress_storage": "current_browser_tab_only",
        "desktop_history_storage": "local_hash_chained_coarse_results_only",
        "customer_records_included": False,
        "privacy_boundaries": [
            "The public recovery API receives no license key, receipt, identity, machine identity, PIN, USB secret, path, filename, screenshot, process list, file content, local readiness result, drill progress, or history.",
            "Browser progress stays only in the current tab and is not uploaded or saved in browser storage.",
            "Desktop history stores only fixed drill IDs, timestamps, completion totals, readiness scores, and hash-chain fields in the current Windows user's LocalAppData.",
            "Recovery drills cannot inspect, lock, unlock, scan, install, remove, quarantine, or remotely control a customer PC.",
        ],
        "limitations": [
            "A completed drill is preparation, not proof that every backup, key, device, account, or future recovery attempt will succeed.",
            "Ransomware exercises are tabletop guidance only; never run malware, suspicious code, destructive scripts, or file-encryption simulations for training.",
            "Microsoft Defender, account providers, trusted adults, qualified responders, and storage-recovery professionals remain necessary for high-impact decisions.",
        ],
        "server_time_utc": utc_now(),
    }


def backup_verification_guide_payload():
    """Return fixed backup plans without receiving customer files, paths, progress, or checkpoints."""
    release = windows_update_release_status()
    plans = fixed_backup_plans()
    objectives = fixed_restore_objectives()
    return {
        "ok": True,
        "backup_verification_schema_version": 1,
        "api_version": API_VERSION,
        "service_status": service_status_payload(),
        "signed_release": {
            "ready": bool(release.get("ready")),
            "version": str(release.get("version", "")),
            "minimum_supported_version": str(release.get("minimum_supported_version", "")),
        },
        "plans": plans,
        "plan_count": len(plans),
        "step_count": sum(len(plan["steps"]) for plan in plans),
        "categories": sorted({plan["category"] for plan in plans}),
        "restore_objectives": objectives,
        "copy_targets": [1, 2, 3, 4, 5],
        "accepts_free_text": False,
        "accepts_files": False,
        "accepts_paths": False,
        "accepts_progress": False,
        "session_progress_storage": "current_browser_tab_only",
        "desktop_checkpoint_storage": "local_hash_chained_fixed_ids_and_coarse_totals_only",
        "customer_records_included": False,
        "privacy_boundaries": [
            "The public backup API receives no license key, receipt, identity, machine identity, PIN, USB secret, backup path, filename, screenshot, process list, file content, local readiness result, progress, or checkpoint history.",
            "Browser progress stays only in the current tab and is not uploaded or saved in browser storage.",
            "Desktop checkpoints store only fixed plan, check, and objective IDs; coarse totals and scores; copy target; timestamps; and hash-chain fields in the current Windows user's LocalAppData.",
            "Backup Verification cannot inspect arbitrary files, unlock data, delete originals, attach backups, scan a remote PC, or remotely control a customer device.",
        ],
        "limitations": [
            "A recognized backup folder, completed plan, or passing readiness score cannot guarantee that every future restore will succeed.",
            "Ransomware planning is tabletop guidance only; never run malware, suspicious code, destructive scripts, or file-encryption simulations.",
            "Microsoft Defender, trusted adults, qualified responders, and storage-recovery professionals remain necessary for high-impact decisions.",
        ],
        "server_time_utc": utc_now(),
    }


def recovery_kit_guide_payload():
    """Return fixed emergency-kit content without receiving customer identity, files, secrets, or progress."""
    release = windows_update_release_status()
    profiles = fixed_recovery_kit_profiles()
    sections = fixed_recovery_kit_sections()
    runbooks = fixed_emergency_runbooks()
    return {
        "ok": True,
        "recovery_kit_schema_version": 1,
        "api_version": API_VERSION,
        "service_status": service_status_payload(),
        "signed_release": {
            "ready": bool(release.get("ready")),
            "version": str(release.get("version", "")),
            "minimum_supported_version": str(release.get("minimum_supported_version", "")),
        },
        "profiles": profiles,
        "profile_count": len(profiles),
        "sections": sections,
        "section_count": len(sections),
        "item_count": sum(len(section["items"]) for section in sections),
        "categories": sorted({section["category"] for section in sections}),
        "runbooks": runbooks,
        "runbook_count": len(runbooks),
        "runbook_step_count": sum(len(runbook["steps"]) for runbook in runbooks),
        "review_intervals": [7, 14, 30, 60, 90],
        "accepts_free_text": False,
        "accepts_files": False,
        "accepts_paths": False,
        "accepts_progress": False,
        "accepts_contacts": False,
        "session_progress_storage": "current_browser_tab_only",
        "desktop_snapshot_storage": "local_hash_chained_fixed_ids_scores_totals_interval_and_time_only",
        "customer_records_included": False,
        "privacy_boundaries": [
            "The public Recovery Kit API receives no name, contact, license proof, receipt, identity, machine identity, key, PIN, USB secret, path, filename, screenshot, process list, file content, local result, progress, calendar data, or snapshot history.",
            "Browser progress stays only in the current tab and is not uploaded or saved in browser storage.",
            "Desktop snapshots store only fixed profile, runbook, item, and check IDs; coarse totals and scores; interval; UTC time; event ID; and hash-chain fields in the current Windows user's LocalAppData.",
            "Recovery Kit cannot inspect a PC, verify a real backup, unlock files, read arbitrary documents, attach logs, run commands remotely, or disable local recovery.",
        ],
        "limitations": [
            "A completed kit or passing readiness score cannot guarantee that every future recovery will succeed.",
            "Suspected-malware guidance is defensive and tabletop only; VaultLink never runs malware, suspicious code, destructive scripts, or file-encryption simulations.",
            "Microsoft Defender, trusted adults, qualified responders, and independent tested backups remain necessary for high-impact decisions.",
        ],
        "server_time_utc": utc_now(),
    }


def data_control_map_payload():
    """Return a fixed public data map without receiving a customer inventory, file, path, or review state."""
    release = windows_update_release_status()
    scopes = fixed_data_scopes()
    data_classes = fixed_data_classes()
    flow_steps = fixed_data_flow_steps()
    return {
        "ok": True,
        "data_control_schema_version": 1,
        "api_version": API_VERSION,
        "service_status": service_status_payload(),
        "signed_release": {
            "ready": bool(release.get("ready")),
            "version": str(release.get("version", "")),
            "minimum_supported_version": str(release.get("minimum_supported_version", "")),
        },
        "scopes": scopes,
        "scope_count": len(scopes),
        "data_classes": data_classes,
        "class_count": len(data_classes),
        "flow_steps": flow_steps,
        "flow_step_count": len(flow_steps),
        "receipt_schema_fields": [
            "schema_version",
            "report_type",
            "generated_at_utc",
            "api_version",
            "service_mode",
            "signed_desktop_version",
            "selected_scope_id",
            "reviewed_class_ids",
            "reviewed_count",
            "class_count",
            "privacy_notice",
        ],
        "accepts_free_text": False,
        "accepts_files": False,
        "accepts_paths": False,
        "accepts_inventory": False,
        "accepts_progress": False,
        "accepts_contacts": False,
        "session_progress_storage": "current_browser_tab_only",
        "desktop_inventory_boundary": "exact_known_vaultlink_app_data_metadata_only",
        "customer_records_included": False,
        "privacy_boundaries": [
            "The public Data Control API receives no name, contact, license proof, receipt, identity, machine identity, key, PIN, USB secret, path, filename, file content, local inventory, storage total, screenshot, process list, review progress, or privacy receipt.",
            "Browser review progress stays only in the current tab and is not uploaded or saved in browser storage.",
            "The desktop companion reads bounded metadata only from exact known VaultLink app-data sources and reports coarse bands; it never searches Downloads, Documents, removable drives, locked-container locations, or arbitrary backup folders.",
            "Desktop privacy receipts store only fixed class IDs, fixed state and coarse band values, fixed passed-check IDs, score, totals, UTC time, anonymous event ID, and hash-chain fields.",
        ],
        "limitations": [
            "Even coarse category presence can be sensitive, so every local export should be reviewed before sharing.",
            "The data map cannot prove that every backup, USB key, locked container, server record, or deleted copy has been discovered or is recoverable.",
            "Data Control is not forensic discovery, legal advice, compliance certification, or a replacement for independent security and privacy review.",
        ],
        "server_time_utc": utc_now(),
    }


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
            "below_minimum_installs_verified_update": True,
            "waits_for_active_local_task": True,
            "recovery_remains_available_on_failure": True,
        },
        "server_time_utc": utc_now(),
    }


def update_version_parts(value):
    text = str(value or "").strip()
    if not text or len(text) > 40 or any(part == "" or not part.isdigit() for part in text.split(".")):
        raise ValueError("installed_version must contain only dot-separated numbers and be 40 characters or fewer.")
    return text, tuple(int(part) for part in text.split("."))


def compare_update_versions(left, right):
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    return (padded_left > padded_right) - (padded_left < padded_right)


def check_windows_update(payload):
    installed_version, installed_parts = update_version_parts(payload.get("installed_version"))
    try:
        manifest, _package_path = load_windows_update_release()
    except (FileNotFoundError, OSError, ValueError) as exc:
        return {
            "ok": True,
            "published": False,
            "status": "unavailable",
            "installed_version": installed_version,
            "message": str(exc),
            "server_time_utc": utc_now(),
            "stored": False,
            "privacy_notice": "The entered version is evaluated for this response and is not stored.",
        }

    latest_version, latest_parts = update_version_parts(manifest["version"])
    minimum_version, minimum_parts = update_version_parts(manifest["minimum_supported_version"])
    latest_comparison = compare_update_versions(installed_parts, latest_parts)
    minimum_comparison = compare_update_versions(installed_parts, minimum_parts)
    if minimum_comparison < 0:
        status = "required"
        message = f"Installed version {installed_version} is below the supported minimum {minimum_version}."
    elif latest_comparison < 0:
        status = "available"
        message = f"Signed update {latest_version} is available for installed version {installed_version}."
    elif latest_comparison == 0:
        status = "current"
        message = f"Installed version {installed_version} matches the latest signed release."
    else:
        status = "ahead"
        message = f"Installed version {installed_version} is newer than published release {latest_version}."
    return {
        "ok": True,
        "published": True,
        "status": status,
        "message": message,
        "installed_version": installed_version,
        "latest_version": latest_version,
        "minimum_supported_version": minimum_version,
        "supported": minimum_comparison >= 0,
        "update_available": latest_comparison < 0,
        "update_required": minimum_comparison < 0,
        "download_recommended": latest_comparison < 0,
        "release": {
            "published_at_utc": manifest["published_at_utc"],
            "package_filename": manifest["package_filename"],
            "download_path": manifest["download_path"],
            "sha256": manifest["sha256"],
            "size_bytes": manifest["size_bytes"],
            "notes": list(manifest["notes"]),
            "manifest_signature": "Ed25519",
            "package_integrity": "SHA-256",
            "preserves_local_app_data": True,
        },
        "server_time_utc": utc_now(),
        "stored": False,
        "privacy_notice": (
            "The entered version is evaluated for this response and is not stored. No license key, identity, "
            "device identifier, path, file, PIN, USB secret, or file content is requested."
        ),
    }


def recovery_readiness_check(payload):
    allowed = {item["id"] for item in READINESS_CHECKS}
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise ValueError(f"Unknown readiness field: {unknown[0]}.")
    missing = sorted(allowed - set(payload))
    if missing:
        raise ValueError(f"Missing readiness field: {missing[0]}.")
    for field in allowed:
        if type(payload.get(field)) is not bool:
            raise ValueError(f"{field} must be true or false.")

    items = []
    score = 0
    critical_missing = []
    actions = []
    for check in READINESS_CHECKS:
        complete = payload[check["id"]]
        if complete:
            score += check["weight"]
        else:
            actions.append(
                {
                    "check_id": check["id"],
                    "priority": "critical" if check["critical"] else "recommended",
                    "action": check["action"],
                }
            )
            if check["critical"]:
                critical_missing.append(check["id"])
        items.append(
            {
                "id": check["id"],
                "label": check["label"],
                "weight": check["weight"],
                "critical": check["critical"],
                "complete": complete,
            }
        )

    if critical_missing:
        status = "blocked"
        headline = "Do not lock important data yet."
    elif score < 80:
        status = "action"
        headline = "Complete more recovery preparation before important use."
    elif score < 100:
        status = "review"
        headline = "Critical recovery checks pass; finish the remaining preparation."
    else:
        status = "ready"
        headline = "All self-reported readiness checks pass."
    actions.sort(key=lambda item: (item["priority"] != "critical", item["check_id"]))
    return {
        "ok": True,
        "status": status,
        "headline": headline,
        "score": score,
        "maximum_score": 100,
        "completed_count": sum(item["complete"] for item in items),
        "total_count": len(items),
        "critical_missing_count": len(critical_missing),
        "ready_for_important_data": status in {"review", "ready"},
        "items": items,
        "actions": actions,
        "stored": False,
        "server_time_utc": utc_now(),
        "limitations": [
            "This score is based only on the boxes selected by the customer.",
            "It does not inspect the PC, test a key, verify a backup, run antivirus, or guarantee recovery.",
            "Use a disposable non-private test file before locking important data.",
        ],
        "privacy_notice": (
            "Readiness Check accepts only seven true-or-false fields and stores nothing. It does not accept "
            "names, paths, keys, PINs, USB secrets, file contents, machine identifiers, or account data."
        ),
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
        <a href="/account">Customer Account</a>
        <a href="/customer">Customer License Center</a>
        <a href="/update">Update Center</a>
        <a href="/readiness">Recovery Readiness</a>
        <a href="/status">Customer Status</a>
        <a href="/terms">Draft Terms</a>
        <a href="/privacy">Privacy Notice</a>
        <a href="/docs">Open Route Index</a>
        <a href="/owner">Owner Console</a>
        <a href="/owner/accounts">Owner Accounts</a>
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
  <header><div><strong>VaultLink</strong><nav><a href="/">HOME</a> &nbsp; <a href="/maintenance">MAINTENANCE</a> &nbsp; <a href="/retention">RETENTION</a> &nbsp; <a href="/data-control">DATA</a> &nbsp; <a href="/recovery-kit">KIT</a> &nbsp; <a href="/backup-verification">BACKUPS</a> &nbsp; <a href="/recovery-drills">DRILLS</a> &nbsp; <a href="/incident-response">INCIDENT</a> &nbsp; <a href="/diagnostics">DIAGNOSTICS</a> &nbsp; <a href="/trust">TRUST</a> &nbsp; <a href="/update">UPDATE</a> &nbsp; <a href="/readiness">READINESS</a> &nbsp; <a href="/shop">SHOP</a> &nbsp; <a href="/terms">TERMS</a> &nbsp; <a href="/privacy">PRIVACY</a></nav></div></header>
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


def update_center_html():
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VaultLink Update Center</title>
  <style>
    :root { --bg:#0f1216; --surface:#171c22; --surface2:#202731; --line:#34404c; --text:#f4f7f8; --muted:#aeb9c4; --green:#69df8a; --blue:#69bce8; --yellow:#ffd166; --red:#ff8278; }
    * { box-sizing:border-box; }
    body { margin:0; min-width:0; background:var(--bg); color:var(--text); font-family:"Segoe UI",Arial,sans-serif; }
    header { border-bottom:1px solid var(--line); background:#14181d; }
    header > div, main, footer > div { width:min(980px,calc(100% - 32px)); margin:0 auto; }
    header > div { min-height:68px; display:flex; align-items:center; justify-content:space-between; gap:16px; }
    .brand { font-weight:800; }
    nav { display:flex; gap:8px; flex-wrap:wrap; }
    nav a { color:var(--text); text-decoration:none; border:1px solid var(--line); border-radius:6px; padding:8px 11px; }
    main { padding:34px 0 52px; }
    .top { display:grid; grid-template-columns:minmax(0,1.15fr) minmax(300px,.85fr); gap:18px; align-items:start; }
    h1 { margin:0; font-size:clamp(2rem,5vw,3.5rem); line-height:1.04; letter-spacing:0; }
    .lead { color:var(--muted); line-height:1.55; max-width:650px; }
    .privacy { margin-top:16px; padding:13px 14px; border-left:4px solid var(--blue); background:#171e25; color:var(--muted); line-height:1.45; }
    .panel { padding:18px; background:var(--surface); border:1px solid var(--line); border-radius:8px; }
    label { display:block; margin-bottom:7px; color:var(--muted); font-size:.75rem; font-weight:800; text-transform:uppercase; }
    input { width:100%; min-width:0; height:44px; padding:0 12px; border:1px solid var(--line); border-radius:5px; background:#0d1116; color:var(--text); font:inherit; }
    .actions { display:grid; grid-template-columns:1fr auto; gap:9px; margin-top:10px; }
    button { min-height:42px; border:0; border-radius:5px; padding:0 14px; font-weight:800; cursor:pointer; }
    #check { background:var(--green); color:#061109; }
    #clear { background:var(--surface2); color:var(--text); border:1px solid var(--line); }
    #status { min-height:23px; margin-top:12px; color:var(--muted); line-height:1.4; }
    #status.good { color:var(--green); } #status.warn { color:var(--yellow); } #status.bad { color:var(--red); }
    #result { margin-top:20px; }
    .empty { padding:30px 18px; border:1px dashed var(--line); border-radius:8px; color:var(--muted); text-align:center; }
    .summary { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); border:1px solid var(--line); border-radius:8px; overflow:hidden; }
    .summary > div { min-width:0; padding:17px; background:var(--surface); border-right:1px solid var(--line); }
    .summary > div:last-child { border-right:0; }
    .eyebrow { color:var(--muted); font-size:.72rem; font-weight:800; text-transform:uppercase; }
    .value { margin-top:6px; font-size:1.05rem; font-weight:800; overflow-wrap:anywhere; }
    .value.current { color:var(--green); } .value.available { color:var(--yellow); } .value.required { color:var(--red); } .value.ahead { color:var(--blue); }
    .message { margin-top:12px; padding:14px; background:#181f26; border-left:4px solid var(--blue); color:var(--muted); line-height:1.5; }
    .toolbar { display:flex; gap:8px; flex-wrap:wrap; margin-top:12px; }
    .toolbar button,.toolbar a { display:inline-flex; align-items:center; justify-content:center; min-height:40px; padding:0 12px; border-radius:5px; background:var(--surface2); border:1px solid var(--line); color:var(--text); text-decoration:none; font-size:.78rem; font-weight:800; }
    .toolbar .primary { background:var(--blue); border-color:var(--blue); color:#071119; }
    .release-grid { display:grid; grid-template-columns:minmax(0,1.1fr) minmax(280px,.9fr); gap:14px; margin-top:16px; }
    .release-grid > section { min-width:0; padding:18px; border:1px solid var(--line); border-radius:8px; background:var(--surface); }
    h2 { margin:0 0 11px; font-size:1rem; }
    ul { margin:0; padding-left:19px; color:var(--muted); line-height:1.6; }
    .verify-copy { margin:0 0 12px; color:var(--muted); line-height:1.5; }
    .verify-file { display:flex; align-items:center; justify-content:center; min-height:40px; padding:0 11px; border:1px solid var(--line); border-radius:5px; background:var(--surface2); color:var(--text); font-size:.78rem; font-weight:800; cursor:pointer; }
    .verify-file input { display:none; }
    .verify-status { min-height:22px; margin-top:10px; color:var(--muted); line-height:1.45; overflow-wrap:anywhere; }
    .verify-status.good { color:var(--green); } .verify-status.bad { color:var(--red); } .verify-status.warn { color:var(--yellow); }
    footer { border-top:1px solid var(--line); background:#14181d; }
    footer > div { padding:23px 0 30px; color:var(--muted); line-height:1.5; }
    @media(max-width:760px) { .top,.release-grid { grid-template-columns:1fr; } .summary { grid-template-columns:1fr 1fr; } .summary > div:nth-child(2) { border-right:0; } .summary > div:nth-child(-n+2) { border-bottom:1px solid var(--line); } }
    @media(max-width:480px) { header > div { align-items:flex-start; flex-direction:column; padding:14px 0; } .summary { grid-template-columns:1fr; } .summary > div { border-right:0; border-bottom:1px solid var(--line)!important; } .summary > div:last-child { border-bottom:0!important; } .actions { grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <header><div><div class="brand">VaultLink Update Center</div><nav><a href="/">HOME</a><a href="/maintenance">MAINTENANCE</a><a href="/retention">RETENTION</a><a href="/data-control">DATA</a><a href="/recovery-kit">KIT</a><a href="/backup-verification">BACKUPS</a><a href="/recovery-drills">DRILLS</a><a href="/diagnostics">DIAGNOSTICS</a><a href="/trust">TRUST</a><a href="/readiness">READINESS</a><a href="/customer">LICENSE</a><a href="/status">STATUS</a><a href="/privacy">PRIVACY</a></nav></div></header>
  <main>
    <div class="top">
      <section>
        <h1>Update Center</h1>
        <p class="lead">Check whether your Windows app version is current, supported, or needs the latest signed release.</p>
        <div class="privacy">The version is checked once and is not stored. Selected ZIP files are hashed locally in this browser and are never uploaded.</div>
      </section>
      <section class="panel">
        <label for="installedVersion">Installed app version</label>
        <input id="installedVersion" autocomplete="off" spellcheck="false" maxlength="40" placeholder="Example: 2026.07.12.9">
        <div class="actions"><button id="check" type="button">CHECK UPDATE</button><button id="clear" type="button">CLEAR</button></div>
        <div id="status" role="status" aria-live="polite">Not checked.</div>
      </section>
    </div>
    <div id="result"><div class="empty">Update compatibility information will appear here.</div></div>
  </main>
  <footer><div>Update Center cannot install software, inspect your PC, read files, or change local settings. API version __API_VERSION__.</div></footer>
  <script>
    const $=(id)=>document.getElementById(id);
    const state={payload:null};
    function setStatus(message,tone="") { const node=$("status"); node.textContent=message; node.className=tone; }
    function safeReport() { if (!state.payload) return null; const value=state.payload; return {exported_at_utc:new Date().toISOString(),status:value.status,message:value.message,installed_version:value.installed_version,latest_version:value.latest_version,minimum_supported_version:value.minimum_supported_version,supported:value.supported,update_available:value.update_available,update_required:value.update_required,release:value.release,privacy_notice:value.privacy_notice}; }
    async function copyReport() { const report=safeReport(); if (!report) return; const lines=["VaultLink Update Check",`Status: ${report.status}`,`Installed: ${report.installed_version}`,`Latest: ${report.latest_version || "Not published"}`,`Minimum supported: ${report.minimum_supported_version || "Not published"}`,report.message]; try { await navigator.clipboard.writeText(lines.join("\\n")); setStatus("Privacy-safe update report copied.","good"); } catch (_) { setStatus("Browser clipboard access was blocked.","bad"); } }
    function exportReport() { const report=safeReport(); if (!report) return; const blob=new Blob([JSON.stringify(report,null,2)],{type:"application/json"}); const url=URL.createObjectURL(blob); const link=document.createElement("a"); link.href=url; link.download="vaultlink-update-check.json"; document.body.append(link); link.click(); link.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000); setStatus("Privacy-safe update report exported.","good"); }
    async function verifyUpdateFile(file) {
      const output=$("verifyStatus"); if (!file || !state.payload?.release) return;
      const release=state.payload.release; output.className="verify-status";
      if (file.size>1024*1024*1024) { output.textContent="Choose an update package no larger than 1 GB."; output.classList.add("bad"); return; }
      if (release.size_bytes && file.size!==release.size_bytes) { output.textContent=`SIZE MISMATCH: selected ${file.size} bytes; expected ${release.size_bytes} bytes.`; output.classList.add("bad"); return; }
      output.textContent="Hashing selected file locally...";
      try { const digest=await crypto.subtle.digest("SHA-256",await file.arrayBuffer()); const actual=[...new Uint8Array(digest)].map((value)=>value.toString(16).padStart(2,"0")).join(""); if (actual.toLowerCase()===String(release.sha256).toLowerCase()) { output.textContent=`MATCH: SHA-256 verified for ${file.name}.`; output.classList.add("good"); } else { output.textContent=`MISMATCH: do not install ${file.name}.`; output.classList.add("bad"); } }
      catch (_) { output.textContent="The browser could not verify this file."; output.classList.add("bad"); }
      finally { const input=$("updateFile"); if (input) input.value=""; }
    }
    function render(payload) {
      const root=$("result"); root.replaceChildren();
      if (!payload.published) { const empty=document.createElement("div"); empty.className="empty"; empty.textContent=payload.message || "No signed update is published."; root.append(empty); return; }
      const summary=document.createElement("div"); summary.className="summary";
      [["Status",payload.status],["Installed",payload.installed_version],["Latest",payload.latest_version],["Minimum supported",payload.minimum_supported_version]].forEach(([label,value],index)=>{ const cell=document.createElement("div"); const key=document.createElement("div"); key.className="eyebrow"; key.textContent=label; const data=document.createElement("div"); data.className=`value${index===0?` ${payload.status}`:""}`; data.textContent=value; cell.append(key,data); summary.append(cell); });
      const message=document.createElement("div"); message.className="message"; message.textContent=payload.message;
      const toolbar=document.createElement("div"); toolbar.className="toolbar";
      const copy=document.createElement("button"); copy.type="button"; copy.textContent="COPY REPORT"; copy.addEventListener("click",copyReport);
      const exportButton=document.createElement("button"); exportButton.type="button"; exportButton.textContent="EXPORT JSON"; exportButton.addEventListener("click",exportReport);
      toolbar.append(copy,exportButton);
      if (payload.download_recommended) { const download=document.createElement("a"); download.className="primary"; download.href=payload.release.download_path; download.textContent="DOWNLOAD SIGNED UPDATE"; toolbar.append(download); }
      const grid=document.createElement("div"); grid.className="release-grid";
      const notes=document.createElement("section"); const notesTitle=document.createElement("h2"); notesTitle.textContent="Signed Release Notes"; const list=document.createElement("ul"); payload.release.notes.forEach((note)=>{ const item=document.createElement("li"); item.textContent=note; list.append(item); }); notes.append(notesTitle,list);
      const verify=document.createElement("section"); const verifyTitle=document.createElement("h2"); verifyTitle.textContent="Local ZIP Verifier"; const verifyCopy=document.createElement("p"); verifyCopy.className="verify-copy"; verifyCopy.textContent=`Expected ${payload.release.package_filename}. This file stays on your device.`; const fileLabel=document.createElement("label"); fileLabel.className="verify-file"; fileLabel.textContent="CHOOSE UPDATE ZIP"; const fileInput=document.createElement("input"); fileInput.id="updateFile"; fileInput.type="file"; fileInput.accept="application/zip,.zip"; fileInput.addEventListener("change",()=>verifyUpdateFile(fileInput.files?.[0])); fileLabel.append(fileInput); const verifyStatus=document.createElement("div"); verifyStatus.id="verifyStatus"; verifyStatus.className="verify-status"; verifyStatus.textContent=`Expected SHA-256: ${payload.release.sha256}`; verify.append(verifyTitle,verifyCopy,fileLabel,verifyStatus); grid.append(notes,verify);
      root.append(summary,message,toolbar,grid);
    }
    async function checkUpdate() {
      const installedVersion=$("installedVersion").value.trim(); if (!installedVersion) return setStatus("Enter the installed app version.","warn");
      $("check").disabled=true; setStatus("Checking signed release...");
      try { const response=await fetch("/api/v1/updates/windows/check",{method:"POST",headers:{"Content-Type":"application/json","Accept":"application/json"},body:JSON.stringify({installed_version:installedVersion}),cache:"no-store",redirect:"error"}); const payload=await response.json(); if (!response.ok) throw new Error(payload.message || "Update check failed."); state.payload=payload; render(payload); setStatus(payload.message,payload.status==="current"?"good":payload.status==="required"?"bad":"warn"); }
      catch (error) { state.payload=null; $("result").innerHTML='<div class="empty">Update compatibility information will appear here.</div>'; setStatus(error.message || "Update check failed.","bad"); }
      finally { $("check").disabled=false; }
    }
    $("check").addEventListener("click",checkUpdate);
    $("clear").addEventListener("click",()=>{ state.payload=null; $("installedVersion").value=""; $("result").innerHTML='<div class="empty">Update compatibility information will appear here.</div>'; setStatus("Version and update result cleared from page memory."); });
    $("installedVersion").addEventListener("keydown",(event)=>{ if (event.key==="Enter") checkUpdate(); });
  </script>
</body>
</html>""".replace("__API_VERSION__", html_escape(API_VERSION))


def recovery_readiness_html():
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VaultLink Recovery Readiness</title>
  <style>
    :root { --bg:#0f1216; --surface:#171c22; --surface2:#202731; --line:#34404c; --text:#f4f7f8; --muted:#aeb9c4; --green:#69df8a; --blue:#69bce8; --yellow:#ffd166; --red:#ff8278; }
    * { box-sizing:border-box; }
    body { margin:0; min-width:0; background:var(--bg); color:var(--text); font-family:"Segoe UI",Arial,sans-serif; }
    header { border-bottom:1px solid var(--line); background:#14181d; }
    header > div, main, footer > div { width:min(980px,calc(100% - 32px)); margin:0 auto; }
    header > div { min-height:68px; display:flex; align-items:center; justify-content:space-between; gap:16px; }
    .brand { font-weight:800; }
    nav { display:flex; gap:8px; flex-wrap:wrap; }
    nav a { color:var(--text); text-decoration:none; border:1px solid var(--line); border-radius:6px; padding:8px 11px; }
    main { padding:34px 0 52px; }
    h1 { margin:0; font-size:clamp(2rem,5vw,3.4rem); line-height:1.04; letter-spacing:0; }
    .lead { margin:10px 0 18px; color:var(--muted); line-height:1.55; max-width:760px; }
    .privacy { padding:13px 14px; border-left:4px solid var(--blue); background:#171e25; color:var(--muted); line-height:1.45; }
    .checklist-head { display:flex; align-items:end; justify-content:space-between; gap:12px; margin:24px 0 10px; }
    .checklist-head h2 { margin:0; font-size:1.05rem; }
    .checklist-head p { margin:0; color:var(--muted); font-size:.85rem; }
    .checklist { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; }
    .check { display:flex; align-items:flex-start; gap:11px; min-width:0; padding:15px; border:1px solid var(--line); border-radius:8px; background:var(--surface); color:var(--text); cursor:pointer; }
    .check input { flex:0 0 auto; width:19px; height:19px; margin:2px 0 0; }
    .check strong { display:block; font-size:.95rem; }
    .check span span { display:block; margin-top:5px; color:var(--muted); font-size:.8rem; line-height:1.4; }
    .check.critical { border-left:4px solid var(--yellow); }
    .controls { display:flex; gap:8px; flex-wrap:wrap; margin-top:12px; }
    button { min-height:42px; border:0; border-radius:5px; padding:0 14px; font-weight:800; cursor:pointer; }
    #checkReadiness { background:var(--green); color:#061109; }
    #clear { background:var(--surface2); color:var(--text); border:1px solid var(--line); }
    #status { min-height:23px; margin-top:10px; color:var(--muted); line-height:1.4; }
    #status.good { color:var(--green); } #status.warn { color:var(--yellow); } #status.bad { color:var(--red); }
    #result { margin-top:18px; }
    .empty { padding:28px 18px; border:1px dashed var(--line); border-radius:8px; color:var(--muted); text-align:center; }
    .summary { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); border:1px solid var(--line); border-radius:8px; overflow:hidden; }
    .summary > div { min-width:0; padding:17px; background:var(--surface); border-right:1px solid var(--line); }
    .summary > div:last-child { border-right:0; }
    .eyebrow { color:var(--muted); font-size:.72rem; font-weight:800; text-transform:uppercase; }
    .value { margin-top:6px; font-size:1.08rem; font-weight:800; overflow-wrap:anywhere; }
    .value.ready { color:var(--green); } .value.review,.value.action { color:var(--yellow); } .value.blocked { color:var(--red); }
    .progress { height:10px; margin-top:10px; overflow:hidden; border-radius:5px; background:#090d11; }
    .progress span { display:block; height:100%; background:var(--green); }
    .headline { margin-top:12px; padding:14px; border-left:4px solid var(--blue); background:#181f26; color:var(--muted); line-height:1.5; }
    .result-actions { display:flex; gap:8px; flex-wrap:wrap; margin-top:12px; }
    .result-actions button { min-height:38px; background:var(--surface2); border:1px solid var(--line); color:var(--text); }
    .result-grid { display:grid; grid-template-columns:minmax(0,1.1fr) minmax(280px,.9fr); gap:14px; margin-top:14px; }
    .result-grid section { min-width:0; padding:18px; border:1px solid var(--line); border-radius:8px; background:var(--surface); }
    .result-grid h2 { margin:0 0 11px; font-size:1rem; }
    ol,ul { margin:0; padding-left:20px; color:var(--muted); line-height:1.6; }
    .priority { color:var(--red); font-size:.72rem; font-weight:800; }
    footer { border-top:1px solid var(--line); background:#14181d; }
    footer > div { padding:23px 0 30px; color:var(--muted); line-height:1.5; }
    @media(max-width:720px) { .checklist,.result-grid { grid-template-columns:1fr; } .checklist-head { align-items:flex-start; flex-direction:column; } }
    @media(max-width:480px) { header > div { align-items:flex-start; flex-direction:column; padding:14px 0; } .summary { grid-template-columns:1fr; } .summary > div { border-right:0; border-bottom:1px solid var(--line); } .summary > div:last-child { border-bottom:0; } .controls button { width:100%; } }
  </style>
</head>
<body>
  <header><div><div class="brand">VaultLink Recovery Readiness</div><nav><a href="/">HOME</a><a href="/maintenance">MAINTENANCE</a><a href="/retention">RETENTION</a><a href="/data-control">DATA</a><a href="/recovery-kit">KIT</a><a href="/backup-verification">BACKUPS</a><a href="/recovery-drills">DRILLS</a><a href="/diagnostics">DIAGNOSTICS</a><a href="/trust">TRUST</a><a href="/update">UPDATE</a><a href="/customer">LICENSE</a><a href="/privacy">PRIVACY</a></nav></div></header>
  <main>
    <h1>Recovery Readiness</h1>
    <p class="lead">Self-reported preparation for safe file locking and recovery.</p>
    <div class="privacy">Only seven yes-or-no values are checked. VaultLink does not request or store names, paths, PINs, keys, files, or device information.</div>
    <div class="checklist-head"><h2>Readiness Checks</h2><p>Critical checks carry a yellow left border.</p></div>
    <div class="checklist">
      <label class="check critical"><input id="backup_current" type="checkbox"><span><strong>Current backup exists</strong><span>20 points, critical</span></span></label>
      <label class="check critical"><input id="master_usb_tested" type="checkbox"><span><strong>Master USB key tested</strong><span>20 points, critical</span></span></label>
      <label class="check"><input id="recovery_copy_separate" type="checkbox"><span><strong>Recovery copy stored separately</strong><span>15 points</span></span></label>
      <label class="check"><input id="pin_stored_separately" type="checkbox"><span><strong>PIN stored separately from USB</strong><span>10 points</span></span></label>
      <label class="check"><input id="defender_enabled" type="checkbox"><span><strong>Microsoft Defender active</strong><span>10 points</span></span></label>
      <label class="check critical"><input id="test_file_roundtrip" type="checkbox"><span><strong>Disposable file lock and unlock tested</strong><span>15 points, critical</span></span></label>
      <label class="check"><input id="update_current" type="checkbox"><span><strong>VaultLink version checked</strong><span>10 points</span></span></label>
    </div>
    <div class="controls"><button id="checkReadiness" type="button">CHECK READINESS</button><button id="clear" type="button">CLEAR</button></div>
    <div id="status" role="status" aria-live="polite">Not checked.</div>
    <div id="result"><div class="empty">Readiness score and action plan will appear here.</div></div>
  </main>
  <footer><div>This self-check cannot inspect the PC, verify a backup, test a key, run antivirus, or guarantee recovery. API version __API_VERSION__.</div></footer>
  <script>
    const $=(id)=>document.getElementById(id);
    const fields=["backup_current","master_usb_tested","recovery_copy_separate","pin_stored_separately","defender_enabled","test_file_roundtrip","update_current"];
    const state={payload:null};
    function setStatus(message,tone="") { const node=$("status"); node.textContent=message; node.className=tone; }
    function answers() { return Object.fromEntries(fields.map((field)=>[field,$(field).checked])); }
    function safeReport() { if (!state.payload) return null; const value=state.payload; return {exported_at_utc:new Date().toISOString(),status:value.status,headline:value.headline,score:value.score,maximum_score:value.maximum_score,completed_count:value.completed_count,total_count:value.total_count,critical_missing_count:value.critical_missing_count,ready_for_important_data:value.ready_for_important_data,items:value.items,actions:value.actions,limitations:value.limitations,privacy_notice:value.privacy_notice}; }
    async function copyReport() { const report=safeReport(); if (!report) return; const lines=["VaultLink Recovery Readiness",`Status: ${report.status}`,`Score: ${report.score} of ${report.maximum_score}`,report.headline,...report.actions.map((item,index)=>`${index+1}. ${item.action}`)]; try { await navigator.clipboard.writeText(lines.join("\\n")); setStatus("Privacy-safe readiness report copied.","good"); } catch (_) { setStatus("Browser clipboard access was blocked.","bad"); } }
    function download(name,body,type) { const blob=new Blob([body],{type}); const url=URL.createObjectURL(blob); const link=document.createElement("a"); link.href=url; link.download=name; document.body.append(link); link.click(); link.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000); }
    function exportJson() { const report=safeReport(); if (!report) return; download("vaultlink-recovery-readiness.json",JSON.stringify(report,null,2),"application/json"); setStatus("Privacy-safe readiness JSON exported.","good"); }
    function exportPlan() { const report=safeReport(); if (!report) return; const lines=["VaultLink Recovery Action Plan",`Status: ${report.status}`,`Score: ${report.score} of ${report.maximum_score}`,"",...(report.actions.length?report.actions.map((item,index)=>`${index+1}. [${item.priority.toUpperCase()}] ${item.action}`):["All self-reported checks pass."]),"","Use a disposable non-private test file before important data."]; download("vaultlink-recovery-action-plan.txt",lines.join("\\r\\n"),"text/plain"); setStatus("Local recovery action plan created.","good"); }
    function render(payload) {
      const root=$("result"); root.replaceChildren();
      const summary=document.createElement("div"); summary.className="summary";
      [["Status",payload.status],["Score",`${payload.score} of ${payload.maximum_score}`],["Critical missing",payload.critical_missing_count]].forEach(([label,value],index)=>{ const cell=document.createElement("div"); const key=document.createElement("div"); key.className="eyebrow"; key.textContent=label; const data=document.createElement("div"); data.className=`value${index===0?` ${payload.status}`:""}`; data.textContent=value; cell.append(key,data); summary.append(cell); });
      const progress=document.createElement("div"); progress.className="progress"; progress.setAttribute("aria-label",`Readiness score ${payload.score} percent`); const fill=document.createElement("span"); fill.style.width=`${payload.score}%`; progress.append(fill);
      const headline=document.createElement("div"); headline.className="headline"; headline.textContent=payload.headline;
      const actions=document.createElement("div"); actions.className="result-actions"; [["COPY REPORT",copyReport],["EXPORT JSON",exportJson],["DOWNLOAD ACTION PLAN",exportPlan]].forEach(([label,handler])=>{ const button=document.createElement("button"); button.type="button"; button.textContent=label; button.addEventListener("click",handler); actions.append(button); });
      const grid=document.createElement("div"); grid.className="result-grid";
      const plan=document.createElement("section"); const planTitle=document.createElement("h2"); planTitle.textContent="Prioritized Action Plan"; const planList=document.createElement("ol"); if (payload.actions.length) payload.actions.forEach((item)=>{ const row=document.createElement("li"); const priority=document.createElement("span"); priority.className=item.priority==="critical"?"priority":""; priority.textContent=`${item.priority.toUpperCase()}: `; row.append(priority,document.createTextNode(item.action)); planList.append(row); }); else { const row=document.createElement("li"); row.textContent="All self-reported checks pass."; planList.append(row); } plan.append(planTitle,planList);
      const limits=document.createElement("section"); const limitsTitle=document.createElement("h2"); limitsTitle.textContent="Limits"; const limitsList=document.createElement("ul"); payload.limitations.forEach((item)=>{ const row=document.createElement("li"); row.textContent=item; limitsList.append(row); }); limits.append(limitsTitle,limitsList); grid.append(plan,limits);
      root.append(summary,progress,headline,actions,grid);
    }
    async function checkReadiness() { $("checkReadiness").disabled=true; setStatus("Calculating readiness..."); try { const response=await fetch("/api/v1/readiness/check",{method:"POST",headers:{"Content-Type":"application/json","Accept":"application/json"},body:JSON.stringify(answers()),cache:"no-store",redirect:"error"}); const payload=await response.json(); if (!response.ok) throw new Error(payload.message || "Readiness check failed."); state.payload=payload; render(payload); setStatus(payload.headline,payload.status==="ready"?"good":payload.status==="blocked"?"bad":"warn"); } catch (error) { state.payload=null; setStatus(error.message || "Readiness check failed.","bad"); } finally { $("checkReadiness").disabled=false; } }
    $("checkReadiness").addEventListener("click",checkReadiness);
    $("clear").addEventListener("click",()=>{ fields.forEach((field)=>{$(field).checked=false;}); state.payload=null; $("result").innerHTML='<div class="empty">Readiness score and action plan will appear here.</div>'; setStatus("Readiness answers and result cleared from page memory."); });
  </script>
</body>
</html>""".replace("__API_VERSION__", html_escape(API_VERSION))


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
  <header><div><strong>VaultLink</strong><nav><a href="/diagnostics">DIAGNOSTICS</a><a href="/trust">TRUST</a><a href="/status">STATUS</a><a href="/terms">TERMS</a><a href="/privacy">PRIVACY</a></nav></div></header>
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
  <footer><div><strong>How delivery works:</strong> create a VaultLink customer account first. After the payment provider confirms payment, the owner assigns the matching license to that account. A checkout receipt is not itself a license key. The plans are software packages, not HIPAA certification or a guarantee against data loss, malware, or legal risk.</div></footer>
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
    .help-center { margin-top:18px; }
    .help-grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
    .help-panel { min-width:0; padding:17px; border:1px solid var(--line); border-radius:8px; background:var(--surface); }
    .help-panel h2 { margin-bottom:8px; }
    .help-panel p { margin:0 0 12px; color:var(--muted); line-height:1.45; }
    .help-controls { display:grid; grid-template-columns:minmax(0,1fr) auto; gap:8px; align-items:end; }
    .help-controls select { width:100%; min-width:0; height:40px; padding:0 10px; border:1px solid var(--line); border-radius:5px; background:#0d1116; color:var(--text); font:inherit; }
    .guide-result { margin-top:12px; }
    .guide-result ol { margin:0; padding-left:20px; color:var(--muted); line-height:1.55; }
    .guide-actions { display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; }
    .guide-actions button { min-height:36px; }
    .verify-file { display:flex; align-items:center; justify-content:center; min-height:40px; padding:0 11px; border:1px solid var(--line); border-radius:5px; background:var(--surface2); color:var(--text); font-size:.78rem; font-weight:800; cursor:pointer; }
    .verify-file input { display:none; }
    .verify-status { min-height:22px; margin-top:10px; color:var(--muted); line-height:1.45; overflow-wrap:anywhere; }
    .verify-status.good { color:var(--green); } .verify-status.bad { color:var(--red); } .verify-status.warn { color:var(--yellow); }
    .timeline { margin-top:18px; }
    .timeline-head { display:flex; justify-content:space-between; gap:12px; align-items:end; margin-bottom:10px; }
    .timeline-head p { margin:0; color:var(--muted); font-size:.85rem; }
    .timeline-actions { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:11px; }
    .timeline-actions button { min-height:36px; background:var(--surface2); border:1px solid var(--line); color:var(--text); }
    .timeline-actions .reminder-action { background:var(--green); border-color:var(--green); color:#061109; }
    .timeline-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:10px; }
    .timeline-event { min-width:0; padding:14px; border:1px solid var(--line); border-left:4px solid var(--blue); border-radius:8px; background:var(--surface); }
    .timeline-event.upcoming { border-left-color:var(--yellow); } .timeline-event.current { border-left-color:var(--green); } .timeline-event.past { border-left-color:var(--red); }
    .timeline-event h3 { margin:5px 0; font-size:.96rem; }
    .timeline-event p { margin:0; color:var(--muted); line-height:1.45; }
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
    @media (max-width:760px) { .top,.help-grid { grid-template-columns:1fr; } .rank-tools-head,.upgrades-head,.checkup-head,.timeline-head { align-items:flex-start; flex-direction:column; } .rank-tools-head p { text-align:left; } .rank-session { grid-template-columns:1fr; } }
    @media (max-width:480px) { header > div { align-items:flex-start; flex-direction:column; padding:14px 0; } .summary { grid-template-columns:1fr; } .summary > div { border-right:0; border-bottom:1px solid var(--line)!important; } .summary > div:last-child { border-bottom:0!important; } .actions { grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <header><div><div class="brand">VaultLink Customer</div><nav><a href="/workspace">WORKSPACE</a><a href="/maintenance">MAINTENANCE</a><a href="/retention">RETENTION</a><a href="/data-control">DATA</a><a href="/recovery-kit">KIT</a><a href="/backup-verification">BACKUPS</a><a href="/recovery-drills">DRILLS</a><a href="/diagnostics">DIAGNOSTICS</a><a href="/trust">TRUST</a><a href="/update">UPDATE</a><a href="/readiness">READINESS</a><a href="/shop">SHOP</a><a href="/status">STATUS</a><a href="/privacy">PRIVACY</a></nav></div></header>
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
    const state = { payload:null, upgrades:null, rankTools:null, checkup:null, timeline:null, guide:null, favorites:new Set() };
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
        customer_timeline:state.timeline ? {status:state.timeline.status,plan:state.timeline.plan,days_remaining:state.timeline.days_remaining,items:state.timeline.items,renewal_reminder:state.timeline.renewal_reminder} : null,
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
    function renderSupportGuide(guide) {
      const root=$("supportGuideResult"); if (!root) return; root.replaceChildren();
      const list=document.createElement("ol"); guide.steps.forEach((step)=>{ const item=document.createElement("li"); item.textContent=step; list.append(item); });
      const actions=document.createElement("div"); actions.className="guide-actions";
      const copy=document.createElement("button"); copy.type="button"; copy.textContent="COPY GUIDE"; copy.addEventListener("click",copySupportGuide);
      const exportButton=document.createElement("button"); exportButton.type="button"; exportButton.textContent="EXPORT GUIDE"; exportButton.addEventListener("click",exportSupportGuide);
      actions.append(copy,exportButton); root.append(list,actions);
    }
    async function loadSupportGuide() {
      const licenseKey=$("licenseKey").value.trim(); const category=$("supportCategory").value;
      const output=$("supportGuideStatus"); output.textContent="Loading guide...";
      try {
        const response=await fetch("/api/v1/licenses/support-guide",{method:"POST",headers:{"Content-Type":"application/json","Accept":"application/json"},body:JSON.stringify({license_key:licenseKey,category}),cache:"no-store",redirect:"error"});
        const guide=await response.json(); if (!response.ok) throw new Error(guide.message || "Support guide failed.");
        state.guide=guide; renderSupportGuide(guide); output.textContent=`${guide.steps.length} privacy-safe steps loaded.`; output.className="verify-status good";
      } catch (error) { output.textContent=error.message || "Support guide failed."; output.className="verify-status bad"; }
    }
    async function copySupportGuide() {
      if (!state.guide) return;
      const lines=[`VaultLink ${state.guide.category} Support Guide`,...state.guide.steps.map((step,index)=>`${index+1}. ${step}`)];
      try { await navigator.clipboard.writeText(lines.join("\\n")); setStatus("Privacy-safe support guide copied.","good"); }
      catch (_) { setStatus("Browser clipboard access was blocked.","bad"); }
    }
    function exportSupportGuide() {
      if (!state.guide) return;
      const safe={exported_at_utc:new Date().toISOString(),guide_id:state.guide.guide_id,category:state.guide.category,license_status:state.guide.license_status,rank:state.guide.rank,steps:state.guide.steps,signed_update:state.guide.signed_update,privacy_notice:state.guide.privacy_notice};
      const blob=new Blob([JSON.stringify(safe,null,2)],{type:"application/json"}); const url=URL.createObjectURL(blob); const link=document.createElement("a");
      link.href=url; link.download=`vaultlink-${state.guide.category}-support-guide.json`; document.body.append(link); link.click(); link.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000); setStatus("Privacy-safe support guide exported.","good");
    }
    async function verifyUpdateFile(file) {
      const output=$("updateVerifyStatus"); if (!file || !state.payload) return;
      const release=state.payload.release; output.className="verify-status";
      if (!release.published || !release.sha256) { output.textContent="No signed update hash is published."; output.classList.add("warn"); return; }
      if (file.size > 1024*1024*1024) { output.textContent="Choose an update package no larger than 1 GB."; output.classList.add("bad"); return; }
      if (release.size_bytes && file.size !== release.size_bytes) { output.textContent=`SIZE MISMATCH: selected ${file.size} bytes; expected ${release.size_bytes} bytes.`; output.classList.add("bad"); return; }
      output.textContent="Hashing selected file locally...";
      try {
        const digest=await crypto.subtle.digest("SHA-256",await file.arrayBuffer());
        const actual=[...new Uint8Array(digest)].map((value)=>value.toString(16).padStart(2,"0")).join("");
        if (actual.toLowerCase()===String(release.sha256).toLowerCase()) { output.textContent=`MATCH: SHA-256 verified for ${file.name}.`; output.classList.add("good"); }
        else { output.textContent=`MISMATCH: do not install ${file.name}.`; output.classList.add("bad"); }
      } catch (_) { output.textContent="The browser could not verify this file."; output.classList.add("bad"); }
      finally { const input=$("updateFileInput"); if (input) input.value=""; }
    }
    function safeTimeline() {
      if (!state.timeline) return null;
      return {exported_at_utc:new Date().toISOString(),status:state.timeline.status,plan:state.timeline.plan,days_remaining:state.timeline.days_remaining,items:state.timeline.items,renewal_reminder:state.timeline.renewal_reminder,privacy_notice:state.timeline.privacy_notice};
    }
    async function copyTimeline() {
      if (!state.timeline) return;
      const lines=["VaultLink Customer Timeline",`Plan: ${state.timeline.plan.name}`,`Status: ${state.timeline.status}`,...state.timeline.items.map((item)=>`${item.at_utc} | ${item.title} | ${item.detail}`)];
      try { await navigator.clipboard.writeText(lines.join("\\n")); setStatus("Privacy-safe timeline copied.","good"); }
      catch (_) { setStatus("Browser clipboard access was blocked.","bad"); }
    }
    function exportTimeline() {
      const safe=safeTimeline(); if (!safe) return;
      const blob=new Blob([JSON.stringify(safe,null,2)],{type:"application/json"}); const url=URL.createObjectURL(blob); const link=document.createElement("a");
      link.href=url; link.download="vaultlink-customer-timeline.json"; document.body.append(link); link.click(); link.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000); setStatus("Privacy-safe timeline exported.","good");
    }
    function downloadRenewalReminder() {
      const reminder=state.timeline?.renewal_reminder;
      if (!reminder?.available || !reminder.expires_at_utc) return setStatus(reminder?.message || "No renewal reminder is available.","warn");
      const stamp=(value)=>new Date(value).toISOString().replaceAll("-","").replaceAll(":","").replace(".000","");
      const lines=["BEGIN:VCALENDAR","VERSION:2.0","PRODID:-//VaultLink//Customer Renewal Reminder//EN","CALSCALE:GREGORIAN","BEGIN:VEVENT",`UID:vaultlink-renewal-${Date.now()}@local`,`DTSTAMP:${stamp(new Date().toISOString())}`,`DTSTART:${stamp(reminder.expires_at_utc)}`,"SUMMARY:VaultLink license expiration",`DESCRIPTION:${state.timeline.plan.name} renewal reminder. This file contains no license key or customer identity.`,"BEGIN:VALARM","TRIGGER:-P30D","ACTION:DISPLAY","DESCRIPTION:VaultLink license renewal reminder","END:VALARM","END:VEVENT","END:VCALENDAR",""];
      const blob=new Blob([lines.join("\\r\\n")],{type:"text/calendar"}); const url=URL.createObjectURL(blob); const link=document.createElement("a");
      link.href=url; link.download="vaultlink-renewal-reminder.ics"; document.body.append(link); link.click(); link.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000); setStatus("Local renewal calendar file created.","good");
    }
    function render(payload,upgrades,rankTools,checkup,timeline) {
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
      const timelineSection=document.createElement("section"); timelineSection.className="timeline";
      const timelineHead=document.createElement("div"); timelineHead.className="timeline-head";
      const timelineTitle=document.createElement("h2"); timelineTitle.textContent="License Timeline";
      const timelineSummary=document.createElement("p"); timelineSummary.textContent=timeline.days_remaining===null?`${timeline.event_count} privacy-safe milestones. No expiration date.`:`${timeline.event_count} privacy-safe milestones. ${timeline.days_remaining} day(s) remaining.`;
      timelineHead.append(timelineTitle,timelineSummary);
      const timelineActions=document.createElement("div"); timelineActions.className="timeline-actions";
      const copyTimelineButton=document.createElement("button"); copyTimelineButton.type="button"; copyTimelineButton.textContent="COPY TIMELINE"; copyTimelineButton.addEventListener("click",copyTimeline);
      const exportTimelineButton=document.createElement("button"); exportTimelineButton.type="button"; exportTimelineButton.textContent="EXPORT TIMELINE"; exportTimelineButton.addEventListener("click",exportTimeline);
      timelineActions.append(copyTimelineButton,exportTimelineButton);
      if (timeline.renewal_reminder.available) { const reminderButton=document.createElement("button"); reminderButton.type="button"; reminderButton.className="reminder-action"; reminderButton.textContent="ADD RENEWAL REMINDER"; reminderButton.addEventListener("click",downloadRenewalReminder); timelineActions.append(reminderButton); }
      const timelineGrid=document.createElement("div"); timelineGrid.className="timeline-grid";
      timeline.items.forEach((item)=>{ const card=document.createElement("article"); card.className=`timeline-event ${item.state}`; const stateLabel=document.createElement("div"); stateLabel.className="eyebrow"; stateLabel.textContent=`${item.state.toUpperCase()} | ${new Date(item.at_utc).toLocaleString()}`; const title=document.createElement("h3"); title.textContent=item.title; const detail=document.createElement("p"); detail.textContent=item.detail; card.append(stateLabel,title,detail); timelineGrid.append(card); });
      timelineSection.append(timelineHead,timelineActions,timelineGrid);
      const helpCenter=document.createElement("section"); helpCenter.className="help-center";
      const helpGrid=document.createElement("div"); helpGrid.className="help-grid";
      const guidePanel=document.createElement("div"); guidePanel.className="help-panel";
      const guideTitle=document.createElement("h2"); guideTitle.textContent="Support Guide";
      const guideCopy=document.createElement("p"); guideCopy.textContent="Load fixed troubleshooting steps without sending free-form text, files, logs, or secrets.";
      const guideControls=document.createElement("div"); guideControls.className="help-controls";
      const guideSelectWrap=document.createElement("label"); guideSelectWrap.textContent="CATEGORY";
      const guideSelect=document.createElement("select"); guideSelect.id="supportCategory"; [["licensing","Licensing"],["update","Update"],["recovery","Recovery"],["security","Security"],["privacy","Privacy"],["other","Other"]].forEach(([value,label])=>{ const option=document.createElement("option"); option.value=value; option.textContent=label; guideSelect.append(option); }); guideSelectWrap.append(guideSelect);
      const guideButton=document.createElement("button"); guideButton.type="button"; guideButton.textContent="LOAD GUIDE"; guideButton.addEventListener("click",loadSupportGuide); guideControls.append(guideSelectWrap,guideButton);
      const guideStatus=document.createElement("div"); guideStatus.id="supportGuideStatus"; guideStatus.className="verify-status"; guideStatus.textContent="No guide loaded.";
      const guideResult=document.createElement("div"); guideResult.id="supportGuideResult"; guideResult.className="guide-result"; guidePanel.append(guideTitle,guideCopy,guideControls,guideStatus,guideResult);
      const verifyPanel=document.createElement("div"); verifyPanel.className="help-panel";
      const verifyTitle=document.createElement("h2"); verifyTitle.textContent="Signed Update Verifier";
      const verifyCopy=document.createElement("p"); verifyCopy.textContent=payload.release.published?`Expected ${payload.release.package_filename || "update package"}. The selected file is hashed locally and never uploaded.`:"No signed Windows update package is currently published.";
      const verifyLabel=document.createElement("label"); verifyLabel.className="verify-file"; verifyLabel.textContent="CHOOSE UPDATE ZIP";
      const verifyInput=document.createElement("input"); verifyInput.id="updateFileInput"; verifyInput.type="file"; verifyInput.accept="application/zip,.zip"; verifyInput.addEventListener("change",()=>verifyUpdateFile(verifyInput.files?.[0])); verifyLabel.append(verifyInput);
      const verifyStatus=document.createElement("div"); verifyStatus.id="updateVerifyStatus"; verifyStatus.className="verify-status"; verifyStatus.textContent=payload.release.sha256?`Expected SHA-256: ${payload.release.sha256}`:"No expected hash available.";
      verifyPanel.append(verifyTitle,verifyCopy,verifyLabel,verifyStatus); helpGrid.append(guidePanel,verifyPanel); helpCenter.append(helpGrid);
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
      root.append(summary,progress,message,toolbar,checkupSection,timelineSection,helpCenter,details);
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
        const timelineResponse=await fetch("/api/v1/licenses/timeline",{method:"POST",headers:{"Content-Type":"application/json","Accept":"application/json"},body:JSON.stringify({license_key:licenseKey}),cache:"no-store",redirect:"error"});
        const timeline=await timelineResponse.json();
        if (!timelineResponse.ok) throw new Error(timeline.message || "License timeline failed.");
        state.payload=payload; state.upgrades=upgrades; state.rankTools=rankTools; state.checkup=checkup; state.timeline=timeline; state.favorites=new Set(); render(payload,upgrades,rankTools,checkup,timeline); setStatus("Customer dashboard loaded.",payload.status==="active"?"good":payload.status==="limited"?"warn":"bad");
      } catch (error) { setStatus(error.message || "License check failed.","bad"); }
      finally { $("check").disabled=false; }
    }
    $("check").addEventListener("click",checkLicense);
    $("clear").addEventListener("click",() => { state.payload=null; state.upgrades=null; state.rankTools=null; state.checkup=null; state.timeline=null; state.guide=null; state.favorites=new Set(); $("licenseKey").value=""; $("appVersion").value=""; $("result").innerHTML='<div class="empty">License information will appear here.</div>'; setStatus("License key and session data cleared from page memory."); });
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
      <div class="record-head"><h2>Signed Release Test</h2><div id="releaseTestSummary" class="meta">Connect to verify the published Windows update.</div><button id="testRelease" class="blue" disabled>TEST SIGNED RELEASE</button></div>
      <div id="releaseTestChecks"><div class="empty">No signed release test has run.</div></div>
      <div class="status">This test is read-only. Publishing stays in the local Owner Update Lab and requires the registered removable owner USB.</div>
    </section>

    <section>
      <h2>50-Point Owner Command Center</h2>
      <div class="latest">
        <div class="status">Open a focused view with exactly 50 live, privacy-safe business and service insights plus search, filters, copy, and JSON/CSV exports.</div>
        <a href="/owner/insights" style="display:inline-flex;align-items:center;justify-content:center;min-height:40px;padding:0 14px;border-radius:4px;background:var(--blue);color:#061017;text-decoration:none;font-weight:800;">OPEN COMMAND CENTER</a>
      </div>
    </section>

    <section>
      <h2>Owner Maintenance Operations</h2>
      <div class="latest">
        <div class="status">Run the fixed 40-check owner readiness contract, review six approval gates and a prioritized decision queue, inspect release and storage matrices, and export privacy-safe evidence.</div>
        <a href="/owner/operations" style="display:inline-flex;align-items:center;justify-content:center;min-height:40px;padding:0 14px;border-radius:4px;background:var(--green);color:#06120a;text-decoration:none;font-weight:800;">OPEN OPERATIONS</a>
      </div>
    </section>

    <section>
      <div class="record-head"><h2>Client Release Adoption</h2><div id="clientHealthSummary" class="meta">Connect to load anonymous client health.</div></div>
      <div id="clientVersionRecords"><div class="empty">No client version data loaded.</div></div>
    </section>

    <section>
      <h2>Customer Pages</h2>
      <div class="page-links"><a href="/account" target="_blank" rel="noopener">CREATE CUSTOMER ACCOUNT</a><a href="/owner/accounts">OWNER ACCOUNT LIST</a><a href="/workspace" target="_blank" rel="noopener">CUSTOMER WORKSPACE</a><a href="/maintenance" target="_blank" rel="noopener">SECURITY MAINTENANCE</a><a href="/retention" target="_blank" rel="noopener">STORAGE & RETENTION</a><a href="/data-control" target="_blank" rel="noopener">DATA CONTROL</a><a href="/recovery-kit" target="_blank" rel="noopener">RECOVERY KIT</a><a href="/backup-verification" target="_blank" rel="noopener">BACKUP VERIFICATION</a><a href="/recovery-drills" target="_blank" rel="noopener">RECOVERY DRILLS</a><a href="/incident-response" target="_blank" rel="noopener">INCIDENT RESPONSE</a><a href="/diagnostics" target="_blank" rel="noopener">DIAGNOSTICS</a><a href="/owner/operations">OWNER OPERATIONS</a><a href="/owner/customers">CUSTOMER EXPERIENCE CONSOLE</a><a href="/owner/trust">TRUST OPERATIONS</a><a href="/trust" target="_blank" rel="noopener">PUBLIC TRUST</a><a href="/status" target="_blank" rel="noopener">STATUS</a><a href="/terms" target="_blank" rel="noopener">DRAFT TERMS</a><a href="/privacy" target="_blank" rel="noopener">PRIVACY</a><a href="/shop" target="_blank" rel="noopener">SHOP</a><a href="/docs" target="_blank" rel="noopener">API DOCS</a></div>
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
      <h2>Issue License To Account</h2>
      <div class="grid">
        <div class="split"><label for="issueAccount">Customer account</label><select id="issueAccount"><option value="">Connect to load accounts</option></select></div>
        <div><label for="rank">Rank</label><select id="rank"></select></div>
        <div><label for="devices">Maximum devices</label><input id="devices" type="number" min="1" max="1000" value="1"></div>
        <div><label for="expires">Expiration, optional</label><input id="expires" type="datetime-local"></div>
        <div><label for="note">Private owner note</label><input id="note" maxlength="2000"></div>
        <div class="split"><button id="issue" class="primary" disabled>ISSUE LICENSE</button></div>
      </div>
      <div class="status">A customer must create an account first. Every new license is bound and assigned to the selected account.</div>
      <div id="latestWrap" hidden>
        <label for="latestKey">Latest key</label>
        <div class="latest"><textarea id="latestKey" readonly></textarea><button id="copyLatest" class="warn">COPY KEY</button></div>
      </div>
    </section>

    <section>
      <h2>Giveaway License To Account</h2>
      <div class="grid">
        <div class="split"><label for="giveawayAccount">Winner account</label><select id="giveawayAccount"><option value="">Connect to load accounts</option></select></div>
        <div><label for="giveawayRank">Rank</label><select id="giveawayRank"></select></div>
        <div><label for="giveawayDays">Duration in days</label><input id="giveawayDays" type="number" min="1" max="365" value="30"></div>
        <div><label for="giveawayDevices">Maximum devices</label><input id="giveawayDevices" type="number" min="1" max="10" value="1"></div>
        <div class="split"><button id="issueGiveaway" class="primary" disabled>ISSUE GIVEAWAY LICENSE</button></div>
      </div>
      <div class="status">The winner must create an account before receiving the promotional license. This does not select winners, collect entries, process payment, or provide contest-law compliance.</div>
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
    const state = { token: "", connected: false, busy: false, loading: false, items: [], accountItems: [], supportItems: [], auditItems: [], announcementItems: [], activityItems: [], activityIntegrity: null, serviceStatus: null, dashboard: null, releaseStatus: null };
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
      $("testRelease").disabled = !value || state.busy;
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

    function renderAccountOptions() {
      for (const select of [$("issueAccount"), $("giveawayAccount")]) {
        const previous = select.value;
        select.replaceChildren();
        const placeholder = document.createElement("option");
        placeholder.value = "";
        placeholder.textContent = state.accountItems.length
          ? "Choose a customer account"
          : "No customer accounts yet";
        select.append(placeholder);
        for (const account of state.accountItems) {
          const option = document.createElement("option");
          option.value = account.account_id;
          const license = account.license || {};
          const access = license.assigned ? `Rank ${license.rank || "?"}` : "No license";
          option.textContent = `${account.username} | ${access} | ${account.status}`;
          option.disabled = account.status !== "active";
          select.append(option);
        }
        if ([...select.options].some(option => option.value === previous && !option.disabled)) {
          select.value = previous;
        }
      }
    }

    async function loadLicenses(silent=false) {
      if (state.loading) return;
      state.loading = true;
      try {
      const [payload, accounts, dashboard, support, audits, announcements, serviceStatus, activity, releaseStatus] = await Promise.all([
        api("/api/v1/admin/licenses"),
        api("/api/v1/admin/accounts"),
        api("/api/v1/admin/dashboard"),
        api("/api/v1/admin/support-tickets"),
        api("/api/v1/admin/audit-exports"),
        api("/api/v1/admin/announcements"),
        api("/api/v1/service-status"),
        api("/api/v1/admin/activity"),
        api("/api/v1/admin/updates/windows/status")
      ]);
      state.items = payload.items || [];
      state.accountItems = accounts.items || [];
      state.supportItems = support.items || [];
      state.auditItems = audits.items || [];
      state.announcementItems = announcements.items || [];
      state.serviceStatus = serviceStatus.service_status || null;
      state.activityItems = activity.items || [];
      state.activityIntegrity = activity.integrity || null;
      state.dashboard = dashboard;
      state.releaseStatus = releaseStatus;
      $("storage").textContent = payload.storage === "persistent_configured" ? "PERSISTENT STORAGE" : "TEMPORARY STORAGE";
      $("supportStorage").textContent = support.storage === "persistent_configured" ? "ENCRYPTED PERSISTENT STORAGE" : "TEMPORARY STORAGE";
      $("auditStorage").textContent = `${audits.storage === "persistent_configured" ? "PERSISTENT STORAGE" : "TEMPORARY STORAGE"} | ${audits.retention_hours || 0}H RETENTION`;
      $("announcementStorage").textContent = announcements.storage === "persistent_configured" ? "PERSISTENT STORAGE" : "TEMPORARY STORAGE";
      renderDashboard(dashboard);
      renderAccountOptions();
      renderRecords();
      renderSupport();
      renderAudits();
      renderAnnouncements();
      renderServiceStatus();
      renderActivity();
      renderReleaseStatus(releaseStatus);
      setConnected(true);
      if (!silent) setStatus(`Loaded ${accounts.count || 0} customer account(s), ${payload.count || 0} license(s), ${support.count || 0} bug report(s), ${audits.count || 0} audit log(s), ${announcements.count || 0} announcement(s), and ${activity.count || 0} activity event(s).`, "good");
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

    function renderReleaseStatus(payload) {
      const host = $("releaseTestChecks");
      const summary = $("releaseTestSummary");
      host.replaceChildren();
      if (!payload) {
        summary.textContent = "Connect to verify the published Windows update.";
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "No signed release test has run.";
        host.append(empty);
        return;
      }
      summary.textContent = `${payload.version || "unknown"} | ${payload.package_filename || "no package"} | tested ${payload.tested_at_utc || "now"}`;
      const checks = payload.checks || {};
      for (const [name, result] of Object.entries(checks)) {
        const passed = result === true || result === "passed";
        const row = document.createElement("article");
        row.className = "record activity-row";
        const label = document.createElement("strong");
        label.textContent = String(name).replaceAll("_", " ").toUpperCase();
        const detail = document.createElement("div");
        detail.className = "meta";
        detail.textContent = passed ? "Verified by the API" : "Verification failed";
        const badge = document.createElement("span");
        badge.className = `badge ${passed ? "resolved" : "revoked"}`;
        badge.textContent = passed ? "PASS" : "FAIL";
        row.append(label, detail, badge);
        host.append(row);
      }
      if (!Object.keys(checks).length) {
        const message = document.createElement("div");
        message.className = "record ticket-copy";
        message.textContent = payload.message || "The release could not be verified.";
        host.append(message);
      }
    }

    async function testRelease() {
      if (!state.connected || state.busy) return;
      state.busy = true;
      setConnected(true);
      setStatus("Testing the signed Windows release...");
      try {
        const payload = await api("/api/v1/admin/updates/windows/status");
        state.releaseStatus = payload;
        renderReleaseStatus(payload);
        setStatus(payload.ready ? "Signed release passed every API verification check." : (payload.message || "Signed release verification failed."), payload.ready ? "good" : "bad");
      } catch (error) {
        state.releaseStatus = null;
        renderReleaseStatus(null);
        setStatus(error.message, "bad");
      } finally {
        state.busy = false;
        setConnected(state.connected);
      }
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
      const accountId = $("issueAccount").value;
      if (!accountId) return setStatus("Choose an existing customer account first.", "bad");
      state.busy = true; setConnected(true); setStatus("Issuing license...");
      try {
        const expiresValue = $("expires").value;
        const payload = await api("/api/v1/licenses/issue", { method:"POST", body:JSON.stringify({
          account_id: accountId,
          plan_id: $("rank").value,
          max_devices: Number($("devices").value || 1),
          license_note: $("note").value.trim(),
          expires_at_utc: expiresValue ? new Date(expiresValue).toISOString() : ""
        }) });
        $("latestKey").value = payload.license_key || "";
        $("latestWrap").hidden = false;
        await loadLicenses();
        setStatus(`License issued and assigned to ${payload.account?.username || "the selected account"}.`, "good");
      } catch (error) { setStatus(error.message, "bad"); }
      finally { state.busy = false; setConnected(state.connected); }
    }

    async function issueGiveaway() {
      if (!state.connected || state.busy) return;
      const accountId = $("giveawayAccount").value;
      const account = state.accountItems.find(item => item.account_id === accountId);
      const days = Number($("giveawayDays").value || 30);
      const devices = Number($("giveawayDevices").value || 1);
      if (!account) return setStatus("Choose the winner's existing customer account first.", "bad");
      if (!Number.isInteger(days) || days < 1 || days > 365) return setStatus("Giveaway duration must be 1 to 365 days.", "bad");
      if (!Number.isInteger(devices) || devices < 1 || devices > 10) return setStatus("Giveaway devices must be 1 to 10.", "bad");
      if (!confirm(`ISSUE A ${days}-DAY GIVEAWAY LICENSE TO ${account.username}?`)) return;
      state.busy = true; setConnected(true); setStatus("Issuing giveaway license...");
      try {
        const expires = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
        const result = await api("/api/v1/licenses/issue", { method:"POST", body:JSON.stringify({
          account_id: accountId,
          plan_id: $("giveawayRank").value,
          max_devices: devices,
          license_note: `Promotional giveaway license | ${days} day(s) | no payment recorded`,
          expires_at_utc: expires
        }) });
        $("latestKey").value = result.license_key || "";
        $("latestWrap").hidden = false;
        $("giveawayAccount").value = "";
        await loadLicenses(true);
        setStatus(`Giveaway license issued and assigned to ${account.username}.`, "good");
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
    $("clearToken").addEventListener("click", () => { state.token=""; $("token").value=""; state.items=[]; state.supportItems=[]; state.auditItems=[]; state.announcementItems=[]; state.activityItems=[]; state.activityIntegrity=null; state.serviceStatus=null; state.dashboard=null; state.releaseStatus=null; setConnected(false); renderDashboard(null); renderReleaseStatus(null); renderRecords(); renderSupport(); renderAudits(); renderAnnouncements(); renderActivity(); setStatus("Admin token cleared from page memory."); });
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
    $("testRelease").addEventListener("click", testRelease);
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
  <header><div><div class="brand"><h1>Owner Command Center</h1><span class="version">50 live insights</span></div><nav><a href="/owner">OWNER CONSOLE</a><a href="/owner/operations">MAINTENANCE OPS</a><a href="/owner/trust">TRUST OPERATIONS</a><a href="/status">CUSTOMER STATUS</a></nav></div></header>
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
        "download_path": "",
        "sha256": "",
        "size_bytes": 0,
        "package_filename": "",
        "published_at_utc": "",
    }
    try:
        manifest, _package_path = load_windows_update_release()
        release = {
            "latest_version": manifest.get("version", ""),
            "minimum_supported_version": manifest.get("minimum_supported_version", ""),
            "published": True,
            "download_path": manifest.get("download_path", ""),
            "sha256": manifest.get("sha256", ""),
            "size_bytes": int(manifest.get("size_bytes", 0) or 0),
            "package_filename": manifest.get("package_filename", ""),
            "published_at_utc": manifest.get("published_at_utc", ""),
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
    allowed_version_characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._+-"
    if app_version and any(character not in allowed_version_characters for character in app_version):
        raise ValueError("app_version may contain only letters, numbers, dots, underscores, plus signs, and hyphens.")

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


def customer_support_guide(payload):
    category = str(payload.get("category", "licensing") or "licensing").strip().lower()
    categories = {"licensing", "update", "recovery", "security", "privacy", "other"}
    if category not in categories:
        raise ValueError("Choose licensing, update, recovery, security, privacy, or other.")
    preview = preview_license(payload)
    rank_tools = customer_rank_tools(payload)
    guides = {
        "licensing": [
            "Read the license status and message shown in Customer Checkup.",
            "Remove accidental spaces before or after the license key.",
            "Use the Windows app to activate or refresh the machine-bound receipt.",
            "If device seats are full, remove an old seat or ask the license owner for help.",
            "Share only the privacy-safe customer summary when requesting support.",
        ],
        "update": [
            "Create a current backup before replacing an installed app folder.",
            "Download only the signed package published by this API.",
            "Use the local file verifier below and require a SHA-256 match.",
            "Keep existing USB keys, local app data, and locked files in place.",
            "Run Microsoft Defender on the downloaded package before installation.",
        ],
        "recovery": [
            "Stop and make a copy of the locked file before experimenting.",
            "Use the original master USB key and the normal Windows unlock workflow.",
            "Try the configured PIN only through the official app interface.",
            "Use the documented recovery or permanent-unlock workflow when available.",
            "Never send the USB secret, PIN, key file, or locked-file contents to support.",
        ],
        "security": [
            "Disconnect from untrusted networks if active compromise is suspected.",
            "Run Microsoft Defender full scan and Microsoft Defender Offline scan.",
            "Do not run malware samples, RATs, laggers, or unknown scripts for testing.",
            "Preserve privacy-safe timestamps and detection names without copying secrets.",
            "Use qualified adult or professional help for high-risk findings.",
        ],
        "privacy": [
            "Keep license keys, PINs, USB secrets, and recovery material out of reports.",
            "Use anonymous device totals instead of machine or customer names.",
            "Export only the privacy-safe customer summary or rank pack.",
            "Review a report before sharing it and remove paths or file contents.",
            "Delete unnecessary exported reports after the support issue is resolved.",
        ],
        "other": [
            "Run Customer Checkup and note which fixed status cards need attention.",
            "Record the exact visible error message and UTC time.",
            "Do not include passwords, keys, PINs, names, paths, or file contents.",
            "Try the same action with a disposable non-private test file when appropriate.",
            "Use the licensed Windows support workflow for a privacy-safe owner message.",
        ],
    }
    steps = list(guides[category])
    if preview["status"] != "active":
        steps.insert(0, f"License status is {preview['status']}. Local unlock and recovery remain available.")
    current_tools = [item["name"] for item in rank_tools.get("current_rank_items", [])]
    return {
        "ok": True,
        "guide_id": f"GUIDE-{category.upper()}",
        "category": category,
        "license_status": preview["status"],
        "rank": preview["plan"]["rank"],
        "rank_name": preview["plan"]["name"],
        "steps": steps,
        "current_rank_tool_names": current_tools,
        "signed_update": {
            "published": preview["release"].get("published", False),
            "version": preview["release"].get("latest_version", ""),
            "package_filename": preview["release"].get("package_filename", ""),
            "size_bytes": preview["release"].get("size_bytes", 0),
            "sha256": preview["release"].get("sha256", ""),
            "download_path": preview["release"].get("download_path", ""),
        },
        "support_channel": "Use the activated Windows app for licensed encrypted support messaging.",
        "local_file_verification": "The browser verifier hashes a selected file locally and does not upload it.",
        "server_time_utc": utc_now(),
        "privacy_notice": (
            "Support guides accept only a fixed category and exclude free-form text, license keys, license ids, "
            "customer identity, notes, machine identifiers, receipts, payment data, paths, PINs, USB secrets, and file contents."
        ),
    }


def customer_timeline(payload):
    """Build a privacy-safe license timeline without activating a device seat."""
    preview = preview_license(payload)
    now = datetime.now(timezone.utc)
    events = []

    def add(identifier, title, at_utc, state, detail):
        if at_utc:
            events.append(
                {
                    "id": identifier,
                    "title": title,
                    "at_utc": at_utc,
                    "state": state,
                    "detail": detail,
                }
            )

    issued_at = str(preview["license"].get("issued_at_utc", ""))
    add(
        "issued",
        "License issued",
        issued_at,
        "complete",
        f"{preview['plan']['name']} rank {preview['plan']['rank']} license created.",
    )

    release = preview["release"]
    if release.get("published") and release.get("published_at_utc"):
        add(
            "release",
            "Signed update published",
            str(release["published_at_utc"]),
            "complete",
            f"Windows release {release.get('latest_version', '')} became available.",
        )

    limited_until = str(preview.get("limited_until_utc", ""))
    if limited_until:
        add(
            "limited-until",
            "Premium limit ends",
            limited_until,
            "upcoming",
            "Local unlock and recovery remain available during the premium limit.",
        )

    expires_at_text = str(preview["license"].get("expires_at_utc", ""))
    expires_at = parse_utc(expires_at_text)
    days_remaining = None
    reminder = {
        "available": False,
        "expires_at_utc": expires_at_text,
        "suggested_reminder_utc": "",
        "advance_days": 30,
        "message": "This license has no expiration date, so no renewal reminder is needed.",
    }
    if expires_at is not None:
        expired = expires_at <= now
        days_remaining = max(0, (expires_at.date() - now.date()).days)
        add(
            "expiration",
            "License expiration",
            expires_at_text,
            "past" if expired else "upcoming",
            "The license has expired." if expired else f"{days_remaining} day(s) remain at the time of this check.",
        )
        suggested = max(now, expires_at - timedelta(days=30))
        reminder = {
            "available": not expired,
            "expires_at_utc": expires_at_text,
            "suggested_reminder_utc": format_utc(suggested),
            "advance_days": 30,
            "message": (
                "Download a local calendar event with a 30-day reminder. No calendar data is uploaded."
                if not expired
                else "The expiration date has passed, so a future calendar reminder is unavailable."
            ),
        }

    checked_at = format_utc(now)
    add(
        "checked",
        "Status checked",
        checked_at,
        "current",
        f"License status is {preview['status']}; this check did not activate a device seat.",
    )
    events.sort(key=lambda item: item["at_utc"])
    return {
        "ok": True,
        "status": preview["status"],
        "plan": {
            "id": preview["plan"]["id"],
            "name": preview["plan"]["name"],
            "rank": preview["plan"]["rank"],
        },
        "event_count": len(events),
        "items": events,
        "days_remaining": days_remaining,
        "renewal_reminder": reminder,
        "does_not_activate": True,
        "server_time_utc": checked_at,
        "privacy_notice": (
            "Timeline responses exclude the license key, license id, customer identity, notes, machine identifiers, "
            "receipts, payment data, paths, PINs, USB secrets, file contents, and calendar-account data."
        ),
    }


def customer_workspace(payload):
    """Build one privacy-safe customer workspace without activating a device seat."""
    require_json_object(payload)
    allowed_fields = {"license_key", "app_version"}
    unknown_fields = sorted(set(payload) - allowed_fields)
    if unknown_fields:
        raise ValueError(f"Unknown customer workspace field: {unknown_fields[0]}.")

    preview = preview_license(payload)
    checkup = customer_checkup(payload)
    timeline = customer_timeline(payload)
    rank_tools = customer_rank_tools(payload)
    upgrade_options = license_upgrade_options(payload)

    target_paths = {
        "license": "/customer",
        "service": "/status",
        "devices": "/customer",
        "expiration": "/shop",
        "update": "/update",
        "rank-tools": "/workspace#rank-tools",
    }
    when_by_severity = {
        "action": "now",
        "check": "soon",
        "info": "maintain",
        "good": "maintain",
    }
    actions = []
    for item in checkup.get("items", []):
        identifier = str(item.get("id", "check"))
        severity = str(item.get("severity", "info"))
        actions.append(
            {
                "id": f"checkup-{identifier}",
                "source": "customer_checkup",
                "when": when_by_severity.get(severity, "maintain"),
                "severity": severity,
                "title": str(item.get("title", "Review customer status")),
                "detail": str(item.get("detail", "Review this customer workspace item.")),
                "target_path": target_paths.get(identifier, "/workspace"),
            }
        )
    actions.extend(
        [
            {
                "id": "recovery-drill",
                "source": "workspace",
                "when": "soon",
                "severity": "check",
                "title": "Complete a recovery-readiness drill",
                "detail": "Use the fixed-field readiness tool before an emergency; it stores no answers.",
                "target_path": "/readiness",
            },
            {
                "id": "safe-support-export",
                "source": "workspace",
                "when": "maintain",
                "severity": "info",
                "title": "Keep a privacy-safe support summary",
                "detail": "Export this workspace without license proof, identity, paths, PINs, USB secrets, or file contents.",
                "target_path": "/workspace",
            },
            {
                "id": "privacy-review",
                "source": "workspace",
                "when": "maintain",
                "severity": "info",
                "title": "Review the privacy boundary",
                "detail": "Confirm which data stays on the customer PC before sending any support information.",
                "target_path": "/privacy",
            },
        ]
    )
    order = {"now": 0, "soon": 1, "maintain": 2}
    actions.sort(key=lambda item: (order.get(item["when"], 3), item["id"]))
    action_counts = {
        name: sum(item["when"] == name for item in actions)
        for name in ("now", "soon", "maintain")
    }

    summary = {
        "status": preview["status"],
        "active": preview["active"],
        "message": preview["message"],
        "plan": preview["plan"],
        "rank_progress": preview["rank_progress"],
        "license": {
            "issued_at_utc": preview["license"].get("issued_at_utc", ""),
            "expires_at_utc": preview["license"].get("expires_at_utc", ""),
        },
        "device_usage": preview["device_usage"],
        "service_status": preview["service_status"],
        "release": preview["release"],
        "limited_until_utc": preview.get("limited_until_utc", ""),
    }
    checkup_by_id = {str(item.get("id", "")): item for item in checkup.get("items", [])}
    score_rules = [
        ("license", "License", 25, {"good": 25, "info": 15, "check": 8, "action": 0}),
        ("service", "Service", 15, {"good": 15, "info": 10, "check": 5, "action": 0}),
        ("devices", "Device seats", 10, {"good": 10, "info": 8, "check": 5, "action": 0}),
        ("expiration", "Renewal timing", 15, {"good": 15, "info": 12, "check": 7, "action": 0}),
        ("update", "Signed desktop release", 20, {"good": 20, "info": 12, "check": 5, "action": 0}),
        ("rank-tools", "Rank access", 15, {"good": 15, "info": 10, "check": 5, "action": 0}),
    ]
    score_factors = []
    workspace_score = 0
    for identifier, title, maximum, awards in score_rules:
        item = checkup_by_id.get(identifier, {})
        severity = str(item.get("severity", "info"))
        awarded = int(awards.get(severity, 0))
        workspace_score += awarded
        score_factors.append(
            {
                "id": identifier,
                "title": title,
                "state": severity,
                "awarded": awarded,
                "maximum": maximum,
                "detail": str(item.get("detail", "No result is available.")),
            }
        )
    score_label = (
        "excellent"
        if workspace_score >= 90
        else "ready"
        if workspace_score >= 75
        else "attention"
        if workspace_score >= 50
        else "action"
    )

    feature_by_id = {item["id"]: item for item in FEATURES}
    unlocked_benefits = []
    for feature_id in preview["plan"].get("entitlements", []):
        feature = feature_by_id.get(feature_id)
        if feature:
            unlocked_benefits.append(
                {
                    "id": feature["id"],
                    "title": feature["title"],
                    "summary": feature["summary"],
                    "category": feature["category"],
                }
            )
    next_option = (upgrade_options.get("items") or [None])[0]
    next_rank = None
    if next_option:
        added_ids = list(next_option.get("added_entitlements", []))
        next_rank = {
            "plan": next_option["plan"],
            "ranks_up": next_option["ranks_up"],
            "added_benefits": [
                {
                    "id": feature_id,
                    "title": feature_by_id.get(feature_id, {}).get("title", feature_id),
                }
                for feature_id in added_ids
            ],
        }

    success_plan = {
        "today": [item for item in actions if item["when"] == "now"],
        "this_week": [item for item in actions if item["when"] == "soon"],
        "this_month": [item for item in actions if item["when"] == "maintain"],
    }
    support_pack = {
        "title": "VaultLink Privacy-Safe Support Pack",
        "facts": [
            {"label": "License status", "value": preview["status"]},
            {"label": "Rank", "value": f"{preview['plan']['rank']} - {preview['plan']['name']}"},
            {"label": "Device seats", "value": f"{preview['device_usage']['active']} of {preview['device_usage']['maximum']}"},
            {"label": "Installed version", "value": str(payload.get("app_version", "") or "Not supplied")},
            {"label": "Latest signed version", "value": preview["release"].get("latest_version", "") or "Not published"},
            {"label": "Service", "value": preview["service_status"].get("mode", "unknown")},
            {"label": "Workspace score", "value": f"{workspace_score} of 100"},
            {"label": "Attention items", "value": str(checkup.get("attention_count", 0))},
        ],
        "safe_to_share_after_review": True,
        "attachments_included": False,
        "instructions": [
            "Review this pack before sharing it.",
            "Describe the visible error separately without adding passwords, keys, PINs, names, paths, or file contents.",
            "Use the activated Windows Bug Center when an owner reply is needed.",
        ],
    }
    recovery_card = {
        "title": "VaultLink Offline Recovery Card",
        "steps": [
            "Stop and keep the original .locked file unchanged.",
            "Make a second copy of the .locked file before troubleshooting.",
            "Use the original master USB key through the official Windows app.",
            "Enter the exact optional PIN only if one was used when locking.",
            "Use Unlock To Folder when a permanent readable copy is needed.",
            "Run Recovery Readiness before changing keys, settings, or app folders.",
            "Never send a USB key file, secret, PIN, locked-file contents, or recovery material to support.",
            "Keep local unlock and recovery available even when premium license status needs attention.",
        ],
        "contains_key_material": False,
        "contains_customer_identity": False,
        "offline_copy_recommended": True,
    }
    factor_by_id = {item["id"]: item for item in score_factors}
    readiness_lanes = []
    for identifier, title, factor_ids, purpose in (
        (
            "account",
            "Account continuity",
            ("license", "devices", "expiration"),
            "Keep the license, device allowance, and renewal timing understandable.",
        ),
        (
            "protection",
            "Signed protection",
            ("update",),
            "Stay on a published desktop package whose signature and SHA-256 digest verify.",
        ),
        (
            "service",
            "Service connection",
            ("service",),
            "Know whether online licensing and support services are available.",
        ),
        (
            "access",
            "Rank access",
            ("rank-tools",),
            "See the fixed tools and benefits included with the current rank.",
        ),
    ):
        factors = [factor_by_id[item_id] for item_id in factor_ids if item_id in factor_by_id]
        awarded = sum(item["awarded"] for item in factors)
        maximum = sum(item["maximum"] for item in factors)
        percent = round((awarded / maximum) * 100) if maximum else 0
        readiness_lanes.append(
            {
                "id": identifier,
                "title": title,
                "purpose": purpose,
                "awarded": awarded,
                "maximum": maximum,
                "percent": percent,
                "state": "ready" if percent >= 75 else "review" if percent >= 50 else "action",
                "attention_count": sum(item["state"] in {"action", "check"} for item in factors),
                "factor_ids": list(factor_ids),
            }
        )

    category_map = {}
    for benefit in unlocked_benefits:
        category = str(benefit.get("category", "Other") or "Other")
        category_map.setdefault(category, []).append(benefit["title"])
    entitlement_categories = [
        {"category": category, "count": len(titles), "items": sorted(titles)}
        for category, titles in sorted(category_map.items())
    ]

    next_best_action = dict(actions[0]) if actions else {
        "id": "maintain-workspace",
        "source": "workspace",
        "when": "maintain",
        "severity": "good",
        "title": "Keep the workspace current",
        "detail": "Reload the workspace after a license, device, service, or signed-release change.",
        "target_path": "/workspace",
    }
    next_best_action.update(
        {
            "position": 1,
            "total_actions": len(actions),
            "reason": (
                "This is the first item after sorting customer actions by urgency. "
                "Completing it is a local customer decision and is never reported to VaultLink."
            ),
        }
    )

    weekly_routine = {
        "title": "Seven-day customer care routine",
        "progress_storage": "customer_device_or_current_browser_only",
        "items": [
            {"id": "monday-status", "day": "Monday", "title": "Check service status", "detail": "Confirm the licensing and support service mode.", "target_path": "/status"},
            {"id": "tuesday-key", "day": "Tuesday", "title": "Confirm recovery material", "detail": "Verify the original USB key is available without opening or sharing it.", "target_path": "/readiness"},
            {"id": "wednesday-backup", "day": "Wednesday", "title": "Review backup readiness", "detail": "Use the fixed backup checklist and keep the original locked data unchanged.", "target_path": "/backup-verification"},
            {"id": "thursday-update", "day": "Thursday", "title": "Check the signed release", "detail": "Install only a package whose signature and SHA-256 digest verify.", "target_path": "/update"},
            {"id": "friday-diagnostics", "day": "Friday", "title": "Run privacy-safe diagnostics", "detail": "Review fixed checks without uploading paths, filenames, or file contents.", "target_path": "/diagnostics"},
            {"id": "saturday-drill", "day": "Saturday", "title": "Practice one recovery drill", "detail": "Use copies and stop if the expected recovery result is unclear.", "target_path": "/recovery-drills"},
            {"id": "sunday-privacy", "day": "Sunday", "title": "Review local data controls", "detail": "Confirm what stays local and what a support export may contain.", "target_path": "/data-control"},
        ],
    }
    help_center = {
        "title": "Customer help paths",
        "items": [
            {"id": "license", "title": "License or device issue", "first_step": "Refresh the saved license and review anonymous seat use.", "target_path": "/customer", "support_category": "licensing"},
            {"id": "update", "title": "Update will not install", "first_step": "Check the signed manifest, package digest, disk space, and supported version.", "target_path": "/update", "support_category": "update"},
            {"id": "unlock", "title": "Locked file will not open", "first_step": "Preserve the original, use the original USB key, and verify whether a PIN was used.", "target_path": "/readiness", "support_category": "recovery"},
            {"id": "backup", "title": "Backup or recovery concern", "first_step": "Work from a copy and complete the fixed backup-verification checklist.", "target_path": "/backup-verification", "support_category": "recovery"},
            {"id": "security", "title": "Security warning or suspicious behavior", "first_step": "Do not disable protection; use the incident guide and Windows Security.", "target_path": "/incident-response", "support_category": "security"},
            {"id": "privacy", "title": "Privacy or data question", "first_step": "Review the data map before exporting or sharing a report.", "target_path": "/data-control", "support_category": "privacy"},
        ],
        "owner_reply_route": "/customer",
        "free_text_not_included": True,
    }
    privacy_guarantees = [
        "The workspace does not activate, remove, reset, or consume a device seat.",
        "Customer identity, owner notes, payment data, receipts, and machine identity are excluded.",
        "Passwords, PINs, USB secrets, key material, paths, filenames, and file contents are excluded.",
        "Checklist progress is local to the customer app or current browser tab and is not uploaded.",
        "The service cannot inspect, lock, unlock, scan, execute, install, or control the customer PC.",
        "Local unlock and recovery remain available when an online premium check needs attention.",
    ]
    customer_snapshot = {
        "status": preview["status"],
        "rank": preview["plan"]["rank"],
        "rank_name": preview["plan"]["name"],
        "workspace_score": workspace_score,
        "attention_count": checkup.get("attention_count", 0),
        "action_count": len(actions),
        "unlocked_tool_count": rank_tools.get("unlocked_count", 0),
        "unlocked_benefit_count": len(unlocked_benefits),
        "readiness_lane_count": len(readiness_lanes),
        "weekly_step_count": len(weekly_routine["items"]),
    }
    lane_by_id = {item["id"]: item for item in readiness_lanes}
    journey_map = {
        "title": "Customer continuity journey",
        "server_tracks_completion": False,
        "stages": [
            {
                "id": "account",
                "order": 1,
                "title": "Confirm account access",
                "state": "ready" if preview["active"] else "action",
                "detail": "Review signed license status and anonymous device-seat capacity.",
                "target_path": "/customer",
            },
            {
                "id": "protect",
                "order": 2,
                "title": "Establish signed protection",
                "state": lane_by_id.get("protection", {}).get("state", "review"),
                "detail": "Use supported app files and install only a verified signed release.",
                "target_path": "/update",
            },
            {
                "id": "prepare",
                "order": 3,
                "title": "Prepare for recovery",
                "state": "available",
                "detail": "Keep the original USB key separate and practice with disposable test data.",
                "target_path": "/readiness",
            },
            {
                "id": "maintain",
                "order": 4,
                "title": "Maintain the workspace",
                "state": "ready" if checkup.get("attention_count", 0) == 0 else "review",
                "detail": "Follow the weekly care routine and review changes without uploading local results.",
                "target_path": "/maintenance",
            },
            {
                "id": "recover",
                "order": 5,
                "title": "Recover and get help",
                "state": "available",
                "detail": "Preserve originals, work from copies, and use the matching fixed help path.",
                "target_path": "/recovery-kit",
            },
        ],
    }
    device_active = int(preview["device_usage"].get("active", 0) or 0)
    device_maximum = int(preview["device_usage"].get("maximum", 0) or 0)
    device_available = max(0, device_maximum - device_active)
    seat_usage_percent = round((device_active / device_maximum) * 100) if device_maximum else 0
    seat_planner = {
        "active": device_active,
        "maximum": device_maximum,
        "available": device_available,
        "usage_percent": seat_usage_percent,
        "state": "available" if device_available > 1 else "review" if device_available == 1 else "full",
        "guidance": (
            "Anonymous capacity is available for another activation."
            if device_available > 0
            else "No anonymous device seats remain; review devices before another activation."
        ),
        "device_identity_included": False,
        "does_not_reserve_or_activate": True,
    }
    support_checks = [
        {
            "id": "license",
            "title": "License status available",
            "ready": bool(preview["active"]),
            "detail": "A signed active status helps support separate licensing from local recovery.",
        },
        {
            "id": "service",
            "title": "Service status available",
            "ready": str(preview["service_status"].get("mode", "")).lower() == "normal",
            "detail": "Current service mode helps distinguish an outage from a local issue.",
        },
        {
            "id": "release",
            "title": "Signed release information available",
            "ready": bool(preview["release"].get("latest_version")),
            "detail": "A published signed version gives support a safe compatibility reference.",
        },
        {
            "id": "support-pack",
            "title": "Privacy-safe support pack available",
            "ready": bool(support_pack.get("safe_to_share_after_review")),
            "detail": "The fixed-field support pack excludes files, paths, identity, secrets, and free text.",
        },
        {
            "id": "recovery-card",
            "title": "Offline recovery card available",
            "ready": bool(recovery_card.get("offline_copy_recommended")),
            "detail": "The card provides recovery order without containing key material.",
        },
    ]
    support_ready_count = sum(item["ready"] for item in support_checks)
    support_readiness = {
        "ready_count": support_ready_count,
        "total": len(support_checks),
        "state": "ready" if support_ready_count == len(support_checks) else "review",
        "items": support_checks,
        "limitations": "This is support-preparation guidance, not proof that a device or file is safe.",
    }
    ninety_day_plan = {
        "title": "Customer 90-day continuity plan",
        "phases": [
            {
                "id": "now",
                "label": "Now",
                "target_days": 1,
                "items": [
                    {
                        "id": next_best_action["id"],
                        "title": next_best_action["title"],
                        "detail": next_best_action["detail"],
                        "target_path": next_best_action["target_path"],
                    }
                ],
            },
            {
                "id": "week",
                "label": "First 7 days",
                "target_days": 7,
                "items": weekly_routine["items"],
            },
            {
                "id": "month",
                "label": "First 30 days",
                "target_days": 30,
                "items": [
                    {
                        "id": item["id"],
                        "title": item["title"],
                        "detail": item["detail"],
                        "target_path": item["target_path"],
                    }
                    for item in actions
                ],
            },
            {
                "id": "quarter",
                "label": "Every 90 days",
                "target_days": 90,
                "items": [
                    {"id": "quarter-recovery", "title": "Repeat a disposable recovery drill", "detail": "Verify the normal key and optional PIN workflow using non-private test data.", "target_path": "/recovery-drills"},
                    {"id": "quarter-backup", "title": "Review backup separation", "detail": "Confirm a recovery copy remains separate from the PC and original USB key.", "target_path": "/backup-verification"},
                    {"id": "quarter-update", "title": "Review supported releases", "detail": "Confirm the installed desktop remains supported and signature verification still succeeds.", "target_path": "/update"},
                    {"id": "quarter-privacy", "title": "Review support-sharing boundaries", "detail": "Confirm exported reports still exclude identity, secrets, paths, and file contents.", "target_path": "/data-control"},
                ],
            },
        ],
        "progress_storage": "customer_device_or_current_browser_only",
    }
    installed_version = str(payload.get("app_version", "") or "").strip()
    latest_signed_version = str(preview["release"].get("latest_version", "") or "")
    change_digest = {
        "api_version": API_VERSION,
        "installed_version": installed_version or "Not supplied",
        "latest_signed_version": latest_signed_version or "Not published",
        "desktop_state": (
            "update_available"
            if preview["release"].get("update_available")
            else "current_or_not_comparable"
        ),
        "service_mode": str(preview["service_status"].get("mode", "unknown")),
        "license_state": str(preview["status"]),
        "changes_customer_pc": False,
    }
    customer_glossary = [
        {"id": "locked-file", "term": "Locked file", "meaning": "An encrypted .locked file that should be preserved unchanged until recovery succeeds."},
        {"id": "master-key", "term": "Master USB key", "meaning": "The original key file used by the official Windows app; it should never be sent to support."},
        {"id": "optional-pin", "term": "Optional PIN", "meaning": "An extra secret used only when one was entered during locking; it is not recoverable from the API."},
        {"id": "signed-release", "term": "Signed release", "meaning": "A desktop package whose Ed25519 manifest signature and SHA-256 package digest verify."},
        {"id": "device-seat", "term": "Device seat", "meaning": "Anonymous activation capacity; customer workspace checks do not consume or reserve one."},
        {"id": "support-pack", "term": "Support pack", "meaning": "A fixed-field status summary that must be reviewed before sharing and contains no attachments."},
        {"id": "recovery-drill", "term": "Recovery drill", "meaning": "A practice lock and unlock performed with disposable, non-private test data."},
        {"id": "owner-message", "term": "Owner message", "meaning": "A rank-targeted service announcement that does not reveal other customer records."},
        {"id": "local-progress", "term": "Local progress", "meaning": "Completed fixed action IDs stored on the customer device or current browser tab, never uploaded."},
        {"id": "workspace-score", "term": "Workspace score", "meaning": "An operational guidance score, not an antivirus result, certification, or guarantee."},
    ]
    customer_snapshot.update(
        {
            "journey_stage_count": len(journey_map["stages"]),
            "available_device_seats": device_available,
            "support_ready_count": support_ready_count,
            "support_check_count": len(support_checks),
            "ninety_day_phase_count": len(ninety_day_plan["phases"]),
            "glossary_term_count": len(customer_glossary),
        }
    )
    return {
        "ok": True,
        "workspace_schema_version": 4,
        "message": "Customer workspace loaded without activating or changing a device seat.",
        "summary": summary,
        "customer_snapshot": customer_snapshot,
        "checkup": checkup,
        "workspace_score": {
            "score": workspace_score,
            "maximum": 100,
            "label": score_label,
            "factors": score_factors,
            "limitations": "This is a customer workspace status score, not an antivirus result, certification, or guarantee.",
        },
        "action_center": {
            "count": len(actions),
            "counts": action_counts,
            "items": actions,
            "progress_storage": "session_only_not_uploaded",
        },
        "timeline": timeline,
        "success_plan": success_plan,
        "benefit_map": {
            "current_rank": {"rank": preview["plan"]["rank"], "name": preview["plan"]["name"]},
            "unlocked_count": len(unlocked_benefits),
            "unlocked": unlocked_benefits,
            "next_rank": next_rank,
        },
        "rank_tools": rank_tools,
        "upgrade_options": upgrade_options,
        "support_pack": support_pack,
        "recovery_card": recovery_card,
        "next_best_action": next_best_action,
        "readiness_lanes": readiness_lanes,
        "weekly_routine": weekly_routine,
        "entitlement_categories": entitlement_categories,
        "help_center": help_center,
        "privacy_guarantees": privacy_guarantees,
        "journey_map": journey_map,
        "seat_planner": seat_planner,
        "support_readiness": support_readiness,
        "ninety_day_plan": ninety_day_plan,
        "change_digest": change_digest,
        "customer_glossary": customer_glossary,
        "support_categories": ["licensing", "update", "recovery", "security", "privacy", "other"],
        "quick_links": [
            {"id": "decision", "label": "RECOVERY DECISION WIZARD", "path": "/decision"},
            {"id": "answers", "label": "CUSTOMER ANSWERS", "path": "/QNA"},
            {"id": "license", "label": "LICENSE DETAILS", "path": "/customer"},
            {"id": "maintenance", "label": "SECURITY MAINTENANCE", "path": "/maintenance"},
            {"id": "retention", "label": "STORAGE & RETENTION", "path": "/retention"},
            {"id": "data", "label": "DATA CONTROL", "path": "/data-control"},
            {"id": "kit", "label": "RECOVERY KIT", "path": "/recovery-kit"},
            {"id": "backup", "label": "BACKUP VERIFICATION", "path": "/backup-verification"},
            {"id": "drills", "label": "RECOVERY DRILLS", "path": "/recovery-drills"},
            {"id": "incident", "label": "INCIDENT RESPONSE", "path": "/incident-response"},
            {"id": "diagnostics", "label": "DIAGNOSTICS", "path": "/diagnostics"},
            {"id": "trust", "label": "TRUST CENTER", "path": "/trust"},
            {"id": "update", "label": "SIGNED UPDATE", "path": "/update"},
            {"id": "recovery", "label": "RECOVERY READINESS", "path": "/readiness"},
            {"id": "status", "label": "SERVICE STATUS", "path": "/status"},
            {"id": "privacy", "label": "PRIVACY", "path": "/privacy"},
            {"id": "shop", "label": "RANK SHOP", "path": "/shop"},
        ],
        "does_not_activate": True,
        "cannot_control_customer_pc": True,
        "server_time_utc": utc_now(),
        "privacy_notice": (
            "Customer workspace responses exclude license keys, license ids, customer labels, email addresses, "
            "owner notes, machine identifiers, activation receipts, payment data, paths, PINs, USB secrets, "
            "file contents, and browser checklist progress."
        ),
    }


def admin_customer_experience():
    """Return aggregate customer-experience health without customer identities."""
    def aggregate_percent(count, maximum, empty=0):
        if int(maximum or 0) <= 0:
            return int(empty)
        return min(100, max(0, round((int(count or 0) / int(maximum)) * 100)))

    dashboard = admin_dashboard_summary()
    inventory = list_admin_license_records()
    plan_counts = {plan["id"]: 0 for plan in PLAN_TIERS}
    for record in inventory.get("items", []):
        plan_id = canonical_plan_id(record.get("plan_id", ""))
        if plan_id in plan_counts:
            plan_counts[plan_id] += 1

    clients = dashboard["client_health"]
    licenses = dashboard["licenses"]
    devices = dashboard["devices"]
    support = dashboard["support_tickets"]
    announcements = dashboard["announcements"]
    release = dashboard["release"]
    shop = dashboard["shop"]
    service = dashboard["service_status"]
    storage = dashboard["storage"]
    active_clients = int(clients.get("active_devices", 0) or 0)
    current_clients = int(clients.get("current_release_devices", 0) or 0)
    adoption = aggregate_percent(current_clients, active_clients, empty=100)
    persistent_stores = sum(value == "persistent_configured" for value in storage.values())
    now = datetime.now(timezone.utc)
    active_records = []
    activated_licenses = 0
    expiring_7_days = 0
    expiring_30_days = 0
    no_expiration = 0
    for record in inventory.get("items", []):
        expires_at = parse_utc(record.get("expires_at_utc"))
        active = record.get("status") != "revoked" and not (expires_at and expires_at <= now)
        if not active:
            continue
        active_records.append(record)
        activated_licenses += int(record.get("active_devices", 0) or 0) > 0
        if expires_at is None:
            no_expiration += 1
            continue
        seconds_left = (expires_at - now).total_seconds()
        if 0 <= seconds_left <= 7 * 86400:
            expiring_7_days += 1
        if 0 <= seconds_left <= 30 * 86400:
            expiring_30_days += 1

    experience_score = 0
    experience_score += 15 if service.get("mode") == "normal" else 5
    if (
        release.get("signed_release_ready")
        and release.get("signature_check") == "passed"
        and release.get("package_hash_check") == "passed"
    ):
        experience_score += 20
    experience_score += round((adoption / 100) * 20)
    experience_score += max(0, 15 - min(15, int(support.get("needs_action", 0) or 0) * 3))
    experience_score += 5 if announcements.get("active") else 0
    shop_total = int(shop.get("total", 0) or 0)
    shop_configured = int(shop.get("configured", 0) or 0)
    experience_score += round((shop_configured / shop_total) * 5) if shop_total else 0
    experience_score += round((persistent_stores / len(storage)) * 10) if storage else 0
    experience_score += 10 if dashboard["api_activity"].get("integrity_valid") else 0
    experience_score = min(100, max(0, experience_score))
    experience_label = (
        "excellent"
        if experience_score >= 90
        else "ready"
        if experience_score >= 75
        else "attention"
        if experience_score >= 50
        else "action"
    )

    actions = [
        {
            "id": "support-inbox",
            "category": "Support",
            "state": "action" if support.get("needs_action") else "good",
            "title": "Review customer support queue",
            "detail": f"{int(support.get('needs_action', 0) or 0)} ticket(s) currently need owner action.",
        },
        {
            "id": "release-adoption",
            "category": "Updates",
            "state": "check" if adoption < 100 else "good",
            "title": "Review signed-release adoption",
            "detail": f"{adoption}% of reporting clients use the current signed desktop release.",
        },
        {
            "id": "stale-clients",
            "category": "Devices",
            "state": "check" if clients.get("stale_24h") else "good",
            "title": "Review stale customer sync",
            "detail": f"{int(clients.get('stale_24h', 0) or 0)} anonymous client(s) have not synced in 24 hours.",
        },
        {
            "id": "service-mode",
            "category": "Service",
            "state": "action" if service.get("mode") != "normal" else "good",
            "title": "Confirm customer service status",
            "detail": str(service.get("message", "No service message is available.")),
        },
        {
            "id": "announcements",
            "category": "Communication",
            "state": "good" if announcements.get("active") else "check",
            "title": "Keep customers informed",
            "detail": f"{int(announcements.get('active', 0) or 0)} active rank-targeted announcement(s).",
        },
        {
            "id": "shop-links",
            "category": "Shop",
            "state": "good" if shop.get("ready") else "check",
            "title": "Check customer purchase routes",
            "detail": f"{int(shop.get('configured', 0) or 0)} of {int(shop.get('total', 0) or 0)} hosted checkout links are configured.",
        },
        {
            "id": "storage",
            "category": "Reliability",
            "state": "good" if persistent_stores == len(storage) else "action",
            "title": "Protect customer service records",
            "detail": f"{persistent_stores} of {len(storage)} service stores report persistent configuration.",
        },
        {
            "id": "activity-integrity",
            "category": "Audit",
            "state": "good" if dashboard["api_activity"].get("integrity_valid") else "action",
            "title": "Verify owner activity integrity",
            "detail": str(dashboard["api_activity"].get("integrity_message", "No integrity result.")),
        },
    ]

    rank_coverage = []
    total_licenses = int(licenses.get("total", 0) or 0)
    for plan in sorted(PLAN_TIERS, key=lambda item: item["rank"]):
        count = int(plan_counts.get(plan["id"], 0))
        rank_coverage.append(
            {
                "rank": plan["rank"],
                "id": plan["id"],
                "name": plan["name"],
                "price_label": plan["price_label"],
                "licenses": count,
                "percent_of_licenses": aggregate_percent(count, total_licenses),
                "entitlement_count": len(plan_entitlements(plan["id"])),
            }
        )

    customer_surfaces = [
        {"id": "workspace", "label": "Customer Workspace", "path": "/workspace", "purpose": "Unified private customer action center", "ready": True},
        {"id": "decision", "label": "Recovery Decision Wizard", "path": "/decision", "purpose": "Ten fixed situations, thirty decision points, and current-tab-only branching", "ready": customer_decisions_payload()["decision_count"] == 30},
        {"id": "answers", "label": "Customer Answers", "path": "/QNA", "purpose": "Thirty fixed answers, safe next steps, and current-tab-only search and saved choices", "ready": customer_answers_payload()["count"] == 30},
        {"id": "maintenance", "label": "Security Maintenance", "path": "/maintenance", "purpose": "Thirty-two fixed tasks, six routines, four cadence horizons, priority review, and current-tab-only coverage", "ready": maintenance_guide_payload()["task_count"] == 32},
        {"id": "retention", "label": "Storage & Retention", "path": "/retention", "purpose": "Eight fixed storage areas, ten retention practices, and current-tab-only review", "ready": retention_guide_payload()["practice_count"] == 10},
        {"id": "data", "label": "Data Control", "path": "/data-control", "purpose": "Fourteen fixed data classes, protection boundaries, retention, and current-tab-only review", "ready": data_control_map_payload()["class_count"] == 14},
        {"id": "kit", "label": "Recovery Kit", "path": "/recovery-kit", "purpose": "Five fixed profiles, fifty kit items, and five first-hour runbooks", "ready": recovery_kit_guide_payload()["item_count"] == 50},
        {"id": "backup", "label": "Backup Verification", "path": "/backup-verification", "purpose": "Twelve fixed plans, restore objectives, and current-tab-only progress", "ready": backup_verification_guide_payload()["step_count"] == 60},
        {"id": "drills", "label": "Recovery Drills", "path": "/recovery-drills", "purpose": "Sixteen fixed exercises and current-tab-only customer progress", "ready": recovery_drill_guide_payload()["step_count"] == 80},
        {"id": "incident", "label": "Incident Response", "path": "/incident-response", "purpose": "Twelve fixed playbooks and session-only customer progress", "ready": incident_guide_payload()["step_count"] == 72},
        {"id": "diagnostics", "label": "Diagnostics Center", "path": "/diagnostics", "purpose": "Fixed-step troubleshooting and safe local reporting", "ready": diagnostics_guide_payload()["step_count"] == 40},
        {"id": "trust", "label": "Trust Center", "path": "/trust", "purpose": "Public service, update, privacy, and recovery posture", "ready": trust_center_payload()["score"]["label"] != "action"},
        {"id": "license", "label": "License Center", "path": "/customer", "purpose": "Detailed read-only license view", "ready": True},
        {"id": "update", "label": "Update Center", "path": "/update", "purpose": "Signed release and local hash verification", "ready": bool(release.get("signed_release_ready"))},
        {"id": "recovery", "label": "Recovery Readiness", "path": "/readiness", "purpose": "Anonymous fixed-field recovery planning", "ready": True},
        {"id": "status", "label": "Service Status", "path": "/status", "purpose": "Public release and service status", "ready": True},
        {"id": "shop", "label": "Rank Shop", "path": "/shop", "purpose": "Seven-rank catalog and hosted checkout routes", "ready": bool(shop.get("ready"))},
        {"id": "privacy", "label": "Privacy", "path": "/privacy", "purpose": "Published customer data boundaries", "ready": True},
    ]
    ready_surfaces = sum(bool(item["ready"]) for item in customer_surfaces)
    active_device_count = int(devices.get("active", 0) or 0)
    customer_journey = [
        {"id": "issued", "label": "Licenses issued", "count": total_licenses, "maximum": total_licenses, "percent": 100 if total_licenses else 0},
        {"id": "active", "label": "Licenses active", "count": len(active_records), "maximum": total_licenses, "percent": aggregate_percent(len(active_records), total_licenses)},
        {"id": "activated", "label": "Active licenses with a device", "count": activated_licenses, "maximum": len(active_records), "percent": aggregate_percent(activated_licenses, len(active_records))},
        {"id": "reporting", "label": "Active devices reporting", "count": active_clients, "maximum": active_device_count, "percent": aggregate_percent(active_clients, active_device_count)},
        {"id": "current", "label": "Reporting devices current", "count": current_clients, "maximum": active_clients, "percent": aggregate_percent(current_clients, active_clients)},
    ]
    return {
        "ok": True,
        "experience_schema_version": 2,
        "metrics": {
            "total_licenses": total_licenses,
            "active_licenses": int(licenses.get("active", 0) or 0),
            "activated_licenses": activated_licenses,
            "active_devices": active_device_count,
            "device_capacity": int(devices.get("capacity", 0) or 0),
            "release_adoption_percent": adoption,
            "current_release_devices": current_clients,
            "support_needs_action": int(support.get("needs_action", 0) or 0),
            "active_announcements": int(announcements.get("active", 0) or 0),
            "shop_links_live": shop_configured,
            "shop_links_total": shop_total,
            "expiring_7_days": expiring_7_days,
            "expiring_30_days": expiring_30_days,
            "experience_score": experience_score,
        },
        "experience_score": {
            "score": experience_score,
            "maximum": 100,
            "label": experience_label,
            "limitations": "Aggregate operational score only; not a security certification or customer guarantee.",
        },
        "actions": actions,
        "rank_coverage": rank_coverage,
        "customer_journey": customer_journey,
        "renewal_health": {
            "expiring_7_days": expiring_7_days,
            "expiring_30_days": expiring_30_days,
            "no_expiration": no_expiration,
            "expired": int(licenses.get("expired", 0) or 0),
        },
        "customer_surfaces": customer_surfaces,
        "surface_summary": {
            "ready": ready_surfaces,
            "total": len(customer_surfaces),
            "attention": len(customer_surfaces) - ready_surfaces,
        },
        "service_status": service,
        "release": release,
        "storage_readiness": f"{persistent_stores} of {len(storage)} persistent",
        "server_time_utc": utc_now(),
        "privacy_notice": (
            "This aggregate console excludes license keys, license ids, customer labels, email addresses, owner notes, "
            "machine identifiers, receipts, report contents, file data, paths, PINs, and USB secrets."
        ),
    }


def require_json_object(payload):
    if not isinstance(payload, dict):
        raise ValueError("Body must be a JSON object.")
    return payload


def issue_license_record(payload):
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
        "account_id": str(payload.get("account_id", "")).strip(),
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


def issue_license(payload):
    if not str(payload.get("account_id", "")).strip():
        raise ValueError(
            "account_id is required. The customer must create an account before a license can be issued."
        )
    account_id = validated_account_id(payload.get("account_id"))
    with LICENSE_STATE_LOCK:
        account = read_account_record(account_id)
        if not account:
            raise FileNotFoundError("Customer account was not found. The customer must create an account first.")
        if account.get("status") != "active":
            raise ValueError("Enable the customer account before issuing a license.")
        private_fields = decrypt_account_private_fields(account)
        username = str(private_fields.get("username", "")).strip()
        issue_payload = dict(payload)
        issue_payload["account_id"] = account_id
        issue_payload["customer_label"] = username
        issue_payload["customer_email"] = ""
        issued = issue_license_record(issue_payload)
        previous_license_id = str(account.get("assigned_license_id", "")).strip()
        new_license_id = str(issued["license"]["license_id"])
        if previous_license_id and previous_license_id != new_license_id:
            update_license_account_binding(previous_license_id, "")
        account["assigned_license_id"] = new_license_id
        write_account_record(account)
    record_api_activity("account_license_assign", "ok", "account", account_id)
    issued["account"] = account_view(account, include_license_key=False)
    issued["account_required"] = True
    return issued


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
    release_status = windows_update_release_status()
    desktop_release = str(release_status.get("version", "")) if release_status.get("ready") else ""
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
            "signed_release_ready": bool(release_status.get("ready")),
            "signature_check": str((release_status.get("checks") or {}).get("ed25519_signature", "failed")),
            "package_hash_check": str((release_status.get("checks") or {}).get("package_sha256", "failed")),
        },
        "server_time_utc": utc_now(),
    }


def admin_trust_center():
    """Build an owner-only, aggregate trust gate without customer identity data."""
    public = trust_center_payload()
    dashboard = admin_dashboard_summary()
    release = dashboard["release"]
    storage = dashboard["storage"]
    support = dashboard["support_tickets"]
    audits = dashboard["audit_exports"]
    clients = dashboard["client_health"]
    service = dashboard["service_status"]
    checks = []

    def add(identifier, category, title, passed, weight, detail, action):
        checks.append(
            {
                "id": identifier,
                "category": category,
                "title": title,
                "state": "good" if passed else "action",
                "passed": bool(passed),
                "weight": int(weight),
                "detail": detail,
                "action": action,
            }
        )

    add("admin-token", "Access", "Admin token configured", admin_token_configured(), 8, "Owner routes require a header token.", "Configure and protect LICENSE_ADMIN_TOKEN.")
    add("license-secret", "Cryptography", "Production license signing secret", not using_default_signing_secret(), 8, "License and receipt signatures do not use the development fallback." if not using_default_signing_secret() else "The development signing fallback is active.", "Configure a strong LICENSE_SIGNING_SECRET and retain it securely.")
    records_secret_configured = bool(os.getenv("LICENSE_RECORDS_SECRET", "").strip())
    add("records-secret", "Cryptography", "Separate private-record secret", records_secret_configured, 6, "Private owner records use an explicitly configured encryption secret." if records_secret_configured else "Private records currently derive protection from the license signing secret.", "Configure LICENSE_RECORDS_SECRET separately and keep a protected recovery copy.")
    add("private-encryption", "Cryptography", "Private record encryption enabled", True, 5, "License notes, customer labels, email, and support private fields are encrypted at rest.", "Keep encryption dependencies and secrets available during upgrades.")
    add("license-storage", "Durability", "License-state storage persistent", storage.get("licenses") == "persistent_configured", 8, str(storage.get("licenses", "unknown")), "Mount a Railway Volume and configure LICENSE_STATE_DIR.")
    add("audit-storage", "Durability", "Audit-export storage persistent", storage.get("audit_exports") == "persistent_configured", 8, str(storage.get("audit_exports", "unknown")), "Mount a Railway Volume and configure AUDIT_EXPORT_DIR.")
    add("service-mode", "Service", "Service mode normal", service.get("mode") == "normal", 6, str(service.get("message", "No service message.")), "Publish a clear service notice and resolve the active maintenance or degradation condition.")
    add("release-ready", "Release", "Signed desktop release ready", bool(release.get("signed_release_ready")), 10, f"Published desktop: {release.get('desktop_version') or 'none'}.", "Build, test, Defender-scan, sign, and publish through Owner Update Lab.")
    add("release-signature", "Release", "Release signature verified", release.get("signature_check") == "passed", 8, f"Ed25519 check: {release.get('signature_check', 'failed')}.", "Remove the release and republish a correctly signed manifest.")
    add("release-hash", "Release", "Release package hash verified", release.get("package_hash_check") == "passed", 8, f"SHA-256 check: {release.get('package_hash_check', 'failed')}.", "Remove the release and republish a package matching the signed digest.")
    add("activity-integrity", "Audit", "Owner API activity chain valid", bool(dashboard["api_activity"].get("integrity_valid")), 8, str(dashboard["api_activity"].get("integrity_message", "No integrity result.")), "Export the activity record, preserve evidence, and investigate the first failed chain entry.")
    support_needs_action = int(support.get("needs_action", 0) or 0)
    add("support-queue", "Customer", "Support queue reviewed", support_needs_action == 0, 5, f"{support_needs_action} support ticket(s) need owner action.", "Review the encrypted support inbox and update each open or acknowledged ticket.")
    breach_levels = audits.get("breach_levels") or {}
    severe_audits = int(breach_levels.get("high", 0) or 0) + int(breach_levels.get("critical", 0) or 0)
    add("audit-findings", "Audit", "No unresolved High or Critical uploads", severe_audits == 0, 7, f"{severe_audits} stored privacy-safe report(s) are High or Critical.", "Download and review each High or Critical privacy-safe report; do not assume it is malware without evidence.")
    active_clients = int(clients.get("active_devices", 0) or 0)
    current_clients = int(clients.get("current_release_devices", 0) or 0)
    adoption = 100 if not active_clients else round((current_clients / active_clients) * 100)
    add("release-adoption", "Customer", "Signed-release adoption at least 80%", adoption >= 80, 5, f"{adoption}% of reporting devices use the current signed release.", "Publish a customer announcement and verify automatic-update compatibility before escalation.")

    score = sum(item["weight"] for item in checks if item["passed"])
    maximum = sum(item["weight"] for item in checks)
    failed = [item for item in checks if not item["passed"]]
    label = "ready" if score >= 90 else "attention" if score >= 65 else "action"
    categories = {}
    for item in checks:
        row = categories.setdefault(item["category"], {"total": 0, "passed": 0, "weight": 0, "earned": 0})
        row["total"] += 1
        row["passed"] += int(item["passed"])
        row["weight"] += item["weight"]
        row["earned"] += item["weight"] if item["passed"] else 0
    return {
        "ok": True,
        "trust_schema_version": 1,
        "score": {"value": score, "maximum": maximum, "label": label, "passed": len(checks) - len(failed), "total": len(checks)},
        "checks": checks,
        "actions": [
            {"id": item["id"], "category": item["category"], "title": item["title"], "action": item["action"]}
            for item in failed
        ],
        "category_summary": [
            {"category": name, **values}
            for name, values in sorted(categories.items())
        ],
        "metrics": {
            "support_needs_action": support_needs_action,
            "high_critical_audits": severe_audits,
            "release_adoption_percent": adoption,
            "active_reporting_devices": active_clients,
            "persistent_stores": sum(value == "persistent_configured" for value in storage.values()),
            "total_stores": len(storage),
        },
        "public_trust_score": public["score"],
        "service_status": service,
        "release": public["signed_release"],
        "storage": storage,
        "limitations": [
            "This owner score is an operational checklist, not certification, legal advice, or a guarantee of security.",
            "A passing API gate cannot test customer backups, USB custody, encryption PINs, local malware state, or successful recovery.",
            "High or Critical audit labels require evidence review and can be false positives.",
        ],
        "privacy_notice": (
            "This owner trust response contains aggregate service results only. It excludes license keys, customer labels, "
            "email addresses, notes, machine hashes, receipts, report contents, file data, paths, PINs, and USB secrets."
        ),
        "server_time_utc": utc_now(),
    }


def admin_maintenance_operations():
    """Build a fixed owner maintenance report from aggregate service state."""
    dashboard = admin_dashboard_summary()
    experience = admin_customer_experience()
    release = windows_update_release_status()
    audit_inventory = list_admin_audit_exports()
    maintenance = maintenance_guide_payload()
    legal = legal_payload()
    docs = docs_payload()
    checks = []

    def add(identifier, category, title, passed, fail_state, priority, detail, action):
        checks.append(
            {
                "id": identifier,
                "category": category,
                "title": title,
                "passed": bool(passed),
                "state": "good" if passed else fail_state,
                "priority": "complete" if passed else priority,
                "detail": detail,
                "action": "" if passed else action,
            }
        )

    storage = dashboard["storage"]
    release_checks = release.get("checks") or {}
    service = dashboard["service_status"]
    clients = dashboard["client_health"]
    devices = dashboard["devices"]
    support = dashboard["support_tickets"]
    announcements = dashboard["announcements"]
    audits = dashboard["audit_exports"]
    activity = dashboard["api_activity"]
    shop = dashboard["shop"]
    renewals = experience["renewal_health"]
    surfaces = experience["surface_summary"]
    high_critical = int((audits.get("breach_levels") or {}).get("high", 0) or 0) + int(
        (audits.get("breach_levels") or {}).get("critical", 0) or 0
    )
    active_clients = int(clients.get("active_devices", 0) or 0)
    current_clients = int(clients.get("current_release_devices", 0) or 0)
    adoption = 100 if not active_clients else round((current_clients / active_clients) * 100)
    records_secret_configured = bool(os.getenv("LICENSE_RECORDS_SECRET", "").strip())

    add("access-admin-token", "Access & Secrets", "Owner admin token configured", admin_token_configured(), "action", "critical", "Owner API routes require the X-License-Admin-Token request header.", "Configure a strong LICENSE_ADMIN_TOKEN and keep it outside source control.")
    add("access-license-secret", "Access & Secrets", "Production license signing secret", not using_default_signing_secret(), "action", "critical", "Signed license keys and activation receipts use a configured HMAC secret." if not using_default_signing_secret() else "The development signing-secret fallback is active.", "Configure and securely retain LICENSE_SIGNING_SECRET.")
    add("access-records-secret", "Access & Secrets", "Separate private-record secret", records_secret_configured, "attention", "high", "Encrypted owner records use a separately configured secret." if records_secret_configured else "Private records derive protection from the license signing secret.", "Configure LICENSE_RECORDS_SECRET separately and retain a protected recovery copy.")
    add("access-private-encryption", "Access & Secrets", "Private fields encrypted at rest", True, "action", "critical", "Customer labels, emails, owner notes, support text, and replies use authenticated encryption.", "")
    add("access-header-only", "Access & Secrets", "Owner token accepted only in a header", True, "action", "critical", "The admin token is never accepted in a JSON body or placed in owner download URLs.", "")

    storage_actions = {
        "licenses": "Mount a Railway Volume and configure LICENSE_STATE_DIR.",
        "audit_exports": "Mount a Railway Volume and configure AUDIT_EXPORT_DIR.",
        "support_tickets": "Keep LICENSE_STATE_DIR on persistent storage for support continuity.",
        "announcements": "Keep LICENSE_STATE_DIR on persistent storage for announcement continuity.",
        "api_activity": "Keep LICENSE_STATE_DIR on persistent storage for owner activity continuity.",
    }
    storage_titles = {
        "licenses": "License and seat storage persistent",
        "audit_exports": "Audit export storage persistent",
        "support_tickets": "Support inbox storage persistent",
        "announcements": "Announcement storage persistent",
        "api_activity": "Owner activity storage persistent",
    }
    for key in ("licenses", "audit_exports", "support_tickets", "announcements", "api_activity"):
        status = str(storage.get(key, "local_ephemeral"))
        add(
            f"storage-{key.replace('_', '-')}",
            "Storage & Recovery",
            storage_titles[key],
            status == "persistent_configured",
            "action",
            "high",
            status,
            storage_actions[key],
        )

    add("release-current", "Signed Releases", "Signed desktop release available", bool(release.get("ready")), "action", "critical", f"Desktop {release.get('version', 'unavailable')} is published." if release.get("ready") else str(release.get("message", "No signed release is ready.")), "Build, Defender-scan, sign, and publish through the Owner Update Lab.")
    add("release-signature", "Signed Releases", "Ed25519 manifest signature passes", release_checks.get("ed25519_signature") == "passed", "action", "critical", f"Signature check: {release_checks.get('ed25519_signature', 'failed')}.", "Remove the release and republish a correctly signed manifest.")
    add("release-size", "Signed Releases", "Published package size matches", release_checks.get("package_size") == "passed", "action", "high", f"Package-size check: {release_checks.get('package_size', 'failed')}.", "Republish the exact package described by the signed manifest.")
    add("release-hash", "Signed Releases", "Published package SHA-256 matches", release_checks.get("package_sha256") == "passed", "action", "critical", f"SHA-256 check: {release_checks.get('package_sha256', 'failed')}.", "Remove the release and publish the exact tested package whose digest matches the manifest.")
    add("release-app-data", "Signed Releases", "Update declares app-data preservation", release_checks.get("app_data_preservation") == "passed", "action", "critical", f"App-data preservation check: {release_checks.get('app_data_preservation', 'failed')}.", "Publish only an update that preserves keys, licenses, settings, vault data, and audit logs.")

    documented_paths = {item.get("path") for item in docs.get("routes", [])}
    add("service-normal", "Service & Surfaces", "Public service mode is normal", service.get("mode") == "normal", "attention", "high", str(service.get("message", "No service message is available.")), "Publish a clear service notice and resolve the active degraded or maintenance condition.")
    add("surfaces-contract", "Service & Surfaces", "All 16 customer surfaces are registered", int(surfaces.get("total", 0) or 0) == 16, "action", "high", f"{int(surfaces.get('total', 0) or 0)} customer surfaces are registered.", "Restore the complete fixed customer-surface contract.")
    add("surfaces-ready", "Service & Surfaces", "Every customer surface reports ready", int(surfaces.get("ready", 0) or 0) == int(surfaces.get("total", 0) or 0), "attention", "medium", f"{int(surfaces.get('ready', 0) or 0)} of {int(surfaces.get('total', 0) or 0)} customer surfaces are ready.", "Review every surface marked for attention before the next release.")
    add("maintenance-contract", "Service & Surfaces", "Maintenance catalog contract passes", maintenance.get("task_count") == 32 and maintenance.get("category_count") == 8 and maintenance.get("routine_count") == 6 and maintenance.get("planning_horizon_count") == 4, "action", "high", f"{maintenance.get('task_count', 0)} tasks, {maintenance.get('category_count', 0)} categories, {maintenance.get('routine_count', 0)} routines, and {maintenance.get('planning_horizon_count', 0)} horizons.", "Restore the fixed maintenance catalog and rerun API regression tests.")
    add("owner-route-contract", "Service & Surfaces", "Owner operations routes documented", "/owner/operations" in documented_paths and "/api/v1/admin/maintenance-operations" in documented_paths, "action", "medium", "The owner page and protected API route are included in the live route index.", "Restore both owner maintenance routes to the API documentation contract.")

    active_devices = int(devices.get("active", 0) or 0)
    device_capacity = int(devices.get("capacity", 0) or 0)
    add("licenses-seat-capacity", "Licensing & Seats", "Active seats do not exceed capacity", active_devices <= device_capacity, "action", "critical", f"{active_devices} active seat(s) out of {device_capacity} available.", "Review the activation ledger and correct any seat-accounting mismatch.")
    add("licenses-stale-clients", "Licensing & Seats", "No clients are stale for 24 hours", int(clients.get("stale_24h", 0) or 0) == 0, "attention", "medium", f"{int(clients.get('stale_24h', 0) or 0)} anonymous client(s) have not synced in 24 hours.", "Confirm service availability and publish update or support guidance before contacting customers.")
    add("licenses-release-adoption", "Licensing & Seats", "Signed-release adoption is at least 80%", adoption >= 80, "attention", "medium", f"{adoption}% of reporting clients use the current signed desktop release.", "Verify compatibility, then publish a rank-targeted update announcement.")
    add("licenses-known-versions", "Licensing & Seats", "Reporting clients identify their app version", int(clients.get("unknown_version_devices", 0) or 0) == 0, "attention", "low", f"{int(clients.get('unknown_version_devices', 0) or 0)} reporting client(s) have an unknown app version.", "Review client compatibility and update reporting without collecting device identity.")
    add("licenses-renewal-window", "Licensing & Seats", "No active licenses expire within 7 days", int(renewals.get("expiring_7_days", 0) or 0) == 0, "attention", "medium", f"{int(renewals.get('expiring_7_days', 0) or 0)} active license(s) expire within seven days.", "Review renewal commitments and contact only the affected customers through approved business records.")

    service_message = str(service.get("message", ""))
    add("support-queue", "Support & Messaging", "Support queue has no waiting work", int(support.get("needs_action", 0) or 0) == 0, "attention", "high", f"{int(support.get('needs_action', 0) or 0)} support ticket(s) need owner action.", "Review, acknowledge, reply to, resolve, or close each waiting ticket.")
    add("support-encryption", "Support & Messaging", "Support private text is encrypted", True, "action", "critical", "Customer reports, owner replies, and private notes use authenticated encryption at rest.", "")
    add("announcements-valid", "Support & Messaging", "No damaged announcement records", int(announcements.get("damaged", 0) or 0) == 0, "action", "high", f"{int(announcements.get('damaged', 0) or 0)} announcement record(s) failed validation.", "Preserve evidence, remove damaged records, and republish only validated plain-text notices.")
    add("announcements-active", "Support & Messaging", "At least one customer announcement is active", int(announcements.get("active", 0) or 0) > 0, "attention", "low", f"{int(announcements.get('active', 0) or 0)} rank-targeted announcement(s) are active.", "Publish a concise current release or service notice when customer communication is useful.")
    add("service-message", "Support & Messaging", "Public service message is present and bounded", bool(service_message.strip()) and len(service_message) <= 240, "action", "medium", f"Public service message length: {len(service_message)} character(s).", "Publish a clear service message of 240 characters or fewer.")

    add("audit-chain", "Audit & Incident Review", "Owner API activity chain verifies", bool(activity.get("integrity_valid")), "action", "critical", str(activity.get("integrity_message", "No integrity result is available.")), "Export the activity record, preserve evidence, and investigate the first failed chain entry.")
    add("audit-severe", "Audit & Incident Review", "No High or Critical audit reports await review", high_critical == 0, "action", "critical", f"{high_critical} stored privacy-safe report(s) are High or Critical.", "Download and review each report; confirm evidence before treating any result as malware.")
    add("audit-records-valid", "Audit & Incident Review", "No damaged stored audit reports", int(audit_inventory.get("damaged_count", 0) or 0) == 0, "action", "high", f"{int(audit_inventory.get('damaged_count', 0) or 0)} stored audit report(s) failed validation.", "Preserve the damaged files, investigate storage integrity, and remove them only after evidence review.")
    add("audit-retention", "Audit & Incident Review", "Audit retention is within policy bounds", 1 <= int(AUDIT_EXPORT_RETENTION_HOURS) <= 2160, "action", "medium", f"Audit retention is {int(AUDIT_EXPORT_RETENTION_HOURS)} hour(s).", "Configure AUDIT_EXPORT_RETENTION_HOURS between 1 and 2160.")
    add("audit-remote-boundary", "Audit & Incident Review", "Remote file and secret collection remains disabled", True, "action", "critical", "The API accepts only approved privacy-safe audit fields and cannot fetch customer files, paths, PINs, or USB secrets.", "")

    add("commerce-ranks", "Commerce & Governance", "Seven license ranks are published", len(PLAN_TIERS) == 7, "action", "high", f"{len(PLAN_TIERS)} license rank(s) are registered.", "Restore the complete seven-rank catalog before selling licenses.")
    add("commerce-checkout", "Commerce & Governance", "Every rank has a hosted checkout route", int(shop.get("configured", 0) or 0) == int(shop.get("total", 0) or 0) == 7, "attention", "medium", f"{int(shop.get('configured', 0) or 0)} of {int(shop.get('total', 0) or 0)} hosted checkout links are configured.", "Configure only allowlisted provider-hosted HTTPS checkout links.")
    add("commerce-card-boundary", "Commerce & Governance", "VaultLink does not collect card data", not bool(shop.get("card_data_collected_by_vaultlink")), "action", "critical", "Payment-card entry stays on the configured hosted payment provider.", "Remove any VaultLink form or endpoint that accepts payment-card secrets.")
    add("governance-legal-draft", "Commerce & Governance", "Legal documents remain clearly marked for review", bool(legal.get("draft")) and bool(legal.get("adult_business_owner_review_required")) and bool(legal.get("qualified_legal_review_recommended")), "action", "high", f"Legal document {legal.get('document_version', 'unknown')} is marked as a draft requiring adult-owner review.", "Keep draft labeling visible and obtain qualified legal review before commercial reliance.")
    add("governance-remote-control", "Commerce & Governance", "Owner operations cannot control customer PCs", True, "action", "critical", "This console is aggregate and read-only toward customer devices; it cannot lock, unlock, execute, scan, delete, or retrieve local data.", "")

    if len(checks) != 40:
        raise RuntimeError(f"Owner maintenance contract expected 40 checks, built {len(checks)}.")
    category_order = [
        "Access & Secrets",
        "Storage & Recovery",
        "Signed Releases",
        "Service & Surfaces",
        "Licensing & Seats",
        "Support & Messaging",
        "Audit & Incident Review",
        "Commerce & Governance",
    ]
    owner_links_by_category = {
        "Access & Secrets": {"path": "/owner/trust", "label": "OPEN TRUST OPERATIONS"},
        "Storage & Recovery": {"path": "/owner/trust", "label": "OPEN TRUST OPERATIONS"},
        "Signed Releases": {"path": "/owner/trust", "label": "OPEN TRUST OPERATIONS"},
        "Service & Surfaces": {"path": "/owner", "label": "OPEN OWNER CONSOLE"},
        "Licensing & Seats": {"path": "/owner", "label": "OPEN LICENSE OPERATIONS"},
        "Support & Messaging": {"path": "/owner", "label": "OPEN SUPPORT OPERATIONS"},
        "Audit & Incident Review": {"path": "/owner", "label": "OPEN AUDIT OPERATIONS"},
        "Commerce & Governance": {"path": "/shop", "label": "OPEN SHOP STATUS"},
    }
    owner_links_by_check = {
        "governance-legal-draft": {"path": "/terms", "label": "OPEN DRAFT TERMS"},
        "commerce-checkout": {"path": "/shop", "label": "OPEN SHOP STATUS"},
        "release-current": {"path": "/update", "label": "OPEN UPDATE CENTER"},
        "release-signature": {"path": "/update", "label": "OPEN UPDATE CENTER"},
        "release-size": {"path": "/update", "label": "OPEN UPDATE CENTER"},
        "release-hash": {"path": "/update", "label": "OPEN UPDATE CENTER"},
        "release-app-data": {"path": "/update", "label": "OPEN UPDATE CENTER"},
        "surfaces-ready": {"path": "/owner/customers", "label": "OPEN CUSTOMER EXPERIENCE"},
        "licenses-release-adoption": {"path": "/owner/customers", "label": "OPEN CUSTOMER EXPERIENCE"},
    }
    for item in checks:
        link = owner_links_by_check.get(item["id"], owner_links_by_category[item["category"]])
        item["owner_path"] = link["path"]
        item["owner_path_label"] = link["label"]

    category_summary = []
    for category in category_order:
        rows = [item for item in checks if item["category"] == category]
        if len(rows) != 5:
            raise RuntimeError(f"Owner maintenance category {category} expected 5 checks, built {len(rows)}.")
        category_passed = sum(item["passed"] for item in rows)
        category_actions = len(rows) - category_passed
        category_critical = sum(not item["passed"] and item["priority"] == "critical" for item in rows)
        category_high = sum(not item["passed"] and item["priority"] == "high" for item in rows)
        category_score = round((category_passed / len(rows)) * 100)
        category_summary.append(
            {
                "category": category,
                "passed": category_passed,
                "total": len(rows),
                "actions": category_actions,
                "critical_actions": category_critical,
                "high_actions": category_high,
                "score": category_score,
                "state": "good" if category_actions == 0 else "action" if category_critical else "attention",
                "owner_path": owner_links_by_category[category]["path"],
                "owner_path_label": owner_links_by_category[category]["label"],
            }
        )
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    runbook = [
        {
            "id": item["id"],
            "category": item["category"],
            "title": item["title"],
            "state": item["state"],
            "priority": item["priority"],
            "detail": item["detail"],
            "action": item["action"],
            "owner_path": item["owner_path"],
            "owner_path_label": item["owner_path_label"],
        }
        for item in sorted(
            (row for row in checks if not row["passed"]),
            key=lambda row: (priority_order.get(row["priority"], 9), checks.index(row)),
        )
    ]
    passed = sum(item["passed"] for item in checks)
    score_value = round((passed / len(checks)) * 100)
    score_label = "ready" if score_value >= 90 else "attention" if score_value >= 70 else "action"
    severity_summary = {
        "complete": passed,
        "critical": sum(not item["passed"] and item["priority"] == "critical" for item in checks),
        "high": sum(not item["passed"] and item["priority"] == "high" for item in checks),
        "medium": sum(not item["passed"] and item["priority"] == "medium" for item in checks),
        "low": sum(not item["passed"] and item["priority"] == "low" for item in checks),
    }
    storage_matrix = [
        {
            "id": key,
            "label": storage_titles[key],
            "status": str(storage.get(key, "local_ephemeral")),
            "persistent": storage.get(key) == "persistent_configured",
        }
        for key in ("licenses", "audit_exports", "support_tickets", "announcements", "api_activity")
    ]
    persistent_stores = sum(item["persistent"] for item in storage_matrix)
    ready_surfaces = int(surfaces.get("ready", 0) or 0)
    total_surfaces = int(surfaces.get("total", 0) or 0)
    customer_impact_points = 0
    customer_impact_points += 2 if service.get("mode") != "normal" else 0
    customer_impact_points += 2 if not release.get("ready") else 0
    customer_impact_points += 1 if ready_surfaces < total_surfaces else 0
    customer_impact_points += 1 if int(support.get("needs_action", 0) or 0) else 0
    customer_impact_points += 2 if high_critical else 0
    customer_impact_points += 1 if adoption < 80 else 0
    customer_impact = (
        "high"
        if customer_impact_points >= 4
        else "watch"
        if customer_impact_points
        else "none"
    )
    briefing_headline = (
        "Immediate owner review required"
        if severity_summary["critical"] or score_label == "action"
        else "Owner review has follow-up items"
        if runbook
        else "Owner operations look ready"
    )
    next_review_minutes = 15 if severity_summary["critical"] else 60 if runbook else 240
    watch_metrics = [
        {"id": "readiness_score", "label": "Readiness score", "value": score_value, "unit": "points", "better": "higher"},
        {"id": "owner_actions", "label": "Owner actions", "value": len(runbook), "unit": "actions", "better": "lower"},
        {"id": "critical_actions", "label": "Critical actions", "value": severity_summary["critical"], "unit": "actions", "better": "lower"},
        {"id": "persistent_stores", "label": "Persistent stores", "value": persistent_stores, "unit": "stores", "better": "higher"},
        {"id": "ready_surfaces", "label": "Ready customer surfaces", "value": ready_surfaces, "unit": "surfaces", "better": "higher"},
        {"id": "release_adoption", "label": "Release adoption", "value": adoption, "unit": "percent", "better": "higher"},
        {"id": "support_queue", "label": "Support queue", "value": int(support.get("needs_action", 0) or 0), "unit": "tickets", "better": "lower"},
        {"id": "high_critical_audits", "label": "High/Critical audits", "value": high_critical, "unit": "reports", "better": "lower"},
        {"id": "stale_clients", "label": "Stale clients", "value": int(clients.get("stale_24h", 0) or 0), "unit": "clients", "better": "lower"},
        {"id": "shop_links", "label": "Hosted checkout links", "value": int(shop.get("configured", 0) or 0), "unit": "links", "better": "higher"},
    ]
    review_windows = [
        {
            "id": "triage-15",
            "minutes": 15,
            "label": "15-minute priority triage",
            "purpose": "Review critical and high owner actions first.",
            "steps": [
                "Refresh the live operations report.",
                "Review Critical actions before High actions.",
                "Confirm service and signed-release status.",
                "Record the next owner action outside VaultLink if follow-up is required.",
            ],
        },
        {
            "id": "release-30",
            "minutes": 30,
            "label": "30-minute release review",
            "purpose": "Verify the customer release and update path.",
            "steps": [
                "Review all five Signed Releases checks.",
                "Open Update Center and confirm the published version.",
                "Review anonymous release adoption and stale-client counts.",
                "Publish a plain-text customer notice only when useful.",
            ],
        },
        {
            "id": "service-60",
            "minutes": 60,
            "label": "60-minute service review",
            "purpose": "Review service, support, audit, storage, and customer surfaces.",
            "steps": [
                "Review every domain below 100 points.",
                "Work the support and audit queues without downloading unnecessary data.",
                "Confirm all persistent stores and public customer surfaces.",
                "Export a SHA-256 evidence receipt after the review.",
            ],
        },
        {
            "id": "full-120",
            "minutes": 120,
            "label": "120-minute full owner review",
            "purpose": "Complete the full fixed owner operations contract.",
            "steps": [
                "Review all forty checks and eight domain scorecards.",
                "Verify access secrets, recovery copies, and persistent storage.",
                "Review licensing, commerce, draft legal status, and customer communication.",
                "Export the safe report, checks CSV, text briefing, and evidence receipt.",
            ],
        },
    ]
    owner_shortcuts = [
        {"id": "owner", "label": "Owner Console", "path": "/owner", "purpose": "Licenses, support, announcements, service, audit, and activity"},
        {"id": "insights", "label": "50-Point Insights", "path": "/owner/insights", "purpose": "Aggregate business and service metrics"},
        {"id": "customers", "label": "Customer Experience", "path": "/owner/customers", "purpose": "Journey, renewal, rank, and customer-surface health"},
        {"id": "trust", "label": "Trust Operations", "path": "/owner/trust", "purpose": "Access, storage, release, audit, and service trust gate"},
        {"id": "update", "label": "Update Center", "path": "/update", "purpose": "Published signed desktop release"},
        {"id": "status", "label": "Customer Status", "path": "/status", "purpose": "Public service and release status"},
        {"id": "shop", "label": "Rank Shop", "path": "/shop", "purpose": "Seven-rank catalog and hosted checkout readiness"},
        {"id": "terms", "label": "Draft Terms", "path": "/terms", "purpose": "Adult-owner and qualified legal review status"},
    ]
    due_minutes_by_priority = {"critical": 15, "high": 60, "medium": 1440, "low": 10080}
    due_label_by_priority = {
        "critical": "Review within 15 minutes",
        "high": "Review within 60 minutes",
        "medium": "Review within 24 hours",
        "low": "Review within 7 days",
    }
    decision_queue = []
    for sequence, item in enumerate(runbook, start=1):
        lane_ids = ["all-actions"]
        if item["priority"] in {"critical", "high"}:
            lane_ids.append("urgent")
        if item["category"] in {"Signed Releases", "Service & Surfaces"}:
            lane_ids.append("release-service")
        if item["category"] in {"Licensing & Seats", "Support & Messaging"}:
            lane_ids.append("customer-support")
        if item["category"] in {"Audit & Incident Review", "Commerce & Governance"}:
            lane_ids.append("evidence-governance")
        decision_queue.append(
            {
                **item,
                "sequence": sequence,
                "suggested_review_minutes": due_minutes_by_priority[item["priority"]],
                "suggested_review_window": due_label_by_priority[item["priority"]],
                "lane_ids": lane_ids,
            }
        )
    review_lane_definitions = [
        ("all-actions", "All owner actions", "Every failed fixed check in priority order."),
        ("urgent", "Urgent review", "Critical and high-priority owner actions."),
        ("release-service", "Release and service", "Signed delivery and customer-surface actions."),
        ("customer-support", "Customers and support", "Licensing, seats, renewal, support, and messaging actions."),
        ("evidence-governance", "Evidence and governance", "Audit, incident, commerce, payment-boundary, and legal-review actions."),
    ]
    review_lanes = [
        {
            "id": identifier,
            "label": label,
            "purpose": purpose,
            "action_count": sum(identifier in item["lane_ids"] for item in decision_queue),
        }
        for identifier, label, purpose in review_lane_definitions
    ]
    gate_definitions = [
        ("owner-access", "Owner Access Gate", "Owner authentication, signing secrets, private encryption, and header-only token handling.", ("Access & Secrets",), "/owner/trust", "OPEN TRUST OPERATIONS"),
        ("service-continuity", "Service Continuity Gate", "Persistent storage, recovery continuity, public service, and customer-surface readiness.", ("Storage & Recovery", "Service & Surfaces"), "/owner/trust", "OPEN TRUST OPERATIONS"),
        ("signed-delivery", "Signed Delivery Gate", "Published package availability, signature, size, digest, and app-data preservation.", ("Signed Releases",), "/update", "OPEN UPDATE CENTER"),
        ("customer-operations", "Customer Operations Gate", "Licensing, seats, renewals, support, announcements, and public messaging.", ("Licensing & Seats", "Support & Messaging"), "/owner/customers", "OPEN CUSTOMER EXPERIENCE"),
        ("evidence-integrity", "Evidence Integrity Gate", "Audit-chain integrity, severe-report review, retention, and remote collection boundaries.", ("Audit & Incident Review",), "/owner", "OPEN AUDIT OPERATIONS"),
        ("commerce-governance", "Commerce & Governance Gate", "Rank catalog, hosted checkout, card-data boundary, draft legal review, and remote-control boundary.", ("Commerce & Governance",), "/shop", "OPEN SHOP STATUS"),
    ]
    approval_gates = []
    for identifier, label, purpose, gate_categories, path, path_label in gate_definitions:
        gate_checks = [item for item in checks if item["category"] in gate_categories]
        failed_checks = [item for item in gate_checks if not item["passed"]]
        blocking_checks = [item for item in failed_checks if item["priority"] == "critical"]
        high_checks = [item for item in failed_checks if item["priority"] == "high"]
        outcome = "blocked" if blocking_checks else "review" if failed_checks else "clear"
        next_check = failed_checks[0] if failed_checks else None
        approval_gates.append(
            {
                "id": identifier,
                "label": label,
                "purpose": purpose,
                "categories": list(gate_categories),
                "passed": len(gate_checks) - len(failed_checks),
                "total": len(gate_checks),
                "score": round(((len(gate_checks) - len(failed_checks)) / len(gate_checks)) * 100),
                "action_count": len(failed_checks),
                "blocking_action_count": len(blocking_checks),
                "high_action_count": len(high_checks),
                "outcome": outcome,
                "state": "action" if blocking_checks else "attention" if failed_checks else "good",
                "check_ids": [item["id"] for item in gate_checks],
                "action_ids": [item["id"] for item in failed_checks],
                "next_action_id": next_check["id"] if next_check else "",
                "next_action": next_check["action"] if next_check else "No gate action is currently required.",
                "owner_path": path,
                "owner_path_label": path_label,
            }
        )
    if sum(item["total"] for item in approval_gates) != len(checks):
        raise RuntimeError("Owner approval gates must cover every fixed check exactly once.")
    return {
        "ok": True,
        "operations_schema_version": 3,
        "api_version": API_VERSION,
        "check_count": len(checks),
        "checks": checks,
        "categories": category_order,
        "category_summary": category_summary,
        "severity_summary": severity_summary,
        "score": {
            "value": score_value,
            "maximum": 100,
            "label": score_label,
            "passed": passed,
            "total": len(checks),
            "actions": len(runbook),
            "limitations": "Operational readiness only; not certification, antivirus proof, legal advice, or a guarantee.",
        },
        "briefing": {
            "headline": briefing_headline,
            "summary": (
                f"{passed} of {len(checks)} fixed checks pass. "
                f"{len(runbook)} owner action(s) remain, including {severity_summary['critical']} critical "
                f"and {severity_summary['high']} high-priority action(s)."
            ),
            "customer_impact": customer_impact,
            "customer_impact_points": customer_impact_points,
            "next_review_minutes": next_review_minutes,
            "top_action_ids": [item["id"] for item in runbook[:5]],
            "service_mode": str(service.get("mode", "unknown")),
            "release_version": str(release.get("version", "")),
        },
        "runbook": runbook,
        "decision_queue": decision_queue,
        "review_lanes": review_lanes,
        "approval_gates": approval_gates,
        "watch_metrics": watch_metrics,
        "review_windows": review_windows,
        "owner_shortcuts": owner_shortcuts,
        "metrics": {
            "persistent_stores": persistent_stores,
            "total_stores": len(storage_matrix),
            "ready_surfaces": ready_surfaces,
            "total_surfaces": total_surfaces,
            "release_adoption_percent": adoption,
            "active_reporting_devices": active_clients,
            "support_needs_action": int(support.get("needs_action", 0) or 0),
            "high_critical_audits": high_critical,
            "active_announcements": int(announcements.get("active", 0) or 0),
            "shop_links_live": int(shop.get("configured", 0) or 0),
            "shop_links_total": int(shop.get("total", 0) or 0),
        },
        "release_gate": {
            "ready": bool(release.get("ready")),
            "version": str(release.get("version", "")),
            "minimum_supported_version": str(release.get("minimum_supported_version", "")),
            "published_at_utc": str(release.get("published_at_utc", "")),
            "package_filename": str(release.get("package_filename", "")),
            "size_bytes": int(release.get("size_bytes", 0) or 0),
            "sha256": str(release.get("sha256", "")),
            "signing_key_id": str(release.get("signing_key_id", "")),
            "message": str(release.get("message", "")),
            "checks": {
                "manifest_schema": str(release_checks.get("manifest_schema", "failed")),
                "ed25519_signature": str(release_checks.get("ed25519_signature", "failed")),
                "package_size": str(release_checks.get("package_size", "failed")),
                "package_sha256": str(release_checks.get("package_sha256", "failed")),
                "app_data_preservation": str(release_checks.get("app_data_preservation", "failed")),
            },
        },
        "storage_matrix": storage_matrix,
        "service_status": service,
        "customer_surfaces": experience["customer_surfaces"],
        "privacy_boundaries": [
            "The owner token stays in current page memory and is sent only in X-License-Admin-Token.",
            "The report contains aggregate counts and configuration states only.",
            "No license key, license id, customer identity, owner note, receipt, or machine identifier is returned.",
            "No file content, full path, PIN, USB secret, customer audit contents, or customer maintenance history is returned.",
            "The owner console cannot lock, unlock, execute, scan, delete, quarantine, or retrieve data from a customer PC.",
            "Text, JSON, CSV, calendar, handoff, and SHA-256 receipt exports are created locally by the browser from this already privacy-safe response.",
            "Review-session completion, lane selection, search, filters, planner state, and change baselines stay only in the current browser tab.",
        ],
        "limitations": [
            "A passing server check cannot test a customer's backups, USB custody, PIN memory, local malware state, or successful recovery.",
            "High and Critical labels can be false positives and require evidence review.",
            "The legal pages remain drafts and do not make VaultLink HIPAA certified or legally compliant.",
            "Payment confirmation and license delivery remain separate owner responsibilities.",
        ],
        "report_contract": {
            "fixed_check_count": 40,
            "fixed_category_count": 8,
            "watch_metric_count": len(watch_metrics),
            "review_window_count": len(review_windows),
            "owner_shortcut_count": len(owner_shortcuts),
            "approval_gate_count": len(approval_gates),
            "review_lane_count": len(review_lanes),
            "decision_queue_source": "failed_checks_only",
            "change_tracking": "current_tab_only",
            "review_plan_state": "current_tab_only",
            "review_session_state": "current_tab_only",
            "auto_refresh_default": False,
            "evidence_hash": "browser_generated_sha256",
            "handoff_export": "browser_generated_fixed_fields",
            "accepts_free_text": False,
            "accepts_files": False,
            "accepts_customer_progress": False,
        },
        "safe_to_export": True,
        "customer_records_included": False,
        "customer_maintenance_history_included": False,
        "cannot_control_customer_pc": True,
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

    def account_session_token(self):
        authorization = self.headers.get("Authorization", "").strip()
        token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
        if not token:
            raise PermissionError("Account session was missing or invalid.")
        return token

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "public, max-age=86400")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            return
        if path == "/":
            self.send_html(homepage_html())
            return
        if path == "/shop":
            self.send_html(shop_html())
            return
        if path == "/customer":
            self.send_html(customer_license_center_html())
            return
        if path == "/account":
            self.send_html(customer_account_html(API_VERSION))
            return
        if path == "/workspace":
            self.send_html(customer_workspace_html(API_VERSION))
            return
        if path in {"/QNA", "/qna", "/answers"}:
            self.send_html(customer_answers_html(API_VERSION))
            return
        if path in {"/decision", "/wizard"}:
            self.send_html(customer_decision_wizard_html(API_VERSION))
            return
        if path == "/maintenance":
            self.send_html(customer_maintenance_html(API_VERSION))
            return
        if path == "/retention":
            self.send_html(customer_retention_html(API_VERSION))
            return
        if path == "/data-control":
            self.send_html(customer_data_control_html(API_VERSION))
            return
        if path == "/recovery-kit":
            self.send_html(customer_recovery_kit_html(API_VERSION))
            return
        if path == "/backup-verification":
            self.send_html(customer_backup_verification_html(API_VERSION))
            return
        if path == "/recovery-drills":
            self.send_html(customer_recovery_drills_html(API_VERSION))
            return
        if path == "/incident-response":
            self.send_html(customer_incident_response_html(API_VERSION))
            return
        if path == "/diagnostics":
            self.send_html(customer_diagnostics_center_html(API_VERSION))
            return
        if path == "/trust":
            self.send_html(customer_trust_center_html(API_VERSION))
            return
        if path == "/update":
            self.send_html(update_center_html())
            return
        if path == "/readiness":
            self.send_html(recovery_readiness_html())
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
        if path == "/owner/accounts":
            self.send_html(owner_accounts_html(API_VERSION))
            return
        if path == "/owner/insights":
            self.send_html(owner_insights_html())
            return
        if path == "/owner/customers":
            self.send_html(owner_customer_experience_html(API_VERSION))
            return
        if path == "/owner/trust":
            self.send_html(owner_trust_center_html(API_VERSION))
            return
        if path == "/owner/operations":
            self.send_html(owner_maintenance_operations_html(API_VERSION))
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
                    "customer_accounts_enabled": True,
                    "customer_passwords_one_way_hashed": True,
                    "customer_account_sessions_hours": ACCOUNT_SESSION_HOURS,
                    "customer_workspace_enabled": True,
                    "customer_answers_enabled": True,
                    "customer_decision_wizard_enabled": True,
                    "security_maintenance_center_enabled": True,
                    "storage_retention_center_enabled": True,
                    "data_control_center_enabled": True,
                    "recovery_kit_builder_enabled": True,
                    "backup_verification_center_enabled": True,
                    "recovery_drill_center_enabled": True,
                    "incident_response_center_enabled": True,
                    "diagnostics_center_enabled": True,
                    "owner_customer_experience_enabled": True,
                    "owner_maintenance_operations_enabled": True,
                    "owner_operations_schema_version": 3,
                    "owner_operations_change_watch_enabled": True,
                    "owner_operations_review_planner_enabled": True,
                    "owner_operations_evidence_receipt_enabled": True,
                    "owner_operations_approval_gates_enabled": True,
                    "owner_operations_review_session_enabled": True,
                    "owner_operations_handoff_export_enabled": True,
                    "public_trust_center_enabled": True,
                    "owner_trust_center_enabled": True,
                    "anonymous_plan_advisor_enabled": True,
                    "shop_checkout_links_configured": shop_payload()["configured_count"],
                    "shop_card_data_collected_by_vaultlink": False,
                    "windows_update_published": UPDATE_MANIFEST_PATH.exists(),
                    "windows_update_center_enabled": True,
                    "recovery_readiness_center_enabled": True,
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
        if path == "/api/v1/accounts/me":
            try:
                self.send_json(account_me(self.account_session_token()))
            except PermissionError as exc:
                self.send_json(
                    {"ok": False, "error": "unauthorized", "message": str(exc)},
                    status=HTTPStatus.UNAUTHORIZED,
                )
            except Exception:
                self.send_json(
                    {"ok": False, "error": "server_error", "message": "Internal server error."},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            return
        if path == "/api/v1/accounts/username-availability":
            try:
                query = parse_qs(parsed.query)
                self.send_json(
                    account_username_availability(
                        (query.get("username") or [""])[0],
                        self.client_address[0],
                    )
                )
            except PermissionError as exc:
                self.send_json(
                    {"ok": False, "error": "rate_limited", "message": str(exc)},
                    status=HTTPStatus.TOO_MANY_REQUESTS,
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
        if path == "/api/v1/customer-answers":
            self.send_json(customer_answers_payload())
            return
        if path == "/api/v1/customer-decisions":
            self.send_json(customer_decisions_payload())
            return
        if path == "/api/v1/trust-center":
            self.send_json(trust_center_payload())
            return
        if path == "/api/v1/maintenance-guide":
            self.send_json(maintenance_guide_payload())
            return
        if path == "/api/v1/retention-guide":
            self.send_json(retention_guide_payload())
            return
        if path == "/api/v1/data-map":
            self.send_json(data_control_map_payload())
            return
        if path == "/api/v1/diagnostics-guide":
            self.send_json(diagnostics_guide_payload())
            return
        if path == "/api/v1/incident-guide":
            self.send_json(incident_guide_payload())
            return
        if path == "/api/v1/recovery-kit":
            self.send_json(recovery_kit_guide_payload())
            return
        if path == "/api/v1/backup-verification":
            self.send_json(backup_verification_guide_payload())
            return
        if path == "/api/v1/recovery-drills":
            self.send_json(recovery_drill_guide_payload())
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
                        "unified privacy-safe customer workspace with a session-only action checklist",
                        "public fixed customer answer catalog with current-tab-only search and saved-answer choices",
                        "public fixed recovery decision wizard with current-tab-only yes-or-no choices and action-plan export",
                        "public fixed security maintenance guidance with current-tab-only review and no remote task completion or PC control",
                        "public fixed storage and retention guidance with current-tab-only review and no remote cleanup capability",
                        "admin-only aggregate customer-experience and seven-rank coverage console",
                        "admin-only fixed 40-check maintenance operations cockpit with six approval gates, a current-tab review session, and privacy-safe evidence exports",
                        "public fixed-step diagnostics with session-only checklist progress and privacy-safe local export",
                        "public trust, signed-release, storage, privacy-boundary, and recovery posture",
                        "admin-only aggregate trust gate with release, audit, storage, and service actions",
                        "fixed-category customer support guides and local signed-update verification metadata",
                        "anonymous Windows version compatibility checks and local update package verification",
                        "anonymous fixed-field recovery-readiness scoring and action-plan export",
                        "public fixed incident playbooks with current-tab-only progress and privacy-safe local export",
                        "public fixed recovery drills with current-tab-only progress and local hash-chained desktop results",
                        "public fixed backup plans with current-tab-only progress and local hash-chained desktop checkpoints",
                        "public fixed recovery kits with current-tab-only progress, local calendar export, and hash-chained desktop snapshots",
                    ],
                    "banned_remote_actions": [
                        "remote unlock",
                        "remote key creation",
                        "remote PIN capture",
                        "remote file reads",
                        "remote vault secret retrieval",
                        "remote storage inventory or cleanup",
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
                        "The maintenance operations cockpit exposes only aggregate checks, fixed actions, public surface states, and signed-release evidence.",
                        "Owner maintenance exports exclude customer records, customer maintenance history, license proof, device identity, files, paths, PINs, and USB secrets.",
                        "Change baselines, auto-refresh choice, review-plan selection, and calendar start time exist only in the current browser tab.",
                        "Approval gates divide the fixed checks exactly once; the decision queue contains only failed fixed checks.",
                        "Review-session marks, lane selection, and handoff generation exist only in the current tab and are not proof that an action was completed.",
                        "The browser evidence receipt hashes a fixed privacy-safe payload with SHA-256 and never includes the admin token.",
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
                        "Support Guide accepts no free-form report text, and browser update verification does not upload the selected file.",
                        "Customer timelines are read-only, and renewal calendar files are created locally without calendar-account access.",
                        "Customer Workspace combines existing read-only checks and never stores the license key or checklist progress.",
                        "Customer Answers accepts no question text or customer data; search and saved-answer choices stay in the current browser tab.",
                        "Recovery Decision Wizard accepts no free-form input or customer data; yes-or-no choices and the resulting action plan stay in the current browser tab.",
                        "Data Control publishes a fixed data map, receives no customer inventory or review progress, and cannot inspect a customer PC.",
                        "The owner customer-experience console exposes aggregate counts only and never returns customer identity or license proof.",
                        "Update Center does not store entered versions, and selected ZIP files are hashed only in the browser.",
                        "Recovery Readiness accepts only seven booleans, stores nothing, and cannot inspect or certify a PC.",
                        "Trust Center exposes configuration states and signed-release evidence but no environment values, customer records, license proof, machine identity, or local PC data.",
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
        if path == "/api/v1/admin/accounts":
            try:
                self.require_admin_token()
                self.send_json(list_admin_accounts())
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
        if path == "/api/v1/admin/updates/windows/status":
            try:
                self.require_admin_token()
                self.send_json(windows_update_release_status())
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
        if path == "/api/v1/admin/customer-experience":
            try:
                self.require_admin_token()
                self.send_json(admin_customer_experience())
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
        if path == "/api/v1/admin/trust-center":
            try:
                self.require_admin_token()
                self.send_json(admin_trust_center())
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
        if path == "/api/v1/admin/maintenance-operations":
            try:
                self.require_admin_token()
                self.send_json(admin_maintenance_operations())
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
            "/api/v1/accounts/register": MAX_ACCOUNT_JSON_BODY_BYTES,
            "/api/v1/accounts/login": MAX_ACCOUNT_JSON_BODY_BYTES,
            "/api/v1/accounts/change-username": MAX_ACCOUNT_JSON_BODY_BYTES,
            "/api/v1/accounts/change-password": MAX_ACCOUNT_JSON_BODY_BYTES,
            "/api/v1/accounts/logout-all": MAX_ACCOUNT_JSON_BODY_BYTES,
            "/api/v1/admin/accounts/assign": MAX_ACCOUNT_JSON_BODY_BYTES,
            "/api/v1/admin/accounts/status": MAX_ACCOUNT_JSON_BODY_BYTES,
            "/api/v1/licenses/issue": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/activate": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/verify": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/preview": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/upgrade-options": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/rank-tools": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/customer-checkup": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/support-guide": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/timeline": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/licenses/customer-workspace": MAX_LICENSE_JSON_BODY_BYTES,
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
            "/api/v1/updates/windows/check": MAX_LICENSE_JSON_BODY_BYTES,
            "/api/v1/readiness/check": MAX_LICENSE_JSON_BODY_BYTES,
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
            if path == "/api/v1/accounts/register":
                self.send_json(
                    register_account(payload, self.client_address[0]),
                    status=HTTPStatus.CREATED,
                )
                return
            if path == "/api/v1/accounts/login":
                self.send_json(login_account(payload, self.client_address[0]))
                return
            if path == "/api/v1/accounts/change-username":
                self.send_json(change_account_username(payload, self.account_session_token()))
                return
            if path == "/api/v1/accounts/change-password":
                self.send_json(change_account_password(payload, self.account_session_token()))
                return
            if path == "/api/v1/accounts/logout-all":
                self.send_json(logout_all_account_sessions(self.account_session_token()))
                return
            if path == "/api/v1/admin/accounts/assign":
                self.require_admin_token()
                self.send_json(assign_account_license(payload))
                return
            if path == "/api/v1/admin/accounts/status":
                self.require_admin_token()
                self.send_json(update_account_status(payload))
                return
            if path == "/api/v1/licenses/issue":
                self.require_admin_token()
                self.send_json(issue_license(payload), status=HTTPStatus.CREATED)
                return
            if path == "/api/v1/updates/windows/check":
                self.send_json(check_windows_update(payload))
                return
            if path == "/api/v1/readiness/check":
                self.send_json(recovery_readiness_check(payload))
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
            if path == "/api/v1/licenses/support-guide":
                self.send_json(customer_support_guide(payload))
                return
            if path == "/api/v1/licenses/timeline":
                self.send_json(customer_timeline(payload))
                return
            if path == "/api/v1/licenses/customer-workspace":
                self.send_json(customer_workspace(payload))
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
