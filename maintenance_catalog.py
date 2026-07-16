import json


CADENCE_DAYS = (7, 14, 30, 60, 90)
PLANNING_HORIZONS = [
    {"id": "all", "label": "All cadence", "maximum_cadence_days": 0},
    {"id": "weekly", "label": "Weekly focus", "maximum_cadence_days": 7},
    {"id": "monthly", "label": "Thirty-day focus", "maximum_cadence_days": 30},
    {"id": "quarterly", "label": "Ninety-day focus", "maximum_cadence_days": 90},
]
SCHEDULE_SCORE_WEIGHTS = {
    "current": 100,
    "due-soon": 65,
    "overdue": 15,
    "not-started": 0,
}

MAINTENANCE_CATEGORIES = [
    {
        "id": "windows-security",
        "title": "Windows Security",
        "summary": "Keep Microsoft Defender and Windows servicing current through visible Windows controls.",
    },
    {
        "id": "signed-software",
        "title": "Signed Software",
        "summary": "Review the transparent VaultLink folder, dependencies, signed release, and retired copies.",
    },
    {
        "id": "key-custody",
        "title": "Key Custody",
        "summary": "Test existing keys with disposable data and keep recovery material separated.",
    },
    {
        "id": "locked-data",
        "title": "Locked Data",
        "summary": "Practice safe lock and unlock handling while preserving encrypted originals and copies.",
    },
    {
        "id": "app-data-backup",
        "title": "App Data Backup",
        "summary": "Create, verify, separate, and understand recovery copies of VaultLink app data.",
    },
    {
        "id": "recovery-practice",
        "title": "Recovery Practice",
        "summary": "Rehearse fixed recovery steps before a real device loss, outage, or replacement.",
    },
    {
        "id": "audit-privacy",
        "title": "Audit & Privacy",
        "summary": "Verify bounded evidence and review what VaultLink keeps, exports, and cleans.",
    },
    {
        "id": "license-service",
        "title": "License & Service",
        "summary": "Review license status, anonymous seats, public service health, and support routes.",
    },
]


def _task(identifier, category_id, title, action, expected, cadence_days):
    return {
        "id": identifier,
        "category_id": category_id,
        "title": title,
        "action": action,
        "expected": expected,
        "cadence_days": cadence_days,
    }


MAINTENANCE_TASKS = [
    _task(
        "defender-protection",
        "windows-security",
        "Review Defender protection",
        "Open Windows Security and review Virus & threat protection without disabling any protection.",
        "Windows reports active protection or gives a visible action that can be reviewed.",
        7,
    ),
    _task(
        "defender-intelligence",
        "windows-security",
        "Update Defender intelligence",
        "Use Windows Security protection updates to check for current Microsoft security intelligence.",
        "The latest available Defender intelligence check finishes normally.",
        7,
    ),
    _task(
        "defender-quick-scan",
        "windows-security",
        "Run a Defender quick scan",
        "Start a Microsoft Defender quick scan and review its exact detection result.",
        "The scan completes; any detection is handled through Windows Security instead of VaultLink.",
        14,
    ),
    _task(
        "windows-update",
        "windows-security",
        "Review Windows Update",
        "Check Windows Update, review pending updates, and restart only when normal work is protected.",
        "Windows reports its current update state and no required restart is forgotten.",
        30,
    ),
    _task(
        "vaultlink-version",
        "signed-software",
        "Check the signed VaultLink version",
        "Open Update Center and compare the installed version with the latest signed release.",
        "The installed version and signed release status are understood before installing anything.",
        14,
    ),
    _task(
        "signed-package-check",
        "signed-software",
        "Verify release signature and hash",
        "Review the Ed25519 manifest result and SHA-256 package result in Update Center.",
        "Both integrity checks pass or the update stays uninstalled.",
        30,
    ),
    _task(
        "app-folder-completeness",
        "signed-software",
        "Review the transparent app folder",
        "Confirm the normal app folder still contains its launchers, Python files, dependency setup, and documentation.",
        "The app uses a complete transparent folder rather than an unknown single-file build.",
        30,
    ),
    _task(
        "retired-copy-review",
        "signed-software",
        "Review retired app copies",
        "Identify obsolete VaultLink app folders only after the current signed copy and rollback path are known good.",
        "Old app copies are not mistaken for the active release, and no app data or keys are removed.",
        60,
    ),
    _task(
        "primary-key-test",
        "key-custody",
        "Test the primary key",
        "Use the existing primary key in a disposable non-private lock and unlock round trip.",
        "The intended key reads correctly without exposing its secret or changing important data.",
        30,
    ),
    _task(
        "backup-key-compare",
        "key-custody",
        "Compare the backup key",
        "Use the local key comparison tool to compare the existing backup with the primary key.",
        "The approved backup matches locally; neither key is uploaded or replaced.",
        60,
    ),
    _task(
        "key-storage-separation",
        "key-custody",
        "Review key and data separation",
        "Confirm the backup key is stored away from the PC, primary USB, PIN, and locked-data backup.",
        "Loss of one location does not expose or destroy every recovery component.",
        30,
    ),
    _task(
        "owner-usb-review",
        "key-custody",
        "Review owner USB policy",
        "Verify the registered owner USB locally and confirm its protected backup remains available.",
        "Owner controls recognize the intended removable USB without creating a replacement key.",
        30,
    ),
    _task(
        "disposable-roundtrip",
        "locked-data",
        "Run a disposable lock round trip",
        "Lock and unlock a new non-private test item using the intended key and optional PIN workflow.",
        "The recovered disposable content matches the original and the real locked files remain unchanged.",
        30,
    ),
    _task(
        "locked-copy-health",
        "locked-data",
        "Check an encrypted backup copy",
        "Run read-only Vault Health checks on a copied non-private .locked test container.",
        "The copied container structure is readable without decrypting or modifying important originals.",
        60,
    ),
    _task(
        "encrypted-copy-count",
        "locked-data",
        "Review independent encrypted copies",
        "Count recovery sets without recording filenames or paths in VaultLink.",
        "At least two intended recovery locations are understood and kept separate from keys.",
        30,
    ),
    _task(
        "temporary-output-review",
        "locked-data",
        "Review temporary unlocked output",
        "Close unlocked viewers and inspect the bounded Storage & Retention preview.",
        "Expired VaultLink temporary copies are understood before any typed-confirmation cleanup.",
        7,
    ),
    _task(
        "appdata-backup-create",
        "app-data-backup",
        "Create an app-data backup",
        "Use Back Up App Data and choose protected storage separate from the live PC.",
        "A transparent recovery copy of approved VaultLink app data is created.",
        30,
    ),
    _task(
        "appdata-backup-verify",
        "app-data-backup",
        "Verify an app-data backup",
        "Use Backup Verification Center on a recognized app-data backup folder.",
        "The backup structure and expected files verify without importing keys or personal documents.",
        30,
    ),
    _task(
        "appdata-backup-separate",
        "app-data-backup",
        "Review backup separation",
        "Confirm the app-data backup is not the same physical device as the live data and primary key.",
        "A PC or single-drive failure does not remove every app-data recovery copy.",
        30,
    ),
    _task(
        "restore-order-review",
        "app-data-backup",
        "Review the restore order",
        "Review the fixed restore objective and safety-snapshot order without replacing live app data.",
        "The restore sequence is understood before an emergency.",
        60,
    ),
    _task(
        "recovery-kit-review",
        "recovery-practice",
        "Review the Recovery Kit",
        "Open Recovery Kit Builder and review the selected fixed profile and first-hour runbook.",
        "The next recovery steps are understood without storing identity, contacts, or secrets.",
        30,
    ),
    _task(
        "recovery-drill-run",
        "recovery-practice",
        "Complete a recovery drill",
        "Use a fixed tabletop or disposable-data drill appropriate for the current setup.",
        "The drill finishes without live malware, destructive simulation, or production data.",
        30,
    ),
    _task(
        "replacement-pc-readiness",
        "recovery-practice",
        "Review replacement-PC readiness",
        "Review the signed app, existing key, app-data backup, and disposable test sequence for a replacement PC.",
        "A replacement plan exists without creating a universal recovery key.",
        90,
    ),
    _task(
        "trusted-helper-handoff",
        "recovery-practice",
        "Review trusted-helper handoff",
        "Explain the fixed recovery order and stop conditions to an authorized trusted adult using disposable data.",
        "The helper understands preservation, privacy, and when qualified help is required.",
        90,
    ),
    _task(
        "audit-chain-verify",
        "audit-privacy",
        "Verify the audit chain",
        "Open Audit Log Viewer and run its full local integrity verification.",
        "The bounded hash chain verifies or the original evidence is preserved for review.",
        14,
    ),
    _task(
        "audit-export-review",
        "audit-privacy",
        "Review a privacy-safe audit export",
        "Export only through Audit Log Viewer and inspect the fields before sharing.",
        "The reviewed export contains no key, PIN, password, file content, client name, or full path.",
        30,
    ),
    _task(
        "data-control-review",
        "audit-privacy",
        "Review the local data map",
        "Open Local Data Control Center and review its fixed classes, controls, and receipt integrity.",
        "VaultLink data boundaries are understood without arbitrary folder scanning.",
        30,
    ),
    _task(
        "retention-review",
        "audit-privacy",
        "Review storage retention",
        "Open Storage & Retention Center and review preservation and cleanup boundaries.",
        "Protected records remain outside cleanup and ordinary deletion is not mistaken for secure erasure.",
        30,
    ),
    _task(
        "license-status-refresh",
        "license-service",
        "Refresh license status",
        "Open Customer Workspace or License Center and refresh the saved license status.",
        "Plan, status, and signed-update access are current without displaying the license key.",
        14,
    ),
    _task(
        "anonymous-seat-review",
        "license-service",
        "Review anonymous device seats",
        "Review active anonymous seats and remove only a device that is intentionally retired or lost.",
        "Intended devices retain access and unknown or retired seats are investigated.",
        30,
    ),
    _task(
        "service-status-review",
        "license-service",
        "Review public service status",
        "Open the public status page before treating an online failure as a local key problem.",
        "Service mode and signed-release availability are understood without sending license data.",
        14,
    ),
    _task(
        "support-channel-review",
        "license-service",
        "Review the official support route",
        "Confirm the visible Bug Center and privacy-safe diagnostic export workflow.",
        "Support evidence can be sent without keys, PINs, receipts, private files, or unnecessary identity.",
        90,
    ),
]

MAINTENANCE_ROUTINES = [
    {
        "id": "weekly-security",
        "label": "Weekly security",
        "summary": "The shortest recurring check for Windows protection, temporary output, service status, and evidence integrity.",
        "task_ids": [
            "defender-protection",
            "defender-intelligence",
            "temporary-output-review",
            "audit-chain-verify",
            "service-status-review",
        ],
    },
    {
        "id": "monthly-core",
        "label": "Monthly core",
        "summary": "A practical monthly pass across updates, keys, locking, backups, recovery, privacy, and licensing.",
        "task_ids": [
            "windows-update",
            "vaultlink-version",
            "primary-key-test",
            "disposable-roundtrip",
            "appdata-backup-create",
            "recovery-kit-review",
            "data-control-review",
            "license-status-refresh",
        ],
    },
    {
        "id": "key-custody",
        "label": "Key custody",
        "summary": "Review the primary key, backup match, physical separation, owner policy, and disposable recovery.",
        "task_ids": [
            "primary-key-test",
            "backup-key-compare",
            "key-storage-separation",
            "owner-usb-review",
            "disposable-roundtrip",
        ],
    },
    {
        "id": "backup-recovery",
        "label": "Backup & recovery",
        "summary": "Review encrypted copies, app-data recovery, fixed runbooks, drills, and replacement readiness.",
        "task_ids": [
            "locked-copy-health",
            "encrypted-copy-count",
            "appdata-backup-create",
            "appdata-backup-verify",
            "appdata-backup-separate",
            "restore-order-review",
            "recovery-kit-review",
            "recovery-drill-run",
            "replacement-pc-readiness",
        ],
    },
    {
        "id": "privacy-evidence",
        "label": "Privacy & evidence",
        "summary": "Verify audit evidence and review data, retention, temporary-output, and support-sharing boundaries.",
        "task_ids": [
            "temporary-output-review",
            "audit-chain-verify",
            "audit-export-review",
            "data-control-review",
            "retention-review",
            "support-channel-review",
        ],
    },
    {
        "id": "full-maintenance",
        "label": "Full maintenance",
        "summary": "Review every fixed maintenance task without adding notes, files, paths, or customer data.",
        "task_ids": [item["id"] for item in MAINTENANCE_TASKS],
    },
]


def fixed_maintenance_categories():
    return json.loads(json.dumps(MAINTENANCE_CATEGORIES))


def fixed_maintenance_tasks():
    return json.loads(json.dumps(MAINTENANCE_TASKS))


def fixed_maintenance_routines():
    return json.loads(json.dumps(MAINTENANCE_ROUTINES))


def fixed_planning_horizons():
    return json.loads(json.dumps(PLANNING_HORIZONS))


_category_ids = {item["id"] for item in MAINTENANCE_CATEGORIES}
_task_ids = {item["id"] for item in MAINTENANCE_TASKS}
_routine_ids = {item["id"] for item in MAINTENANCE_ROUTINES}

if len(MAINTENANCE_CATEGORIES) != 8 or len(MAINTENANCE_TASKS) != 32 or len(MAINTENANCE_ROUTINES) != 6:
    raise RuntimeError("The fixed maintenance catalog cardinality changed unexpectedly.")
if len(_category_ids) != 8 or len(_task_ids) != 32 or len(_routine_ids) != 6:
    raise RuntimeError("Maintenance catalog IDs must be unique.")
if any(item["category_id"] not in _category_ids or item["cadence_days"] not in CADENCE_DAYS for item in MAINTENANCE_TASKS):
    raise RuntimeError("Maintenance tasks must reference a fixed category and cadence.")
if any(sum(task["category_id"] == category_id for task in MAINTENANCE_TASKS) != 4 for category_id in _category_ids):
    raise RuntimeError("Every maintenance category must contain exactly four tasks.")
if any(
    not item["task_ids"]
    or len(item["task_ids"]) != len(set(item["task_ids"]))
    or not set(item["task_ids"]).issubset(_task_ids)
    for item in MAINTENANCE_ROUTINES
):
    raise RuntimeError("Maintenance routines must reference unique fixed tasks.")
if set(MAINTENANCE_ROUTINES[-1]["task_ids"]) != _task_ids:
    raise RuntimeError("The full maintenance routine must contain every fixed task.")
if len(PLANNING_HORIZONS) != 4 or len({item["id"] for item in PLANNING_HORIZONS}) != 4:
    raise RuntimeError("Maintenance planning horizons must contain four unique fixed rows.")
if set(SCHEDULE_SCORE_WEIGHTS) != {"current", "due-soon", "overdue", "not-started"}:
    raise RuntimeError("Maintenance schedule scoring must cover every fixed desktop task state.")
