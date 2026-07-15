import json


RETENTION_AREAS = [
    {"id": "temporary-unlocked-workspace", "label": "Temporary unlocked workspace", "policy": "cleanup-eligible", "purpose": "Short-lived working copies created by explicit local unlock-view actions.", "retention": "Automatic cleanup is attempted; entries older than ten minutes can be reviewed for explicit cleanup.", "customer_control": "Close viewers and use the desktop Storage & Retention Center's typed-confirmation cleanup."},
    {"id": "audit-evidence", "label": "Audit evidence", "policy": "preserve", "purpose": "Bounded privacy-safe app actions and their local integrity key.", "retention": "Rotated by the audit subsystem to a bounded current file and backup set.", "customer_control": "Verify and export from Audit Log Viewer; never clean it from the retention center."},
    {"id": "recovery-history", "label": "Recovery and backup history", "policy": "preserve", "purpose": "Fixed-ID Recovery Kit, Recovery Drill, and Backup Verification results.", "retention": "Bounded exact-schema histories remain until deliberately managed in their source centers.", "customer_control": "Verify integrity before replacing or restoring app data."},
    {"id": "privacy-baselines", "label": "Privacy receipts and baselines", "policy": "preserve", "purpose": "Coarse Data Control, retention, and Vault Health evidence without file inventories.", "retention": "Remains local until deliberately replaced or cleared from the owning center.", "customer_control": "Investigate drift before replacing evidence."},
    {"id": "protected-local-records", "label": "Protected local records", "policy": "preserve", "purpose": "Settings, protected license and owner controls, and the encrypted Personal Vault.", "retention": "Remains until local settings or state are deliberately changed or app data is restored.", "customer_control": "Use the owning app controls and protect app-data backups."},
    {"id": "update-rollback", "label": "Update and rollback records", "policy": "source-center-only", "purpose": "Signed-update status and rollback app files needed after installation.", "retention": "Managed by Update Center and updater boundaries.", "customer_control": "Use Update Center instead of deleting rollback data manually."},
    {"id": "owner-lab", "label": "Private owner-lab records", "policy": "owner-only", "purpose": "Tested candidate packages, private runtimes, preflight evidence, and release history.", "retention": "Bounded by Owner Update Lab runtime maintenance and owner release policy.", "customer_control": "Owner-only; never include it in customer packages or customer cleanup."},
    {"id": "external-customer-data", "label": "External keys, locks, and backups", "policy": "not-inventoried", "purpose": "Customer-selected USB keys, locked containers, and backup destinations.", "retention": "Controlled by the customer outside VaultLink app data.", "customer_control": "Manage those locations directly and keep independent tested recovery copies."},
]

RETENTION_PRACTICES = [
    {"id": "close-viewers", "category": "Temporary data", "title": "Close unlocked viewers", "action": "Close temporary unlocked documents before starting a cleanup review.", "expected": "No active viewer depends on a temporary working copy."},
    {"id": "refresh-preview", "category": "Temporary data", "title": "Refresh the metadata preview", "action": "Run a fresh bounded preview immediately before cleanup.", "expected": "The current eligible band and safety blockers are visible."},
    {"id": "respect-links", "category": "Boundary", "title": "Stop on links or junctions", "action": "Do not follow or bypass a reparse-point warning.", "expected": "Cleanup stays inside the exact VaultLink temporary directory."},
    {"id": "typed-confirmation", "category": "Boundary", "title": "Require typed confirmation", "action": "Use the exact CLEAN TEMP confirmation only after reviewing the preview.", "expected": "Cleanup cannot start through an accidental single click."},
    {"id": "preserve-audit", "category": "Evidence", "title": "Preserve audit evidence", "action": "Manage audit records only from Audit Log Viewer and verified app-data recovery.", "expected": "Retention cleanup never removes audit records or the integrity key."},
    {"id": "preserve-recovery", "category": "Evidence", "title": "Preserve recovery histories", "action": "Verify Recovery Kit, Drill, and Backup Verification chains before changing app data.", "expected": "Hash-chained recovery evidence remains reviewable."},
    {"id": "preserve-vault", "category": "Protected data", "title": "Preserve settings and vault data", "action": "Use the owning VaultLink controls for settings, licenses, owner policy, and Personal Vault.", "expected": "The retention center never deletes protected local records."},
    {"id": "manage-updates", "category": "Updates", "title": "Manage rollback in Update Center", "action": "Keep rollback files until the installed update is known good.", "expected": "A verified rollback path remains available during update review."},
    {"id": "separate-owner-lab", "category": "Owner", "title": "Keep owner-lab data private", "action": "Keep candidates, signing evidence, and private runtimes out of customer packages.", "expected": "Customer cleanup and exports contain no owner-lab material."},
    {"id": "review-export", "category": "Privacy", "title": "Review coarse exports", "action": "Review every retention report because category presence can still be sensitive.", "expected": "Shared exports contain fixed IDs and coarse bands only."},
]

CLEANUP_FLOW = [
    {"id": "preview", "label": "Preview exact temp boundary", "detail": "The desktop reads stat metadata only from the exact VaultLink temporary workspace."},
    {"id": "block", "label": "Stop on unsafe structure", "detail": "Links, junctions, metadata errors, or the 5,000-entry cap block cleanup."},
    {"id": "close", "label": "Close active viewers", "detail": "The customer closes working copies before confirming removal."},
    {"id": "confirm", "label": "Type CLEAN TEMP", "detail": "A second exact confirmation is required after the visible warning."},
    {"id": "revalidate", "label": "Revalidate and record", "detail": "Age and boundary are checked again before deletion, then a coarse hash-chained receipt is saved."},
]


def fixed_retention_areas():
    return json.loads(json.dumps(RETENTION_AREAS))


def fixed_retention_practices():
    return json.loads(json.dumps(RETENTION_PRACTICES))


def fixed_cleanup_flow():
    return json.loads(json.dumps(CLEANUP_FLOW))


if len(RETENTION_AREAS) != 8 or len(RETENTION_PRACTICES) != 10 or len(CLEANUP_FLOW) != 5:
    raise RuntimeError("The fixed retention catalog cardinality changed unexpectedly.")

if len({item["id"] for item in RETENTION_AREAS}) != 8 or len({item["id"] for item in RETENTION_PRACTICES}) != 10:
    raise RuntimeError("Retention catalog IDs must be unique.")
