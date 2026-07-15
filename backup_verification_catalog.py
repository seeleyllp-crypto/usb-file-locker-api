import json


def _step(identifier, title, action, expected):
    return {"id": identifier, "title": title, "action": action, "expected": expected}


RESTORE_OBJECTIVES = [
    {"id": "15-minutes", "label": "Critical access in 15 minutes", "minutes": 15},
    {"id": "1-hour", "label": "Critical access in 1 hour", "minutes": 60},
    {"id": "4-hours", "label": "Working recovery in 4 hours", "minutes": 240},
    {"id": "1-day", "label": "Working recovery in 1 day", "minutes": 1440},
    {"id": "3-days", "label": "Full recovery in 3 days", "minutes": 4320},
]


BACKUP_PLANS = [
    {
        "id": "master-key-copies",
        "category": "Keys",
        "title": "Master-key copy verification",
        "summary": "Confirm that independent master-key copies can be identified and tested without exposing key bytes.",
        "steps": [
            _step("key-count", "Count independent key copies", "Count copies without listing paths, labels, or key contents.", "At least two independent copies are understood."),
            _step("key-separate", "Separate key and locked data", "Keep key copies away from the locked-file backup locations.", "One lost location does not remove both key and data."),
            _step("key-compare", "Compare a backup key", "Use Key Inspector or the main recovery tools to compare one selected backup.", "The selected copy matches the intended key ID."),
            _step("key-protect", "Protect physical custody", "Use trusted physical storage and do not send the key through chat or email.", "The unlocking secret is not unnecessarily copied online."),
            _step("key-rehearse", "Run a disposable recovery test", "Use a non-private test item and the backup key without deleting originals.", "The backup key completes an authenticated test unlock."),
        ],
        "success": "Independent key custody and a disposable recovery test were confirmed without exposing key material.",
    },
    {
        "id": "optional-pin-custody",
        "category": "Keys",
        "title": "Optional-PIN custody plan",
        "summary": "Prepare for exact optional-PIN recovery without storing the PIN in VaultLink or beside the key.",
        "steps": [
            _step("pin-scope", "Identify which locks use a PIN", "Use memory or a separate trusted record without entering the PIN here.", "The protected set is understood without revealing the PIN."),
            _step("pin-separate", "Keep PIN knowledge separate", "Do not store the PIN on the master USB or inside the same backup container.", "A stolen key does not automatically include the PIN."),
            _step("pin-case", "Confirm exact spelling rules", "Remember that the optional PIN is exact and case-sensitive.", "Recovery will not fail because of capitalization assumptions."),
            _step("pin-test", "Test with disposable data", "Lock and unlock a non-private test item using the intended PIN.", "The remembered PIN works before important recovery is needed."),
            _step("pin-handoff", "Plan trusted-adult recovery", "Choose a trusted adult or professional process without writing the PIN in this planner.", "A safe human recovery route exists."),
        ],
        "success": "Optional-PIN recovery was rehearsed without recording the PIN in VaultLink.",
    },
    {
        "id": "locked-file-copies",
        "category": "Locked Data",
        "title": "Locked-file backup sets",
        "summary": "Verify encrypted-container copies while leaving originals locked and unchanged.",
        "steps": [
            _step("locked-count", "Count protected sets", "Count backup sets without listing filenames, paths, or contents.", "The number of independent encrypted copies is known."),
            _step("locked-copy", "Copy containers while locked", "Copy .locked files without unlocking, editing, or renaming the originals.", "Authenticated encrypted containers exist elsewhere."),
            _step("locked-separate", "Separate from key custody", "Keep encrypted files and key copies in different protected locations.", "One location does not expose or remove both parts."),
            _step("locked-health", "Check a disposable copied container", "Use Vault Health Center on a non-private copied test container.", "The copied container has a readable supported structure."),
            _step("locked-restore", "Test one copied container", "Unlock a copied disposable item to a separate folder and compare the expected result.", "At least one copied recovery path works."),
        ],
        "success": "Encrypted copies and one disposable restore path were verified without changing originals.",
    },
    {
        "id": "app-data-backup",
        "category": "App Data",
        "title": "VaultLink app-data backup",
        "summary": "Protect settings, audit records, and personal-vault data without including master-key files.",
        "steps": [
            _step("app-create", "Create the backup", "Use BACK UP APP DATA and choose protected removable or approved storage.", "VaultLink creates a normal transparent backup folder."),
            _step("app-summary", "Review the backup summary", "Confirm the summary says keys and locked documents are excluded.", "The backup scope is understood before storage."),
            _step("app-separate", "Keep the backup separate", "Do not keep the only app-data backup on the same Windows drive.", "A device failure does not remove every copy."),
            _step("app-verify", "Verify the folder", "Use Backup Verification Center to check that restorable app-data files are present.", "The selected folder contains a recognized backup set."),
            _step("app-restore", "Rehearse on a disposable setup", "Use a separate Windows account or test device when available; never overwrite the only live copy.", "The restore sequence is understood before an emergency."),
        ],
        "success": "A recognized app-data backup exists away from the live PC and its restore order is understood.",
    },
    {
        "id": "audit-evidence",
        "category": "App Data",
        "title": "Audit evidence continuity",
        "summary": "Preserve privacy-safe audit evidence and its verification material without exporting private file data.",
        "steps": [
            _step("audit-verify", "Verify the local chain", "Open Audit Log Viewer and confirm the hash chain before copying evidence.", "The local audit chain reports valid."),
            _step("audit-export", "Create a reviewed safe export", "Export only the approved audit fields and review them before sharing.", "The export excludes secrets, file contents, and full paths."),
            _step("audit-backup", "Include app audit data", "Create an app-data backup that includes the local audit records and verification file.", "Audit evidence has an offline recovery copy."),
            _step("audit-access", "Protect access", "Use Windows permissions and approved storage access controls.", "Unrelated users cannot casually alter the evidence."),
            _step("audit-recheck", "Recheck after copying", "Open the copied safe export and confirm its expected coarse totals.", "The copied evidence is readable and still privacy-safe."),
        ],
        "success": "Verified audit evidence was preserved and reviewed without exporting private content.",
    },
    {
        "id": "signed-app-rollback",
        "category": "Application",
        "title": "Signed app and rollback copies",
        "summary": "Prepare transparent signed app files and rollback copies without touching LocalAppData.",
        "steps": [
            _step("update-status", "Check the signed release", "Use Update Center to confirm version, Ed25519 signature, package size, and SHA-256.", "The intended package passes every release check."),
            _step("update-download", "Keep a verified package copy", "Download only the published verified ZIP and preserve its displayed SHA-256.", "A known signed installer source is available."),
            _step("update-data", "Separate app files and app data", "Remember that updates replace transparent app files while LocalAppData stays separate.", "Rollback does not require deleting settings or audit history."),
            _step("update-backup", "Locate updater backups", "Use Update Center to identify existing rollback app-file copies.", "The prior transparent app folder is available if needed."),
            _step("update-rehearse", "Rehearse a test-folder launch", "Open a verified copy from a disposable test folder without replacing the stable app.", "A signed fallback can start without changing customer data."),
        ],
        "success": "A signed package and transparent rollback route were confirmed without modifying customer data.",
    },
    {
        "id": "new-device-recovery",
        "category": "Devices",
        "title": "New-device recovery order",
        "summary": "Recover on a replacement PC using signed software, separate backups, and disposable validation first.",
        "steps": [
            _step("device-secure", "Secure and update Windows", "Complete Windows Update and confirm Microsoft Defender protection first.", "The replacement starts from a current protected state."),
            _step("device-app", "Install the signed app folder", "Use only the verified VaultLink package and compare the published SHA-256.", "The transparent app files pass signature checks."),
            _step("device-data", "Restore app data", "Restore a verified app-data backup before changing existing records.", "Settings and audit data return through the documented workflow."),
            _step("device-test", "Test key and PIN with disposable data", "Complete a non-private lock and unlock before opening important containers.", "Key, PIN, and runtime work together."),
            _step("device-files", "Restore locked copies last", "Copy encrypted containers only after the test succeeds and keep originals unchanged.", "Important encrypted data returns after every dependency is verified."),
        ],
        "success": "The replacement-device order was rehearsed with disposable data before important files.",
    },
    {
        "id": "lost-device-continuity",
        "category": "Devices",
        "title": "Lost-device continuity",
        "summary": "Prepare account, license-seat, key, app-data, and locked-file actions from another trusted device.",
        "steps": [
            _step("loss-account", "Secure the Windows account", "Use official account controls to review sign-ins and remove the missing device.", "Unknown device access can be removed."),
            _step("loss-seat", "Remove the anonymous license seat", "Use Customer Center or owner controls without publishing the license key.", "The missing installation loses premium access."),
            _step("loss-keys", "Review key exposure", "Treat a missing master USB as sensitive and use unaffected backup custody.", "Recovery does not depend on the missing key copy."),
            _step("loss-data", "Locate separate backups", "Confirm app-data and locked-file copies are independent of the lost device.", "The missing device is not the only recovery source."),
            _step("loss-replace", "Follow new-device order", "Use signed software, Defender, disposable testing, then copied locked containers.", "Replacement recovery follows a controlled sequence."),
        ],
        "success": "A lost-device path exists without depending on the missing device or exposing credentials.",
    },
    {
        "id": "family-handoff",
        "category": "People",
        "title": "Trusted-family handoff",
        "summary": "Teach a trusted adult the restore order without giving VaultLink secrets, files, or identity data.",
        "steps": [
            _step("family-roles", "Assign fixed roles", "Choose who holds key custody, PIN knowledge, and backup storage outside this planner.", "No one accidental loss removes every recovery part."),
            _step("family-map", "Explain the four backup types", "Distinguish app data, master keys, locked containers, and signed app files.", "The trusted adult knows which backup solves which problem."),
            _step("family-order", "Teach the restore order", "Secure Windows, verify the app, restore app data, test disposal, then restore locked files.", "Important data is not used as the first experiment."),
            _step("family-practice", "Run a disposable handoff", "Have the trusted adult follow a non-private recovery exercise with supervision.", "The instructions work for someone besides the creator."),
            _step("family-review", "Schedule the next review", "Choose a fixed review interval and update only the coarse checkpoint.", "The handoff does not silently become stale."),
        ],
        "success": "A trusted adult completed the recovery order without VaultLink collecting identity or secrets.",
    },
    {
        "id": "small-office-continuity",
        "category": "Business",
        "title": "Small-office continuity pack",
        "summary": "Rehearse a synthetic office recovery with fixed roles, disposable files, and no client data.",
        "steps": [
            _step("office-scope", "Use a synthetic test scope", "Choose one test workstation and disposable files with no client information.", "Production data cannot be changed by the exercise."),
            _step("office-priority", "Choose the restore objective", "Select a fixed recovery-time objective without entering client or case details.", "The team shares one measurable time target."),
            _step("office-copies", "Confirm independent copies", "Count app-data, key, and locked-container sets without listing their locations.", "Single-device loss is not the only recovery route."),
            _step("office-restore", "Run the restore order", "Use signed app files, test keys, app-data backup, and disposable locked files.", "The synthetic workflow returns in the chosen order."),
            _step("office-record", "Save a coarse checkpoint", "Record only plan ID, score, fixed check states, totals, objective, and time.", "No client, employee, path, file, or free-form detail is stored."),
        ],
        "success": "A synthetic office workflow recovered within a fixed target without production data exposure.",
    },
    {
        "id": "ransomware-safe-backups",
        "category": "Security",
        "title": "Ransomware-safe backup decisions",
        "summary": "Practice isolation and preservation decisions only; never run malware or encryption simulations.",
        "steps": [
            _step("ransom-tabletop", "Use a tabletop scenario", "Read the fixed scenario without running code, encrypting files, or changing backups.", "No destructive simulation occurs."),
            _step("ransom-isolate", "State the isolation action", "Disconnect an actually affected PC when files are changing and stop using it.", "Potential spread and overwrite activity are reduced."),
            _step("ransom-preserve", "Preserve affected originals", "Do not pay, rerun, rename, edit, or overwrite affected files or logs.", "Evidence and possible recovery options remain."),
            _step("ransom-clean", "Use a known-clean recovery device", "Follow Microsoft Defender or qualified responder guidance before attaching backups.", "Backups are not connected to an untrusted active system."),
            _step("ransom-order", "Restore copies, not originals", "Use known-good copies and test data first; keep affected originals unchanged.", "Recovery cannot destroy the only remaining evidence."),
        ],
        "success": "Ransomware backup decisions were rehearsed without malware, file changes, or destructive simulation.",
    },
    {
        "id": "full-restore-rehearsal",
        "category": "Recovery",
        "title": "Full disposable restore rehearsal",
        "summary": "Combine signed software, app data, key custody, and copied locked data in one disposable end-to-end check.",
        "steps": [
            _step("full-scope", "Prepare disposable data", "Use a non-private text item, a test destination, and copies of every required recovery part.", "No production file is the first recovery attempt."),
            _step("full-app", "Verify the app and Defender", "Confirm the signed package and current Windows protection before recovery.", "The test environment passes its software gates."),
            _step("full-data", "Verify app-data backup", "Select a recognized backup folder and review the coarse file count only.", "The backup structure is restorable."),
            _step("full-unlock", "Complete copied-item recovery", "Use the intended key and optional PIN to unlock only the disposable copied item.", "Authenticated recovery succeeds without changing originals."),
            _step("full-record", "Save the checkpoint", "Store fixed IDs, score, objective, copy target, totals, timestamp, and hash-chain fields only.", "Future comparison is possible without private data."),
        ],
        "success": "An end-to-end disposable recovery completed and produced a privacy-safe checkpoint.",
    },
]


def fixed_backup_plans():
    return json.loads(json.dumps(BACKUP_PLANS))


def fixed_restore_objectives():
    return json.loads(json.dumps(RESTORE_OBJECTIVES))
