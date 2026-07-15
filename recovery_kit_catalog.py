import json


def _item(identifier, title, action, expected):
    return {"id": identifier, "title": title, "action": action, "expected": expected}


KIT_PROFILES = [
    {
        "id": "personal-pc",
        "label": "Personal PC",
        "summary": "A complete personal recovery kit for one Windows PC.",
        "section_ids": [
            "signed-software",
            "master-key-custody",
            "optional-pin-plan",
            "locked-data-copies",
            "app-data-backup",
            "license-device-recovery",
            "audit-evidence",
            "first-hour-response",
            "continuity-review",
        ],
    },
    {
        "id": "family-handoff",
        "label": "Family handoff",
        "summary": "A recovery kit that a trusted adult can follow without receiving secrets here.",
        "section_ids": [
            "signed-software",
            "master-key-custody",
            "optional-pin-plan",
            "locked-data-copies",
            "app-data-backup",
            "license-device-recovery",
            "audit-evidence",
            "trusted-person-handoff",
            "first-hour-response",
            "continuity-review",
        ],
    },
    {
        "id": "travel-device",
        "label": "Travel device",
        "summary": "A compact kit for device loss, replacement, and account recovery while away.",
        "section_ids": [
            "signed-software",
            "master-key-custody",
            "optional-pin-plan",
            "app-data-backup",
            "license-device-recovery",
            "first-hour-response",
            "continuity-review",
        ],
    },
    {
        "id": "small-office",
        "label": "Small office",
        "summary": "A synthetic continuity kit for a small team without client or employee data.",
        "section_ids": [
            "signed-software",
            "master-key-custody",
            "optional-pin-plan",
            "locked-data-copies",
            "app-data-backup",
            "license-device-recovery",
            "audit-evidence",
            "trusted-person-handoff",
            "first-hour-response",
            "continuity-review",
        ],
    },
    {
        "id": "high-assurance",
        "label": "High-assurance review",
        "summary": "Every fixed section for customers who want the broadest recovery rehearsal.",
        "section_ids": [
            "signed-software",
            "master-key-custody",
            "optional-pin-plan",
            "locked-data-copies",
            "app-data-backup",
            "license-device-recovery",
            "audit-evidence",
            "trusted-person-handoff",
            "first-hour-response",
            "continuity-review",
        ],
    },
]


KIT_SECTIONS = [
    {
        "id": "signed-software",
        "category": "Application",
        "title": "Signed software kit",
        "summary": "Keep a transparent, verified way to reinstall VaultLink without touching customer data.",
        "items": [
            _item("software-official-source", "Use the official source", "Keep the pinned VaultLink repository or published update address available.", "The app source can be identified without a search-result guess."),
            _item("software-version-floor", "Record the supported version floor", "Use Update Center to review the current and minimum supported versions.", "An obsolete build will not be mistaken for a safe fallback."),
            _item("software-manifest", "Verify the release manifest", "Confirm the published Ed25519 signature before trusting a package.", "The release manifest passes its signature check."),
            _item("software-package-hash", "Verify the package hash", "Compare the downloaded ZIP against the published SHA-256 and size.", "The exact transparent package is verified."),
            _item("software-offline-copy", "Keep a verified offline copy", "Store a verified package separately from the live PC without adding keys or customer data.", "A clean reinstall source remains available after device loss."),
        ],
    },
    {
        "id": "master-key-custody",
        "category": "Access",
        "title": "Master-key custody",
        "summary": "Prepare independent key custody without recording key bytes, labels, or locations.",
        "items": [
            _item("key-primary-test", "Test the primary key", "Use disposable data to confirm the selected key completes an authenticated unlock.", "The working key is known before an emergency."),
            _item("key-independent-copy", "Keep an independent key copy", "Maintain another protected copy outside the live PC and away from the first copy.", "One device or location loss does not remove every key."),
            _item("key-id-check", "Check the intended key ID", "Use Key Inspector locally and compare only the fixed key identifier.", "A backup key can be matched without exposing its secret."),
            _item("key-data-separation", "Separate key and locked data", "Do not keep the only key beside the only encrypted-container copy.", "One theft does not automatically include both recovery parts."),
            _item("key-trusted-custody", "Plan trusted custody", "Choose a trusted adult or professional process outside this app without entering identity details.", "A recovery path exists if the primary holder is unavailable."),
        ],
    },
    {
        "id": "optional-pin-plan",
        "category": "Access",
        "title": "Optional-PIN plan",
        "summary": "Prepare exact PIN recovery while keeping the PIN out of VaultLink and away from the key.",
        "items": [
            _item("pin-scope", "Know which locks use a PIN", "Use memory or a separate approved process without entering the PIN here.", "The PIN-protected recovery scope is understood."),
            _item("pin-separate", "Keep PIN knowledge separate", "Do not store the PIN on the master USB or inside the same backup container.", "A stolen key does not automatically include the PIN."),
            _item("pin-exact-rules", "Remember exact spelling", "Treat the optional PIN as case-sensitive and exact.", "Recovery does not depend on capitalization guesses."),
            _item("pin-disposable-test", "Run a disposable PIN test", "Lock and unlock a non-private copied item with the intended PIN.", "The remembered PIN works before important recovery is needed."),
            _item("pin-recovery-boundary", "Set a recovery boundary", "Use a trusted adult or qualified process without placing the PIN in support messages.", "PIN recovery does not expose the secret to VaultLink or the API."),
        ],
    },
    {
        "id": "locked-data-copies",
        "category": "Data",
        "title": "Locked-data copies",
        "summary": "Preserve authenticated encrypted containers while keeping originals unchanged.",
        "items": [
            _item("locked-scope-count", "Count protected sets", "Count backup sets without listing filenames, paths, or contents.", "The number of independent encrypted sets is understood."),
            _item("locked-second-copy", "Keep a second locked copy", "Copy containers while they remain locked and do not rename or edit originals.", "An authenticated encrypted copy exists elsewhere."),
            _item("locked-independent-place", "Use an independent location", "Keep the only copy away from the live Windows drive.", "A drive failure does not remove every encrypted copy."),
            _item("locked-preserve-original", "Preserve originals", "Recover to a separate destination and never overwrite the only original during testing.", "A failed rehearsal cannot destroy the source."),
            _item("locked-sample-restore", "Test a disposable copied item", "Use a copied non-private item to rehearse the full unlock flow.", "At least one copied recovery route is proven."),
        ],
    },
    {
        "id": "app-data-backup",
        "category": "Data",
        "title": "App-data backup",
        "summary": "Protect settings, audit records, and vault data without including master keys.",
        "items": [
            _item("appdata-create", "Create an app-data backup", "Use VaultLink's reviewed backup action and choose protected storage.", "A transparent backup folder is created."),
            _item("appdata-verify", "Verify the backup structure", "Use Backup Verification Center to recognize restorable app-data files.", "The selected folder has a supported structure."),
            _item("appdata-second-copy", "Keep an independent copy", "Do not leave the only app-data backup on the live Windows drive.", "Device failure is not the only copy."),
            _item("appdata-restore-order", "Know the restore order", "Restore app data before important locked containers and test with disposable data first.", "Settings and evidence return in a controlled order."),
            _item("appdata-recent-check", "Review backup age", "Use a fixed review interval and create a new backup after meaningful configuration changes.", "The recovery copy does not silently become stale."),
        ],
    },
    {
        "id": "license-device-recovery",
        "category": "Service",
        "title": "License and device recovery",
        "summary": "Prepare customer self-service without placing license proof into this kit.",
        "items": [
            _item("license-center-route", "Know the License Center route", "Use the customer License Center to review status without activating a seat.", "The official self-service route is available."),
            _item("license-seat-review", "Review anonymous seat use", "Check the coarse active-seat total without collecting PC names or raw identifiers.", "Unexpected seat pressure can be recognized."),
            _item("license-device-remove", "Know device removal", "Use customer or owner controls to remove a lost device receipt when needed.", "A missing installation can lose premium access."),
            _item("license-offline-boundary", "Understand offline grace", "Local unlock and recovery remain separate from premium API availability.", "A service outage is not mistaken for data loss."),
            _item("license-support-route", "Keep the safe support route", "Use Bug Center without attaching keys, receipts, logs, paths, or files automatically.", "Support can begin without exposing recovery secrets."),
        ],
    },
    {
        "id": "audit-evidence",
        "category": "Evidence",
        "title": "Audit evidence kit",
        "summary": "Preserve reviewed coarse evidence and its integrity status without private file data.",
        "items": [
            _item("audit-chain-valid", "Verify the local chain", "Open Audit Log Viewer and confirm the hash chain before exporting.", "Evidence starts from a valid local chain."),
            _item("audit-safe-export", "Create a reviewed safe export", "Export only approved event fields and review the result before sharing.", "Secrets, contents, and full paths are absent."),
            _item("audit-independent-copy", "Keep an independent evidence copy", "Include audit data in a protected app-data backup.", "A device failure does not remove all evidence."),
            _item("audit-time-order", "Preserve time order", "Keep sequence, UTC time, action, result, event ID, and chain fields unchanged.", "The event order remains verifiable."),
            _item("audit-privacy-review", "Review before disclosure", "Use the Audit Log label and never describe the feature as a keylogger.", "Evidence remains purpose-limited and privacy-safe."),
        ],
    },
    {
        "id": "trusted-person-handoff",
        "category": "People",
        "title": "Trusted-person handoff",
        "summary": "Teach a fixed restore order without collecting a person's name or contact details.",
        "items": [
            _item("person-choose-adult", "Choose a trusted adult", "Choose the person outside this app and do not enter identity details here.", "A responsible recovery helper exists."),
            _item("person-explain-parts", "Explain the recovery parts", "Distinguish signed app files, app data, keys, PIN knowledge, and locked containers.", "The helper knows which part solves which problem."),
            _item("person-separate-secrets", "Keep secrets separated", "Do not give one casual location every key, PIN, and data copy.", "One mistake does not expose every recovery part."),
            _item("person-emergency-boundary", "Set emergency boundaries", "Define when to use Windows Security, the owner, or a qualified professional.", "The helper does not improvise destructive actions."),
            _item("person-practice", "Practice with disposable data", "Have the trusted adult follow a non-private rehearsal with supervision.", "The written order works for someone besides the creator."),
        ],
    },
    {
        "id": "first-hour-response",
        "category": "Response",
        "title": "First-hour response",
        "summary": "Use a fixed safe order when something breaks or looks suspicious.",
        "items": [
            _item("response-stop-changes", "Stop unnecessary changes", "Do not repeatedly run, rename, delete, or overwrite affected files.", "Recovery options and evidence are preserved."),
            _item("response-preserve-originals", "Preserve originals", "Work from copies and keep affected originals unchanged.", "Testing cannot remove the only remaining source."),
            _item("response-security-check", "Use Windows Security", "Use Microsoft Defender and trusted Windows controls for suspected malware.", "Security decisions use the platform protection layer."),
            _item("response-choose-runbook", "Choose the matching runbook", "Select only the fixed scenario that matches the visible problem.", "The response starts from a bounded known workflow."),
            _item("response-disposable-first", "Restore disposable data first", "Prove the full order with non-private copied data before important recovery.", "Important data is not the first experiment."),
        ],
    },
    {
        "id": "continuity-review",
        "category": "Recovery",
        "title": "Continuity review",
        "summary": "Turn the recovery kit into a repeatable fixed schedule and coarse checkpoint.",
        "items": [
            _item("review-objective", "Choose a recovery objective", "Select a fixed time target without entering case or customer details.", "The expected recovery window is measurable."),
            _item("review-copy-target", "Choose a copy target", "Use a fixed one-to-five copy target and keep failure domains separate.", "The intended redundancy is explicit."),
            _item("review-interval", "Choose a review interval", "Use 7, 14, 30, 60, or 90 days.", "The next review can be scheduled without free-form data."),
            _item("review-snapshot", "Save a coarse snapshot", "Store only fixed IDs, scores, totals, interval, timestamp, and hash-chain fields.", "Future comparison contains no secrets or paths."),
            _item("review-escalation", "Know when to escalate", "Use a trusted adult, Microsoft support, or a qualified responder for high-impact decisions.", "The kit does not pretend to replace professional help."),
        ],
    },
]


EMERGENCY_RUNBOOKS = [
    {
        "id": "replacement-pc",
        "label": "Replacement PC",
        "summary": "Restore on a replacement Windows PC in a controlled order.",
        "steps": [
            "Complete Windows Update and confirm Microsoft Defender protection.",
            "Download only the signed VaultLink package and verify its SHA-256.",
            "Restore a recognized app-data backup without deleting the backup source.",
            "Test the intended key and optional PIN with disposable copied data.",
            "Copy important locked containers only after the disposable test succeeds.",
            "Review the anonymous license seat and remove the old device when appropriate.",
        ],
    },
    {
        "id": "lost-master-usb",
        "label": "Lost master USB",
        "summary": "Protect recovery options when a master-key copy is missing.",
        "steps": [
            "Stop creating new locks with the missing key setup.",
            "Use an unaffected independent key copy from separate custody.",
            "Compare the backup key ID locally without exposing key material.",
            "Keep optional-PIN knowledge separate and never place it in support messages.",
            "Complete a disposable copied-item unlock before important recovery.",
            "Use a qualified recovery professional if no matching key copy exists; do not guess or modify originals.",
        ],
    },
    {
        "id": "suspected-malware",
        "label": "Suspected malware",
        "summary": "Preserve evidence and protect backups without running a malware simulation.",
        "steps": [
            "If files are actively changing, disconnect the affected PC from networks and stop using it.",
            "Do not attach the only backup or rerun the suspicious program.",
            "Use Microsoft Defender and a trusted adult or qualified responder.",
            "Preserve affected originals, audit evidence, and safe coarse timestamps.",
            "Use a known-clean updated device before checking copied backups.",
            "Restore known-good copies to a separate location and never overwrite the only evidence.",
        ],
    },
    {
        "id": "unlock-failure",
        "label": "Unlock failure",
        "summary": "Troubleshoot an unlock failure without damaging the locked source.",
        "steps": [
            "Preserve the original locked file and make a working copy.",
            "Use Vault Health Center to review the copied container structure.",
            "Confirm the selected key ID matches the intended lock.",
            "Enter the exact optional PIN only in the local unlock field when one was used.",
            "Run Diagnostics Center and review the fixed local checks.",
            "Escalate with a privacy-safe support report; never send the key, PIN, file, or full path.",
        ],
    },
    {
        "id": "service-outage",
        "label": "Service outage",
        "summary": "Keep local recovery separate from temporary API availability.",
        "steps": [
            "Check the public VaultLink status page from a trusted browser.",
            "Do not repurchase a license or repeatedly activate devices.",
            "Remember that local unlock and recovery do not require remote file access.",
            "Keep the still-valid cached receipt within its documented offline grace period.",
            "Use fixed local tools and preserve all keys, backups, and locked originals.",
            "Submit a privacy-safe Bug Center report after service returns if the issue continues.",
        ],
    },
]


def fixed_recovery_kit_profiles():
    return json.loads(json.dumps(KIT_PROFILES))


def fixed_recovery_kit_sections():
    return json.loads(json.dumps(KIT_SECTIONS))


def fixed_emergency_runbooks():
    return json.loads(json.dumps(EMERGENCY_RUNBOOKS))
