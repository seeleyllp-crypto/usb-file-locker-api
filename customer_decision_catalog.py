import copy


DECISION_SCENARIOS = (
    {
        "id": "unlock-failure",
        "title": "A locked file will not open",
        "summary": "Protect the encrypted original, confirm the exact key, and verify the PIN mode.",
        "start_node_id": "unlock-has-copy",
        "max_decisions": 3,
    },
    {
        "id": "lost-usb-key",
        "title": "The original USB key is missing",
        "summary": "Check for a protected recovery copy without replacing or changing the locked file.",
        "start_node_id": "lost-has-recovery-copy",
        "max_decisions": 3,
    },
    {
        "id": "update-problem",
        "title": "A verified update will not install",
        "summary": "Confirm the signed release, finish local file work, and prepare Windows safely.",
        "start_node_id": "update-is-published",
        "max_decisions": 3,
    },
    {
        "id": "license-problem",
        "title": "A license or rank is not working",
        "summary": "Separate service, redemption, and owner-account states without exposing the key.",
        "start_node_id": "license-service-online",
        "max_decisions": 3,
    },
    {
        "id": "security-warning",
        "title": "Security software showed a warning",
        "summary": "Keep protection enabled, record the exact alert, and verify the signed release.",
        "start_node_id": "security-has-detection-name",
        "max_decisions": 3,
    },
    {
        "id": "app-startup",
        "title": "VaultLink will not start",
        "summary": "Use the visible error, dependency check, and Defender result to choose a safe repair.",
        "start_node_id": "startup-has-error",
        "max_decisions": 3,
    },
    {
        "id": "move-to-new-pc",
        "title": "I am moving to another PC",
        "summary": "Prove recovery on the current PC before moving the key and locked data.",
        "start_node_id": "move-has-key-backup",
        "max_decisions": 3,
    },
)


def _choice(target_type, target_id):
    return {"target_type": target_type, "target_id": target_id}


DECISION_NODES = (
    {
        "id": "unlock-has-copy",
        "scenario_id": "unlock-failure",
        "question": "Do you have an unchanged copy of the .locked item?",
        "explanation": "Troubleshooting should happen on a copy so the original encrypted container stays untouched.",
        "yes": _choice("node", "unlock-has-original-key"),
        "no": _choice("outcome", "unlock-preserve-first"),
    },
    {
        "id": "unlock-has-original-key",
        "scenario_id": "unlock-failure",
        "question": "Do you have the exact USB key used when the item was locked?",
        "explanation": "A newly created or unrelated key cannot reproduce the original encryption key material.",
        "yes": _choice("node", "unlock-knows-pin-mode"),
        "no": _choice("outcome", "unlock-find-key"),
    },
    {
        "id": "unlock-knows-pin-mode",
        "scenario_id": "unlock-failure",
        "question": "Are you certain whether an extra PIN was used and what it was?",
        "explanation": "USB-key-only and USB-key-plus-PIN are different recovery modes.",
        "yes": _choice("outcome", "unlock-controlled-retry"),
        "no": _choice("outcome", "unlock-verify-pin"),
    },
    {
        "id": "lost-has-recovery-copy",
        "scenario_id": "lost-usb-key",
        "question": "Do you have a protected recovery copy of the original key file?",
        "explanation": "The API, owner, and a new USB key cannot reconstruct missing key material.",
        "yes": _choice("node", "lost-copy-was-tested"),
        "no": _choice("outcome", "lost-preserve-and-search"),
    },
    {
        "id": "lost-copy-was-tested",
        "scenario_id": "lost-usb-key",
        "question": "Was that recovery copy tested with disposable data before the loss?",
        "explanation": "A test reduces uncertainty but does not replace a careful recovery attempt from a copy.",
        "yes": _choice("node", "lost-has-trusted-pc"),
        "no": _choice("outcome", "lost-test-recovery-copy"),
    },
    {
        "id": "lost-has-trusted-pc",
        "scenario_id": "lost-usb-key",
        "question": "Is a trusted, updated Windows PC available for the recovery attempt?",
        "explanation": "Recovery material should not be used on an unknown or suspicious computer.",
        "yes": _choice("outcome", "lost-use-recovery-copy"),
        "no": _choice("outcome", "lost-prepare-trusted-pc"),
    },
    {
        "id": "update-is-published",
        "scenario_id": "update-problem",
        "question": "Does Update Center show a published release with a verified signature and hash?",
        "explanation": "VaultLink should never install an unsigned, mismatched, or privately copied package.",
        "yes": _choice("node", "update-local-work-finished"),
        "no": _choice("outcome", "update-wait-for-signed-release"),
    },
    {
        "id": "update-local-work-finished",
        "scenario_id": "update-problem",
        "question": "Have all local lock, unlock, export, and recovery tasks finished?",
        "explanation": "The updater waits for active local file work to finish before replacing app files.",
        "yes": _choice("node", "update-pc-ready"),
        "no": _choice("outcome", "update-finish-local-work"),
    },
    {
        "id": "update-pc-ready",
        "scenario_id": "update-problem",
        "question": "Is Defender enabled and is there enough free working space?",
        "explanation": "The package needs room for download, extraction, verification, and rollback backup.",
        "yes": _choice("outcome", "update-install-verified"),
        "no": _choice("outcome", "update-prepare-pc"),
    },
    {
        "id": "license-service-online",
        "scenario_id": "license-problem",
        "question": "Does the public service-status page show VaultLink online?",
        "explanation": "An outage can affect online licensing while local unlock and recovery remain available.",
        "yes": _choice("node", "license-redeemed-here"),
        "no": _choice("outcome", "license-wait-for-service"),
    },
    {
        "id": "license-redeemed-here",
        "scenario_id": "license-problem",
        "question": "Was the license redeemed or activated on this Windows device?",
        "explanation": "Owning a key and activating a device seat are separate steps.",
        "yes": _choice("node", "license-limited-message"),
        "no": _choice("outcome", "license-redeem-device"),
    },
    {
        "id": "license-limited-message",
        "scenario_id": "license-problem",
        "question": "Does License Center say the license is limited, revoked, expired, or out of seats?",
        "explanation": "Those states need an owner or account action, not a local bypass.",
        "yes": _choice("outcome", "license-owner-review"),
        "no": _choice("outcome", "license-refresh-state"),
    },
    {
        "id": "security-has-detection-name",
        "scenario_id": "security-warning",
        "question": "Can you see the exact security detection name and affected filename?",
        "explanation": "The exact visible alert is more useful than a general claim that the app was flagged.",
        "yes": _choice("node", "security-is-signed-release"),
        "no": _choice("outcome", "security-record-alert"),
    },
    {
        "id": "security-is-signed-release",
        "scenario_id": "security-warning",
        "question": "Did the file come from the signed VaultLink update or transparent GitHub folder?",
        "explanation": "Unknown downloads should not be trusted just because they use the VaultLink name.",
        "yes": _choice("node", "security-active-behavior"),
        "no": _choice("outcome", "security-remove-unverified"),
    },
    {
        "id": "security-active-behavior",
        "scenario_id": "security-warning",
        "question": "Is the PC showing active suspicious behavior beyond the security alert?",
        "explanation": "Unexpected account access, new processes, encryption, or repeated crashes need incident handling.",
        "yes": _choice("outcome", "security-incident-now"),
        "no": _choice("outcome", "security-verify-release"),
    },
    {
        "id": "startup-has-error",
        "scenario_id": "app-startup",
        "question": "Is there an exact visible startup or traceback message?",
        "explanation": "A visible error can distinguish a missing dependency from a blocked or damaged installation.",
        "yes": _choice("node", "startup-dependencies-ready"),
        "no": _choice("outcome", "startup-run-diagnostics"),
    },
    {
        "id": "startup-dependencies-ready",
        "scenario_id": "app-startup",
        "question": "Did Ensure Dependencies complete without an error?",
        "explanation": "The transparent Python app requires its listed cryptography dependency.",
        "yes": _choice("node", "startup-defender-alert"),
        "no": _choice("outcome", "startup-repair-dependencies"),
    },
    {
        "id": "startup-defender-alert",
        "scenario_id": "app-startup",
        "question": "Did Defender show an exact detection for a VaultLink file?",
        "explanation": "Do not disable Defender or add an exclusion to force the app to start.",
        "yes": _choice("outcome", "startup-handle-detection"),
        "no": _choice("outcome", "startup-transparent-reinstall"),
    },
    {
        "id": "move-has-key-backup",
        "scenario_id": "move-to-new-pc",
        "question": "Do you have the original USB key and a separate protected recovery copy?",
        "explanation": "Moving without a tested recovery copy creates a single point of failure.",
        "yes": _choice("node", "move-current-test-passed"),
        "no": _choice("outcome", "move-prepare-recovery"),
    },
    {
        "id": "move-current-test-passed",
        "scenario_id": "move-to-new-pc",
        "question": "Has a disposable lock-and-unlock test passed on the current PC?",
        "explanation": "Prove the current key and PIN mode before adding a new computer to the process.",
        "yes": _choice("node", "move-new-pc-ready"),
        "no": _choice("outcome", "move-test-current-pc"),
    },
    {
        "id": "move-new-pc-ready",
        "scenario_id": "move-to-new-pc",
        "question": "Is the new Windows PC updated, trusted, and protected by Defender?",
        "explanation": "The destination should be prepared before connecting recovery media or copying locked data.",
        "yes": _choice("outcome", "move-ready"),
        "no": _choice("outcome", "move-prepare-new-pc"),
    },
)


def _outcome(
    outcome_id,
    scenario_id,
    title,
    priority,
    summary,
    steps,
    target_path,
    target_label,
    warning,
):
    return {
        "id": outcome_id,
        "scenario_id": scenario_id,
        "title": title,
        "priority": priority,
        "summary": summary,
        "steps": list(steps),
        "target_path": target_path,
        "target_label": target_label,
        "warning": warning,
    }


DECISION_OUTCOMES = (
    _outcome(
        "unlock-preserve-first", "unlock-failure", "Preserve the encrypted original first", "urgent",
        "Do not continue recovery attempts until an unchanged working copy exists.",
        ("Stop opening or editing the .locked item.", "Create a second copy without renaming the original.", "Keep the original in a protected location.", "Troubleshoot only the copy."),
        "/recovery-kit", "OPEN RECOVERY KIT", "A changed or damaged encrypted container may be impossible to reconstruct.",
    ),
    _outcome(
        "unlock-find-key", "unlock-failure", "Find the original or protected recovery key", "urgent",
        "A different or newly created key cannot unlock this container.",
        ("Preserve every copy of the .locked item.", "Check protected recovery media.", "Do not overwrite any key file.", "Test only after the matching key is found."),
        "/backup-verification", "OPEN BACKUP CHECK", "Never upload or send a master key to support.",
    ),
    _outcome(
        "unlock-controlled-retry", "unlock-failure", "Run one controlled unlock attempt", "normal",
        "The recovery materials appear ready for a careful attempt from a copy.",
        ("Use the copied .locked item.", "Connect the exact original key.", "Enter the exact PIN only if one was used.", "Open and verify the recovered result before deleting anything."),
        "/readiness", "OPEN RECOVERY READINESS", "A successful unlock must still be verified by opening the recovered result.",
    ),
    _outcome(
        "unlock-verify-pin", "unlock-failure", "Verify the original PIN mode", "watch",
        "Do not keep guessing because VaultLink cannot look up or recover the PIN.",
        ("Stop repeated attempts.", "Check whether USB-key-only mode was used.", "Review a separate offline PIN record.", "Keep the original locked item unchanged."),
        "/QNA", "OPEN CUSTOMER ANSWERS", "Support should never ask for the PIN or master key.",
    ),
    _outcome(
        "lost-preserve-and-search", "lost-usb-key", "Preserve locked data and search for recovery media", "urgent",
        "Without the original key material, recovery cannot be promised.",
        ("Do not delete locked originals.", "Check protected offline recovery locations.", "Do not create a replacement key over an old file.", "Record which recovery locations were checked."),
        "/recovery-kit", "OPEN RECOVERY KIT", "The API and owner cannot recreate missing encryption key material.",
    ),
    _outcome(
        "lost-test-recovery-copy", "lost-usb-key", "Test the recovery key with disposable data", "watch",
        "Validate the recovery copy without risking important locked data.",
        ("Use a trusted Windows PC.", "Create disposable test data.", "Lock and unlock only that test data.", "Preserve important locked originals until the test succeeds."),
        "/backup-verification", "OPEN BACKUP CHECK", "A file existing on a USB drive does not prove it is the correct key.",
    ),
    _outcome(
        "lost-use-recovery-copy", "lost-usb-key", "Use the protected recovery copy carefully", "normal",
        "The recovery copy and trusted PC are ready for a controlled attempt.",
        ("Work from a copy of the locked item.", "Use the protected recovery key.", "Use the original PIN mode.", "Verify the recovered result before changing anything."),
        "/readiness", "OPEN RECOVERY READINESS", "Keep the recovery key offline again after the attempt.",
    ),
    _outcome(
        "lost-prepare-trusted-pc", "lost-usb-key", "Prepare a trusted recovery computer", "watch",
        "Do not connect recovery media to an unknown or suspicious PC.",
        ("Install Windows updates.", "Confirm Defender is active.", "Install only a verified VaultLink release.", "Run a disposable recovery test first."),
        "/maintenance", "OPEN MAINTENANCE", "Treat recovery media as a high-value secret.",
    ),
    _outcome(
        "update-wait-for-signed-release", "update-problem", "Wait for a signed published release", "watch",
        "Do not install a package that Update Center cannot verify.",
        ("Keep the current working app.", "Refresh Update Center later.", "Confirm the Ed25519 signature.", "Confirm the SHA-256 package hash."),
        "/update", "OPEN UPDATE CENTER", "Never bypass a signature or hash failure.",
    ),
    _outcome(
        "update-finish-local-work", "update-problem", "Finish local file work before updating", "normal",
        "The updater should wait until local lock, unlock, export, and recovery work is idle.",
        ("Let the active operation finish.", "Verify its final result.", "Close extra VaultLink windows.", "Retry the signed update."),
        "/update", "OPEN UPDATE CENTER", "Do not force-close an active encryption or recovery operation.",
    ),
    _outcome(
        "update-install-verified", "update-problem", "Install the verified update", "normal",
        "The signed release, idle app state, Defender, and working space are ready.",
        ("Review the release version.", "Install through Update Center.", "Wait for verification and restart.", "Confirm keys, settings, and locked files remain available."),
        "/update", "OPEN UPDATE CENTER", "Updates replace app files only and should preserve LocalAppData.",
    ),
    _outcome(
        "update-prepare-pc", "update-problem", "Prepare Windows before retrying", "watch",
        "Resolve protection or storage readiness before running the updater.",
        ("Keep Defender enabled.", "Install Windows security updates.", "Free sufficient working space.", "Run VaultLink diagnostics and retry."),
        "/diagnostics", "OPEN DIAGNOSTICS", "Do not add antivirus exclusions to force an update.",
    ),
    _outcome(
        "license-wait-for-service", "license-problem", "Use local recovery and wait for service", "watch",
        "Online license features may be unavailable during a service outage.",
        ("Keep using local unlock and recovery.", "Check the public status page.", "Do not repeatedly redeem the key.", "Retry after service returns."),
        "/status", "OPEN SERVICE STATUS", "A service outage should not block local unlock or recovery.",
    ),
    _outcome(
        "license-redeem-device", "license-problem", "Redeem the license on this device", "normal",
        "The device needs an activation seat before rank features can appear.",
        ("Open License Center.", "Enter the license key only in the license field.", "Redeem on this device.", "Refresh the Customer Workspace."),
        "/customer", "OPEN LICENSE CENTER", "Never place a license key in a URL or support message.",
    ),
    _outcome(
        "license-owner-review", "license-problem", "Ask the owner to review the license state", "watch",
        "Revocation, limits, expiration, and seat capacity require an owner or account action.",
        ("Keep local recovery material safe.", "Record only the visible status label.", "Use the privacy-safe Bug Center if needed.", "Wait for owner confirmation before redeeming again."),
        "/customer", "OPEN LICENSE CENTER", "Do not send the full license key in a bug report.",
    ),
    _outcome(
        "license-refresh-state", "license-problem", "Refresh the signed license state", "normal",
        "The service and activation look ready, so refresh the current signed status.",
        ("Open License Center.", "Run Verify or Refresh.", "Close and reopen the Customer Hub.", "Check the rank feature again."),
        "/customer", "OPEN LICENSE CENTER", "A refresh does not create extra device seats.",
    ),
    _outcome(
        "security-record-alert", "security-warning", "Record the exact security alert", "watch",
        "Find the Defender or security-product detection details before changing anything.",
        ("Keep protection enabled.", "Open protection history.", "Record the exact detection name.", "Record only the affected filename, not private file contents."),
        "/incident-response", "OPEN INCIDENT GUIDE", "Do not disable protection or add exclusions.",
    ),
    _outcome(
        "security-remove-unverified", "security-warning", "Stop using the unverified file", "urgent",
        "A file from an unknown source should not be treated as VaultLink.",
        ("Do not run the file again.", "Keep security protection enabled.", "Use the incident guide.", "Replace it only with the transparent signed release."),
        "/incident-response", "OPEN INCIDENT GUIDE", "A familiar filename is not proof that a file is safe.",
    ),
    _outcome(
        "security-incident-now", "security-warning", "Start incident response now", "urgent",
        "Active suspicious behavior needs containment and qualified help.",
        ("Stop entering secrets.", "Keep Defender enabled.", "Disconnect from untrusted networks when appropriate.", "Ask a trusted adult or security professional for help."),
        "/incident-response", "OPEN INCIDENT GUIDE", "Do not run malware samples or untrusted cleanup tools.",
    ),
    _outcome(
        "security-verify-release", "security-warning", "Verify the transparent release", "watch",
        "The absence of active suspicious behavior allows a careful false-positive review.",
        ("Record the exact detection.", "Verify the signed release identity.", "Verify the SHA-256 package hash.", "Submit the file to the security vendor only after adult review."),
        "/trust", "OPEN TRUST CENTER", "Do not whitelist or obfuscate the app to avoid a detection.",
    ),
    _outcome(
        "startup-run-diagnostics", "app-startup", "Run the fixed startup checks", "normal",
        "Use read-only diagnostics to identify runtime, dependency, storage, or update readiness.",
        ("Open Diagnostics Center.", "Review startup and dependency checks.", "Copy the privacy-safe summary.", "Do not include full paths or private files."),
        "/diagnostics", "OPEN DIAGNOSTICS", "Diagnostics is guidance, not proof that the PC is safe.",
    ),
    _outcome(
        "startup-repair-dependencies", "app-startup", "Repair the transparent dependencies", "normal",
        "Complete the listed dependency setup instead of downloading a bundled mystery executable.",
        ("Use Ensure Dependencies.cmd.", "Keep the console open for the exact error.", "Install the listed cryptography package.", "Run the transparent Python launcher again."),
        "/diagnostics", "OPEN DIAGNOSTICS", "Do not download random DLL or dependency-fix websites.",
    ),
    _outcome(
        "startup-handle-detection", "app-startup", "Handle the Defender detection safely", "watch",
        "The startup problem may be a security block and needs exact-alert review.",
        ("Keep Defender enabled.", "Record the detection name.", "Verify source and package hash.", "Use the incident guide before rebuilding."),
        "/incident-response", "OPEN INCIDENT GUIDE", "Do not add a Defender exclusion.",
    ),
    _outcome(
        "startup-transparent-reinstall", "app-startup", "Reinstall the transparent app folder", "normal",
        "Use the verified normal-folder release while preserving LocalAppData.",
        ("Back up LocalAppData with the built-in tool.", "Download the signed package.", "Replace app files only.", "Run Ensure Dependencies and start again."),
        "/update", "OPEN UPDATE CENTER", "Do not delete keys, settings, vault data, audit logs, or locked files.",
    ),
    _outcome(
        "move-prepare-recovery", "move-to-new-pc", "Prepare recovery material before moving", "urgent",
        "Do not move important locked data with a single untested key copy.",
        ("Keep the current PC unchanged.", "Create a protected recovery key copy.", "Store it separately.", "Test with disposable data."),
        "/recovery-kit", "OPEN RECOVERY KIT", "A move is not a backup.",
    ),
    _outcome(
        "move-test-current-pc", "move-to-new-pc", "Prove recovery on the current PC", "watch",
        "Confirm the key and PIN mode before introducing the new computer.",
        ("Create disposable test data.", "Lock it with the intended key and PIN mode.", "Unlock and open it.", "Record only the fixed drill result."),
        "/recovery-drills", "OPEN RECOVERY DRILLS", "Do not use the only copy of important data as the test.",
    ),
    _outcome(
        "move-ready", "move-to-new-pc", "Run a controlled move test", "normal",
        "Recovery material and the destination PC appear ready.",
        ("Install the signed VaultLink release.", "Copy one disposable locked test item.", "Unlock it with the original key and PIN mode.", "Move important data only after the test succeeds."),
        "/readiness", "OPEN RECOVERY READINESS", "Keep the old PC and backups until the new-PC recovery test passes.",
    ),
    _outcome(
        "move-prepare-new-pc", "move-to-new-pc", "Prepare the destination PC first", "watch",
        "Update and protect the new PC before connecting key or recovery media.",
        ("Install Windows updates.", "Confirm Defender is active.", "Install only the signed VaultLink release.", "Run diagnostics before connecting recovery media."),
        "/maintenance", "OPEN MAINTENANCE", "Do not connect the master key to an untrusted PC.",
    ),
)


def fixed_decision_scenarios():
    return copy.deepcopy(list(DECISION_SCENARIOS))


def fixed_decision_nodes():
    return copy.deepcopy(list(DECISION_NODES))


def fixed_decision_outcomes():
    return copy.deepcopy(list(DECISION_OUTCOMES))
