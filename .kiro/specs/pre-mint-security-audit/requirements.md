# Requirements Document

## Introduction

The Pre-Mint Security Audit & Hardening Checklist System is the final quality gate before the cNGN platform processes any live mainnet transactions. It provides a structured, evidence-driven audit framework that verifies every security control across all ten security domains is correctly deployed and functioning in the production environment. The system manages a persistent checklist, enforces section-level and final sign-off workflows, runs automated verification scripts, gates all mainnet cNGN transaction endpoints behind audit approval, and generates regulatory-grade audit reports. No mainnet cNGN transaction may be processed until the audit has been fully approved by the security lead.

## Glossary

- **Audit_System**: The pre-mint security audit and checklist management subsystem.
- **Checklist_Item**: A single verifiable security control entry within the audit checklist, belonging to exactly one domain section.
- **Checklist_Section**: A grouping of Checklist_Items corresponding to one of the ten security domains.
- **Audit_Record**: The top-level database entity representing the complete pre-mint audit instance, containing all Checklist_Items and their state.
- **Item_Status**: The terminal or non-terminal state of a Checklist_Item — one of `pending`, `pass`, `fail`, or `not_applicable`.
- **Terminal_State**: An Item_Status of `pass` or `not_applicable`, indicating the item requires no further action.
- **Evidence**: A verifiable artifact (screenshot reference, log output, test result, or configuration file reference) attached to a Checklist_Item before it may be marked as `pass`.
- **Section_Sign_Off**: A sign-off record created by the responsible team member attesting that all items in a Checklist_Section are in a Terminal_State.
- **Final_Approval**: The security lead's sign-off that all Checklist_Sections have Section_Sign_Offs and all Checklist_Items are in a Terminal_State, granting mint approval.
- **Mint_Gate**: The platform-level enforcement mechanism that blocks all mainnet cNGN transaction endpoints until Final_Approval is granted.
- **Mint_Gate_Cache**: The Redis cache entry that stores the current Mint_Gate status and is refreshed on every Final_Approval or approval revocation.
- **Automated_Verification**: A programmatic check that produces a `pass` or `fail` result with machine-generated Evidence for a Checklist_Item.
- **Remediation_Deadline**: The date by which a failing Checklist_Item must be resolved and re-verified.
- **Super_Admin**: A platform administrator with the highest privilege level, permitted to access all audit management endpoints.
- **Security_Lead**: The designated Super_Admin responsible for granting Final_Approval.
- **Responsible_Member**: The team member assigned ownership of a Checklist_Item or Checklist_Section.
- **Audit_Report**: A formatted document containing all Checklist_Items, Evidence references, and sign-off identities, suitable for regulatory submission.
- **Mainnet_Transaction**: A cNGN transaction executed against the Stellar mainnet network.
- **Testnet_Transaction**: A cNGN transaction executed against the Stellar testnet network, not subject to the Mint_Gate.
- **Domain**: One of the ten security domains (API Key Management, Request Signing & Integrity, OAuth 2.0 & Token Management, IP Security & Network Controls, Rate Limiting & Abuse Prevention, Consumer Identity & Access, Audit Monitoring & Compliance, Data Security & Encryption, API Gateway & Infrastructure Security, Pre-Mint Readiness).
- **Propagation_Delay**: The maximum elapsed time between a Mint_Gate status change and its reflection in the Mint_Gate_Cache, configurable via application configuration.

---

## Requirements

### Requirement 1: Audit Checklist Initialisation

**User Story:** As a Super_Admin, I want the pre-mint audit checklist to be seeded with all required items across all ten security domains, so that the audit framework is ready for execution without manual item creation.

#### Acceptance Criteria

1. THE Audit_System SHALL persist a complete Audit_Record to the database containing at least one Checklist_Item per Domain on first initialisation.
2. THE Audit_System SHALL assign each Checklist_Item to exactly one Checklist_Section corresponding to its Domain.
3. THE Audit_System SHALL initialise every Checklist_Item with an Item_Status of `pending` and no Evidence.
4. WHEN the Audit_Record already exists, THE Audit_System SHALL return the existing Audit_Record without creating a duplicate.
5. THE Audit_System SHALL include Checklist_Items covering all verification points specified for each Domain: API key generation entropy and hash storage for Domain 1; HMAC enforcement and replay prevention for Domain 2; PKCE flow, token lifetime, and revocation for Domain 3; allowlist enforcement and geo-restriction for Domain 4; per-consumer rate limits and DDoS protection for Domain 5; KYC tier enforcement and admin MFA for Domain 6; audit log hash chain integrity and alert rule status for Domain 7; payload encryption and key rotation schedules for Domain 8; mTLS, TLS version, and security headers for Domain 9; and all phase completion criteria for Domain 10.

---

### Requirement 2: Checklist Item Retrieval

**User Story:** As a Super_Admin, I want to retrieve the full audit checklist with current status, evidence, and sign-off state per item, so that I can monitor audit progress.

#### Acceptance Criteria

1. WHEN a GET request is received at `/api/admin/security/pre-mint-audit`, THE Audit_System SHALL return the complete Audit_Record including all Checklist_Items, their Item_Status, Evidence references, Responsible_Member assignments, and Section_Sign_Off state for each Checklist_Section.
2. WHEN the requesting principal does not have Super_Admin privileges, THE Audit_System SHALL return HTTP 403.
3. THE Audit_System SHALL include the overall checklist completion percentage in the response, calculated as the count of Checklist_Items in a Terminal_State divided by the total count of Checklist_Items, expressed as a percentage rounded to two decimal places.
4. THE Audit_System SHALL include the Final_Approval status and, when approved, the approving Security_Lead identity and approval timestamp in the response.

---

### Requirement 3: Checklist Item Update

**User Story:** As a Responsible_Member, I want to update a checklist item with evidence and status, so that I can record the outcome of my verification work.

#### Acceptance Criteria

1. WHEN a PATCH request is received at `/api/admin/security/pre-mint-audit/items/:item_id` with a valid Item_Status and Evidence, THE Audit_System SHALL persist the updated Item_Status, Evidence, and Responsible_Member identity to the Checklist_Item record.
2. WHEN a PATCH request attempts to set Item_Status to `pass` without providing Evidence, THE Audit_System SHALL return HTTP 422 with an error indicating Evidence is required before an item may be marked as passed.
3. WHEN a PATCH request is received for a Checklist_Item that does not exist, THE Audit_System SHALL return HTTP 404.
4. WHEN a PATCH request is received for a Checklist_Item in a Checklist_Section that has an existing Section_Sign_Off, THE Audit_System SHALL invalidate the Section_Sign_Off and require re-sign-off before the section contributes to Final_Approval eligibility.
5. WHEN a PATCH request is received with Item_Status `fail`, THE Audit_System SHALL require a Remediation_Deadline to be provided and SHALL persist it to the Checklist_Item record.
6. THE Audit_System SHALL emit a structured log event for every Checklist_Item update containing the item identifier, previous status, new status, Responsible_Member identity, and timestamp.

---

### Requirement 4: Section Sign-Off

**User Story:** As a Responsible_Member, I want to sign off a completed checklist section, so that the section is marked as verified and contributes to final approval eligibility.

#### Acceptance Criteria

1. WHEN a POST request is received at `/api/admin/security/pre-mint-audit/items/:item_id/sign-off` and all Checklist_Items in the corresponding Checklist_Section are in a Terminal_State, THE Audit_System SHALL create a Section_Sign_Off record containing the Responsible_Member identity and timestamp.
2. WHEN a POST request is received for a section sign-off and one or more Checklist_Items in the Checklist_Section are not in a Terminal_State, THE Audit_System SHALL return HTTP 422 with a list of the non-terminal item identifiers.
3. WHEN a POST request is received for a section sign-off and the Checklist_Section already has a valid Section_Sign_Off, THE Audit_System SHALL return HTTP 409.
4. THE Audit_System SHALL emit a structured log event for every Section_Sign_Off containing the section identifier, Responsible_Member identity, and timestamp.

---

### Requirement 5: Final Audit Approval

**User Story:** As a Security_Lead, I want to grant final audit approval when all checklist items are resolved and all sections are signed off, so that mainnet cNGN transactions are permitted to proceed.

#### Acceptance Criteria

1. WHEN a POST request is received at `/api/admin/security/pre-mint-audit/approve` and all Checklist_Items are in a Terminal_State and all Checklist_Sections have valid Section_Sign_Offs, THE Audit_System SHALL record Final_Approval with the Security_Lead identity and timestamp and SHALL activate the Mint_Gate.
2. WHEN a POST request is received at `/api/admin/security/pre-mint-audit/approve` and one or more Checklist_Items are not in a Terminal_State, THE Audit_System SHALL return HTTP 422 with the count and identifiers of non-terminal items.
3. WHEN a POST request is received at `/api/admin/security/pre-mint-audit/approve` and one or more Checklist_Sections do not have a valid Section_Sign_Off, THE Audit_System SHALL return HTTP 422 with the identifiers of unsigned sections.
4. WHEN a POST request is received at `/api/admin/security/pre-mint-audit/approve` and the requesting principal does not have Security_Lead privileges, THE Audit_System SHALL return HTTP 403.
5. WHEN Final_Approval is recorded, THE Audit_System SHALL update the Mint_Gate_Cache within the configured Propagation_Delay.
6. THE Audit_System SHALL emit a structured log event for Final_Approval containing the Security_Lead identity, approval timestamp, and total count of approved Checklist_Items.

---

### Requirement 6: Approval Revocation

**User Story:** As a Security_Lead, I want to revoke a previously granted mint approval, so that the transaction gate is immediately re-activated if a critical security issue is discovered post-approval.

#### Acceptance Criteria

1. WHEN a POST request is received at `/api/admin/security/pre-mint-audit/revoke-approval` with a revocation reason and the Audit_Record has an active Final_Approval, THE Audit_System SHALL revoke the Final_Approval, record the revoking Security_Lead identity, revocation reason, and timestamp, and SHALL immediately re-activate the Mint_Gate.
2. WHEN a POST request is received at `/api/admin/security/pre-mint-audit/revoke-approval` and no active Final_Approval exists, THE Audit_System SHALL return HTTP 409.
3. WHEN approval is revoked, THE Audit_System SHALL update the Mint_Gate_Cache within the configured Propagation_Delay.
4. WHEN approval is revoked, THE Audit_System SHALL immediately emit a structured log event and a Prometheus alert containing the revoking Security_Lead identity, revocation reason, and timestamp.
5. WHEN a POST request is received at `/api/admin/security/pre-mint-audit/revoke-approval` without a revocation reason, THE Audit_System SHALL return HTTP 422.

---

### Requirement 7: Automated Verification

**User Story:** As a Super_Admin, I want to trigger automated verification scripts for all automatable checklist items, so that machine-verifiable controls are checked consistently and their results are recorded as evidence.

#### Acceptance Criteria

1. WHEN a POST request is received at `/api/admin/security/pre-mint-audit/run-automated-checks`, THE Audit_System SHALL execute all Automated_Verification scripts and persist the `pass` or `fail` result and machine-generated Evidence to each corresponding Checklist_Item.
2. THE Audit_System SHALL implement Automated_Verification scripts for: API key hash algorithm verification, JWT signing algorithm verification, rate limit configuration verification, audit log hash chain integrity check, encryption key rotation schedule compliance, TLS configuration verification, security header presence verification, mTLS handshake verification for all internal service pairs, and Prometheus alert rule active status verification.
3. WHEN any individual Automated_Verification script exceeds the configured maximum duration, THE Audit_System SHALL record a `fail` result for that Checklist_Item with Evidence indicating a timeout and SHALL emit a structured log event identifying the timed-out check.
4. WHEN all Automated_Verification scripts complete, THE Audit_System SHALL return a summary containing the count of passed checks, failed checks, and timed-out checks.
5. WHEN a POST request is received at `/api/admin/security/pre-mint-audit/run-automated-checks` and the requesting principal does not have Super_Admin privileges, THE Audit_System SHALL return HTTP 403.

---

### Requirement 8: Mint Gate Enforcement

**User Story:** As a platform operator, I want all mainnet cNGN transaction endpoints to be blocked until the pre-mint audit is approved, so that no real user funds are processed before security controls are verified.

#### Acceptance Criteria

1. WHEN a Mainnet_Transaction initiation request is received and the Mint_Gate_Cache indicates the audit is not approved, THE Audit_System SHALL return HTTP 503 with error code `platform_not_mint_ready`.
2. WHEN a Testnet_Transaction initiation request is received, THE Audit_System SHALL process the request regardless of Mint_Gate status.
3. THE Audit_System SHALL read Mint_Gate status from the Mint_Gate_Cache on every Mainnet_Transaction request.
4. WHEN the Mint_Gate_Cache entry is absent, THE Audit_System SHALL treat the Mint_Gate as active (blocking) and SHALL re-populate the cache from the database.
5. WHEN Final_Approval is granted or revoked, THE Audit_System SHALL refresh the Mint_Gate_Cache within the configured Propagation_Delay.

---

### Requirement 9: Mint Gate Cache Correctness

**User Story:** As a platform operator, I want the mint gate Redis cache to accurately reflect the current approval state, so that gate enforcement is consistent and propagation is bounded.

#### Acceptance Criteria

1. THE Audit_System SHALL store the Mint_Gate status in Redis under a well-defined key with no expiry, so that the gate persists across application restarts.
2. WHEN Final_Approval is recorded, THE Audit_System SHALL set the Mint_Gate_Cache value to `approved` within the configured Propagation_Delay.
3. WHEN approval is revoked, THE Audit_System SHALL set the Mint_Gate_Cache value to `revoked` within the configured Propagation_Delay.
4. WHEN the Redis connection is unavailable during a Mainnet_Transaction request, THE Audit_System SHALL fall back to the database to determine Mint_Gate status and SHALL return HTTP 503 with error code `platform_not_mint_ready` if the audit is not approved.

---

### Requirement 10: Audit Report Generation

**User Story:** As a Security_Lead, I want to generate a formatted pre-mint audit report, so that I can submit it to regulators with all evidence references and sign-off identities.

#### Acceptance Criteria

1. WHEN a GET request is received at `/api/admin/security/pre-mint-audit/report`, THE Audit_System SHALL return a formatted Audit_Report containing all Checklist_Items grouped by Domain, each item's Item_Status, Evidence references, Responsible_Member identity, and timestamp.
2. THE Audit_Report SHALL include all Section_Sign_Off records with the signing Responsible_Member identity and timestamp.
3. THE Audit_Report SHALL include the Final_Approval record with the Security_Lead identity and approval timestamp, or indicate that Final_Approval has not been granted.
4. WHEN the requesting principal does not have Super_Admin privileges, THE Audit_System SHALL return HTTP 403.
5. THE Audit_Report SHALL include the overall checklist completion percentage and the count of items in each Item_Status category.

---

### Requirement 11: Audit Observability

**User Story:** As a platform operator, I want Prometheus gauges and structured log events for audit state, so that I can monitor audit progress and be alerted to deadline breaches and approval revocations.

#### Acceptance Criteria

1. THE Audit_System SHALL expose a Prometheus gauge `pre_mint_audit_completion_percentage` reflecting the current checklist completion percentage, updated on every Checklist_Item status change.
2. THE Audit_System SHALL expose a Prometheus gauge `pre_mint_audit_failing_items_total` reflecting the current count of Checklist_Items with Item_Status `fail`, updated on every Checklist_Item status change.
3. THE Audit_System SHALL expose a Prometheus gauge `pre_mint_audit_awaiting_signoff_sections_total` reflecting the count of Checklist_Sections without a valid Section_Sign_Off where all items are in a Terminal_State.
4. THE Audit_System SHALL expose a Prometheus gauge `pre_mint_audit_days_since_last_update` reflecting the number of days elapsed since the most recent Checklist_Item update.
5. WHEN a Checklist_Item with Item_Status `fail` has a Remediation_Deadline that has passed without the item reaching a Terminal_State of `pass` or `not_applicable`, THE Audit_System SHALL fire a Prometheus alert.
6. WHEN approval is revoked, THE Audit_System SHALL immediately fire a Prometheus alert containing the revoking Security_Lead identity and revocation reason.

---

### Requirement 12: Audit Failure Handling

**User Story:** As a Super_Admin, I want failing checklist items to be tracked with remediation deadlines and owners, so that no security gap is left unresolved before mint approval.

#### Acceptance Criteria

1. WHEN a Checklist_Item is updated to Item_Status `fail`, THE Audit_System SHALL require a Remediation_Deadline and a Responsible_Member assignment.
2. WHEN a Checklist_Item with Item_Status `fail` is re-verified and updated to Item_Status `pass` with Evidence, THE Audit_System SHALL record the re-verification timestamp and the verifying Responsible_Member identity.
3. THE Audit_System SHALL prevent Final_Approval while any Checklist_Item has Item_Status `fail`.
4. WHEN a Checklist_Item has Item_Status `fail` and its Remediation_Deadline is within 24 hours without resolution, THE Audit_System SHALL emit a structured log event identifying the item, its Responsible_Member, and the deadline.

---

### Requirement 13: Audit Environment Constraint

**User Story:** As a Security_Lead, I want the audit to be executed against the production or production-identical staging environment, so that the audit results reflect real deployment state.

#### Acceptance Criteria

1. THE Audit_System SHALL record the target environment identifier (production or staging) in the Audit_Record at initialisation time.
2. WHEN the target environment identifier is not `production` or `staging`, THE Audit_System SHALL reject the audit initialisation request with HTTP 422.
3. THE Audit_Report SHALL include the target environment identifier so that reviewers can confirm the audit was not executed against a development environment.

---

### Requirement 14: Unit Tests

**User Story:** As a developer, I want unit tests for core audit logic, so that regressions in critical calculations and enforcement are caught before deployment.

#### Acceptance Criteria

1. THE Test_Suite SHALL include a unit test that verifies checklist completion percentage is calculated correctly for all combinations of Terminal_State and non-terminal item counts.
2. THE Test_Suite SHALL include a unit test that verifies Final_Approval is blocked when any Checklist_Item is not in a Terminal_State.
3. THE Test_Suite SHALL include a unit test that verifies Final_Approval is blocked when any Checklist_Section lacks a Section_Sign_Off.
4. THE Test_Suite SHALL include a unit test that verifies Mint_Gate_Cache is set to `approved` on Final_Approval and `revoked` on revocation.
5. THE Test_Suite SHALL include a unit test that verifies Automated_Verification results are correctly persisted to the corresponding Checklist_Items.
6. THE Test_Suite SHALL include a unit test that verifies Audit_Report generation produces a document containing all Checklist_Items, Evidence references, and sign-off identities.

---

### Requirement 15: Integration Tests

**User Story:** As a developer, I want integration tests covering the full audit lifecycle, so that end-to-end correctness of the audit workflow and transaction gate is verified.

#### Acceptance Criteria

1. THE Test_Suite SHALL include an integration test covering the full audit lifecycle: checklist initialisation, Automated_Verification execution, Checklist_Item updates with Evidence, Section_Sign_Offs for all sections, Final_Approval, and Mint_Gate activation.
2. THE Test_Suite SHALL include an integration test verifying that Mainnet_Transaction endpoints return HTTP 503 with error code `platform_not_mint_ready` when the Mint_Gate is active.
3. THE Test_Suite SHALL include an integration test verifying that Testnet_Transaction endpoints return a successful response regardless of Mint_Gate status.
4. THE Test_Suite SHALL include an integration test verifying that approval revocation immediately re-activates the Mint_Gate and that subsequent Mainnet_Transaction requests return HTTP 503.
5. THE Test_Suite SHALL include an integration test verifying that the Mint_Gate_Cache reflects the correct state within the configured Propagation_Delay after both approval and revocation.
