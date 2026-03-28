# Third-Party Security Audit Framework

## Engagement Framework Template

### Scope Definition
- All platform components (API, admin dashboard, workers)
- All security domains (auth, crypto, payments, KYC)
- All consumer types (individual, business)
- Full cNGN transaction lifecycle (onramp, bill pay, offramp)

### Type
- Combined white box source code review + grey box pen test

### Vendor Selection Criteria
- Financial platform audit experience
- Certified pentesters
- Verifiable refs
- Professional indemnity insurance

### Timeline
- Start: [date]
- Scope confirm: +1w
- Prelim findings: +4w
- Final report: +6w
- Remediation verification: +8w

## Pre-Audit Package
- Architecture docs
- API spec
- Deployment diagrams
- Threat model
- Security controls inventory
- Internal review findings

## Rules of Engagement
- Dedicated audit env (testnet cNGN)
- Grey box creds (API keys, admin dashboard)
- Secure comms channel
- Escalation contacts
- Safe harbour

## Findings Format
- ID, title, severity, component, description, PoC steps, impact, CVSS, remediation

## SLA
| Severity | Triage | Remediate |
|----------|--------|-----------|
| Critical | 24h | 48h |
| High | 48h | 7d |
| Medium | 5d | 30d |

## Completion Gate
- Critical/High verified_closed
- Medium plan with date

## API Endpoints
- POST /api/admin/security/third-party-audit/findings/:engagement_id
- GET /api/admin/security/third-party-audit/report/:engagement_id
- GET /api/admin/security/third-party-audit/executive-summary/:engagement_id
- GET /api/admin/security/third-party-audit/remediation-matrix/:engagement_id
- POST /api/admin/security/third-party-audit/complete/:engagement_id
- GET /api/admin/security/third-party-audit/schedule

All endpoints super admin only.

