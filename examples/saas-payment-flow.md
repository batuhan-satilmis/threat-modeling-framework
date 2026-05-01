# Threat Model — SaaS Payment Flow

## Scope

Subscribe / cancel / refund flows backed by Stripe. Covers webhook ingestion,
client-initiated mutations, and the reconciliation between Stripe state and
application state.

## Trust boundaries

| ID | Crosses | Trust |
|---|---|---|
| TB1 | Anonymous internet → Edge | none |
| TB2 | Edge → API | session cookie verified, JWT-derived |
| TB3 | API → DB | parameterized queries; RLS forced |
| TB4 | Stripe → API webhooks | signed events only; replay-detected via ledger |

## Risk register summary

- 🔴 **Critical**: 1
- 🟠 **High**: 4
- 🟡 **Medium**: 5
- 🔵 **Low**: 2

## Threats

### Spoofing

| # | Severity | Title | Mitigation | Status | MITRE |
|---|---|---|---|---|---|
| T-001 | 🟠 High | Forged webhook events | Verify Stripe-Signature header on every event using the per-environment signing secret. Failed verification → 401, no DB write. | implemented | T1190 |
| T-002 | 🟡 Medium | Stripe customer-ID spoof | Server resolves customer ID from session, never from request body. | implemented |  |

### Tampering

| # | Severity | Title | Mitigation | Status | MITRE |
|---|---|---|---|---|---|
| T-004 | 🟠 High | Modify amount in client request before /subscribe | Amount is server-derived from plan_id; client cannot supply amount. | implemented |  |
| T-009 | 🟠 High | Cancellation in UI never reaches Stripe | Cancellation state transition only after Stripe ack. UI optimistic updates rolled back on failure. Daily reconciliation job compares local subscription state to Stripe and alerts on drift. | implemented |  |
| T-003 | 🟡 Medium | Race two concurrent /subscribe requests | Idempotency keys on every payment-creating call. DB unique constraint on (tenant_id, stripe_subscription_id). Stripe's own idempotency layer. | implemented | T1078 |
| T-011 | 🟡 Medium | Stale webhook secret accepted after rotation | Stripe supports two active signing secrets; old one is removed within 24h of rotation in the rotation runbook. | implemented |  |

### Repudiation

| # | Severity | Title | Mitigation | Status | MITRE |
|---|---|---|---|---|---|
| T-005 | 🔵 Low | User claims a refund was unauthorized | Audit log records actor, action, target, before/after. Stripe ledger is the independent third-party record. | implemented |  |

### Information Disclosure

| # | Severity | Title | Mitigation | Status | MITRE |
|---|---|---|---|---|---|
| T-010 | 🔴 Critical | Refund webhook leaks customer email to wrong tenant via misrouting | Webhook handler enforces (stripe_customer_id, tenant_id) join. Any event with a customer ID not owned by exactly one tenant is rejected and alerted. | implemented |  |
| T-012 | 🟠 High | Stripe API key written to logs by SDK error path | Pin Stripe SDK to a version that scrubs Authorization. Application's error logger redacts any 'sk_*' prefixed string in stack traces. | implemented |  |
| T-006 | 🟡 Medium | Stripe webhook payloads logged with PII | Redact known-sensitive keys before logging. Log event ID and type only; look up details from Stripe by ID when needed for debugging. | implemented |  |

### Denial of Service

| # | Severity | Title | Mitigation | Status | MITRE |
|---|---|---|---|---|---|
| T-007 | 🔵 Low | Webhook flood | Edge rate-limit on /webhooks/stripe; signature verification is fast and rejects unsigned traffic before any DB hit. | implemented |  |

### Elevation of Privilege

| # | Severity | Title | Mitigation | Status | MITRE |
|---|---|---|---|---|---|
| T-008 | 🟡 Medium | Replay successful webhook for another tenant | Signed-event ledger keyed by Stripe event ID. Replay → no-op. Webhook handler derives tenant from event payload, never from URL or headers. | implemented |  |
