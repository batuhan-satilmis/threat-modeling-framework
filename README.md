# threat-modeling-framework

> STRIDE worksheets, MITRE ATT&CK mappings, and a small Python tool to convert YAML threat models into Markdown risk registers. Built to make threat modeling a 30-minute habit, not a quarterly event.

```
$ tmf render examples/saas-payment-flow.yaml --out PAYMENT-THREAT-MODEL.md
Loaded threat model: SaaS Payment Flow (12 threats)
Rendered to PAYMENT-THREAT-MODEL.md
```

## Why

Threat modeling fails when the artifact is too heavy to update. This repo is opinionated against Microsoft TMT–style giant diagrams; instead it standardizes on:

- **STRIDE worksheets** as Markdown.
- **YAML threat models** that produce risk registers.
- **MITRE ATT&CK** technique IDs on every threat where applicable.
- **An example per common pattern** (auth, multi-tenant, payments, data export, file upload) so a new feature starts from a relevant template, not a blank page.

## How to use it

1. Copy the template that matches your feature pattern from [`templates/`](./templates/).
2. Fill it in with your team in a 30-minute session.
3. Drop it in [`examples/`](./examples/) as part of the PR for the feature.
4. Run `tmf render` to produce the Markdown risk register.

## What's in this repo

```
templates/
  stride-worksheet.md           Generic STRIDE worksheet
  pattern-auth-and-session.md   Filled stub for auth/session features
  pattern-multi-tenant-saas.md  Tenant isolation focus
  pattern-payment-flow.md       Payment / billing focus
  pattern-data-export.md        Data egress / DLP focus
  pattern-file-upload.md        File / media handling focus
examples/
  saas-payment-flow.yaml        Example YAML threat model
  saas-payment-flow.md          Rendered output (so reviewers can preview)
mitre-mapping.md                STRIDE → MITRE ATT&CK technique map
src/tmf/
  cli.py                        argparse entry: render, lint, ids
  model.py                      Pydantic-style schema for YAML threat models
  render.py                     Markdown risk-register renderer
  ids.py                        Validate MITRE technique IDs
tests/
```

## YAML schema (excerpt)

```yaml
title: SaaS Payment Flow
scope: Subscribe / cancel / refund flows backed by Stripe
trust_boundaries:
  - name: TB1
    crosses: Anonymous internet → Vercel edge
    trust: none
  - name: TB4
    crosses: Stripe → API webhooks
    trust: signed events only
threats:
  - id: T-001
    stride: spoofing
    title: Forged webhook events
    description: An attacker without signing-secret access POSTs a fake event.
    severity: high
    mitre: [T1190]
    mitigation: Verify Stripe-Signature header on every event.
    status: implemented
  - id: T-002
    stride: tampering
    title: Race two concurrent /subscribe requests
    severity: medium
    mitre: [T1078]
    mitigation: Idempotency keys + DB unique constraint.
    status: implemented
```

## Companion repos

- 🛡️ [forsman-crm-showcase](https://github.com/batuhan-satilmis/forsman-crm-showcase) — a full threat model is one of the documents.
- 📚 [owasp-saas-hardening-guide](https://github.com/batuhan-satilmis/owasp-saas-hardening-guide) — the controls referenced in mitigations.

## License

MIT
