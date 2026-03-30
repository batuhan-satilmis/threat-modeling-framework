# 🗺️ Threat Modeling Framework

> A structured, reusable threat modeling framework using the **STRIDE methodology**, **MITRE ATT&CK** mapping, and **NIST SP 800-30** risk assessment — designed for web applications, cloud environments, and enterprise systems.

![Framework](https://img.shields.io/badge/Methodology-STRIDE-blue?style=flat)
![MITRE](https://img.shields.io/badge/Mapped-MITRE%20ATT%26CK-red?style=flat)
![NIST](https://img.shields.io/badge/Aligned-NIST%20SP%20800--30-blue?style=flat)
![ISO](https://img.shields.io/badge/Aligned-ISO%2027001-green?style=flat)

---

## Overview

This repository provides a complete, reusable threat modeling framework that security analysts, consultants, and development teams can adapt to their environments. It includes templates, worked examples, and a risk register ready for real-world use.

**Applicable to:** Web applications, REST APIs, cloud-hosted systems (AWS/Azure/GCP), SaaS platforms, enterprise internal systems.

---

## Repository Structure

```
threat-modeling-framework/
├── README.md
├── methodology/
│   ├── STRIDE_overview.md          # STRIDE methodology guide
│   ├── attack_trees.md             # Attack tree construction guide
│   └── risk_scoring.md             # NIST SP 800-30 risk scoring guide
├── templates/
│   ├── threat_model_template.md    # Blank threat model (fill in for any system)
│   ├── risk_register_template.md   # Risk register with scoring matrix
│   └── dfd_checklist.md            # Data Flow Diagram review checklist
├── examples/
│   ├── web_app_threat_model.md     # Worked example: Secure web application
│   └── api_threat_model.md         # Worked example: REST API
├── mitre_mappings/
│   ├── stride_to_attack.md         # STRIDE category → MITRE ATT&CK technique mapping
│   └── web_app_techniques.md       # Web app specific ATT&CK techniques
└── controls/
    ├── nist_controls_mapping.md    # Threat → NIST 800-53 control mapping
    └── owasp_mitigations.md        # Threat → OWASP Top 10 mitigation mapping
```

---

## STRIDE Methodology Quick Reference

| Threat Category | Description | Example | MITRE Tactic |
|---|---|---|---|
| **S**poofing | Impersonating another user or system | Stolen credentials, session hijacking | Initial Access (TA0001) |
| **T**ampering | Unauthorized modification of data | SQL injection, parameter manipulation | Impact (TA0040) |
| **R**epudiation | Denying having performed an action | Deleting audit logs, forging timestamps | Defense Evasion (TA0005) |
| **I**nformation Disclosure | Unauthorized access to information | Data exfiltration, misconfigured S3 | Exfiltration (TA0010) |
| **D**enial of Service | Making a system unavailable | DDoS, resource exhaustion | Impact (TA0040) |
| **E**levation of Privilege | Gaining higher permissions than granted | Privilege escalation, SSRF | Privilege Escalation (TA0004) |

---

## How to Use This Framework

### Step 1 — Define the System Scope

Before modeling threats, document:
- System purpose and data classification
- Users/actors and their trust levels
- External dependencies and integrations
- Deployment environment (cloud, on-prem, hybrid)
- Data flows across trust boundaries

### Step 2 — Create a Data Flow Diagram (DFD)

Map all components, data flows, and trust boundaries. Use the `dfd_checklist.md` to ensure completeness.

**DFD Elements:**
- 🟦 **Processes** — Components that handle data (app servers, functions)
- 🟨 **Data Stores** — Where data is persisted (databases, S3, caches)
- ➡️ **Data Flows** — How data moves between components
- 🔴 **Trust Boundaries** — Lines separating different trust zones
- 👤 **External Entities** — Users, third-party APIs, other systems

### Step 3 — Apply STRIDE to Each Element

For every DFD element, systematically ask: which STRIDE threats apply? Use `threat_model_template.md`.

### Step 4 — Score Risk Using NIST SP 800-30

For each identified threat:

```
Risk = Likelihood × Impact

Likelihood: 1 (Very Low) → 5 (Very High)
Impact:     1 (Very Low) → 5 (Very High)
Risk Score: 1–5 (Low) | 6–12 (Medium) | 13–19 (High) | 20–25 (Critical)
```

### Step 5 — Map to MITRE ATT&CK

Identify the ATT&CK techniques that correspond to each threat. This enables:
- Detection rule development (SIEM/SOAR)
- Red team exercise scoping
- Security control gap analysis

### Step 6 — Define Mitigations and Controls

Map each threat to:
- NIST SP 800-53 security controls (see `nist_controls_mapping.md`)
- OWASP mitigations (see `owasp_mitigations.md`)
- Implementation tasks for the development/ops team

---

## Worked Example: Web Application Threat Model (Summary)

**System:** Customer-facing e-commerce web application with user authentication, payment processing, and order management.

**Trust Boundaries:**
- Internet → Web Application (DMZ)
- Web Application → Database (Internal)
- Web Application → Payment Processor API (External)

### Threat Register (Excerpt)

| ID | Component | STRIDE | Threat | Likelihood | Impact | Risk | MITRE ATT&CK | NIST Control | Status |
|---|---|---|---|---|---|---|---|---|---|
| T-001 | Login Form | S | Credential stuffing / brute force | 4 | 5 | **Critical (20)** | T1110.003 | IA-5, AC-7 | 🔴 Open |
| T-002 | User Input Fields | T | SQL Injection | 3 | 5 | **High (15)** | T1190 | SI-10, SA-11 | 🔴 Open |
| T-003 | Session Tokens | S | Session hijacking via XSS | 3 | 4 | **High (12)** | T1539 | SC-8, SC-23 | 🔴 Open |
| T-004 | API Keys (config) | I | Hardcoded secrets in source code | 2 | 5 | **High (10)** | T1552.001 | IA-5, CM-6 | 🟡 Mitigated |
| T-005 | Admin Panel | E | Privilege escalation via IDOR | 2 | 5 | **High (10)** | T1078 | AC-3, AC-6 | 🔴 Open |
| T-006 | Audit Logs | R | Log deletion / tampering | 2 | 4 | **Medium (8)** | T1070.002 | AU-9, AU-10 | 🟡 Mitigated |
| T-007 | Payment API | I | Data in transit interception | 1 | 5 | **Medium (5)** | T1557 | SC-8, SC-28 | ✅ Closed |
| T-008 | App Server | D | Resource exhaustion / DDoS | 3 | 3 | **Medium (9)** | T1498 | SC-5, SC-6 | 🟡 Mitigated |

### Key Mitigations (from above)

| Threat | Mitigation | OWASP | Implementation |
|---|---|---|---|
| T-001: Brute Force | Rate limiting, MFA, account lockout | A07:2021 | Implement at API gateway + application layer |
| T-002: SQL Injection | Parameterized queries, input validation | A03:2021 | ORM enforcement, WAF rules |
| T-003: XSS / Session Hijack | CSP headers, HttpOnly cookies, token rotation | A03:2021 | Server-side session management |
| T-004: Hardcoded Secrets | Secrets manager (AWS SSM, HashiCorp Vault) | A02:2021 | CI/CD secret scanning (GitGuardian, truffleHog) |
| T-005: IDOR | Server-side authorization checks on every request | A01:2021 | RBAC enforcement at controller layer |

---

## STRIDE → MITRE ATT&CK Mapping

| STRIDE | MITRE ATT&CK Tactics | Key Techniques |
|---|---|---|
| Spoofing | Initial Access, Credential Access | T1078 (Valid Accounts), T1110 (Brute Force), T1539 (Session Theft) |
| Tampering | Impact, Execution | T1190 (Exploit Public-Facing App), T1059 (Command Injection) |
| Repudiation | Defense Evasion | T1070 (Indicator Removal), T1562 (Impair Defenses) |
| Information Disclosure | Exfiltration, Collection | T1041 (Exfil over C2), T1552 (Unsecured Credentials) |
| Denial of Service | Impact | T1498 (Network DoS), T1499 (Endpoint DoS) |
| Elevation of Privilege | Privilege Escalation | T1068 (Exploit for Priv Esc), T1548 (Abuse Elevation Control) |

---

## Threat → NIST SP 800-53 Control Mapping

| Threat Area | Primary NIST Controls |
|---|---|
| Authentication / Spoofing | IA-2, IA-5, AC-7, AC-17 |
| Input Validation / Tampering | SI-10, SA-11, SA-15 |
| Audit / Repudiation | AU-2, AU-9, AU-10, AU-12 |
| Data Protection / Info Disclosure | SC-8, SC-28, AC-3, AC-23 |
| Availability / DoS | SC-5, SC-6, CP-10 |
| Authorization / Privilege Escalation | AC-2, AC-3, AC-6, IA-4 |

---

## Templates

See the `templates/` directory for blank, fillable versions of:
- `threat_model_template.md` — Full threat modeling worksheet
- `risk_register_template.md` — Risk register with scoring matrix
- `dfd_checklist.md` — Pre-modeling checklist

---

## References

- [STRIDE Methodology — Microsoft SDL](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST SP 800-30 — Guide for Risk Assessments](https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final)
- [NIST SP 800-53 — Security Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [OWASP Top 10 — 2021](https://owasp.org/Top10/)
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)

---

## Author

**Batuhan Satilmis** — Cybersecurity Analyst & IT Security Consultant
- 🌐 [forsmantech.com](https://forsmantech.com)
- 💼 [LinkedIn](https://linkedin.com/in/batuhan-satilmis)

---

## License

MIT License — freely use and adapt for your own threat modeling work.
