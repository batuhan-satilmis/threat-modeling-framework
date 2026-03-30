# Threat Model — [System Name]

**Author:** [Your Name]
**Date:** [YYYY-MM-DD]
**Version:** 1.0
**Classification:** [Internal / Confidential]
**Review Date:** [YYYY-MM-DD]

---

## 1. System Overview

**System Name:**
**System Purpose:**
**Data Classification:** ☐ Public ☐ Internal ☐ Confidential ☐ Restricted
**Deployment Environment:** ☐ Cloud (AWS/Azure/GCP) ☐ On-Premise ☐ Hybrid ☐ SaaS

**Brief Description:**
> [Describe what the system does, who uses it, and what data it handles]

---

## 2. Scope & Assumptions

**In Scope:**
- [ ] [Component 1]
- [ ] [Component 2]

**Out of Scope:**
- [ ] [Component X]

**Assumptions:**
- [ ] [Assumption 1]
- [ ] [Assumption 2]

---

## 3. Actors & Trust Levels

| Actor | Type | Trust Level | Description |
|---|---|---|---|
| | External User | Untrusted | |
| | Admin | Trusted | |
| | Third-party API | Semi-trusted | |

---

## 4. Data Flow Diagram (DFD) Description

> Describe or embed your DFD here. List all data flows across trust boundaries.

**Trust Boundaries:**
1. **Boundary 1:** [e.g., Internet → DMZ]
2. **Boundary 2:** [e.g., DMZ → Internal Network]

**Data Flows:**
| Flow ID | From | To | Data | Protocol | Encrypted? |
|---|---|---|---|---|---|
| DF-01 | | | | | ☐ Yes ☐ No |

---

## 5. Threat Register

> Apply STRIDE to each DFD element. Score using NIST SP 800-30: Likelihood (1–5) × Impact (1–5)

| ID | Component | STRIDE | Threat Description | Likelihood | Impact | Risk Score | MITRE ATT&CK | NIST Control | Status |
|---|---|---|---|---|---|---|---|---|---|
| T-001 | | S — Spoofing | | | | | | | 🔴 Open |
| T-002 | | T — Tampering | | | | | | | 🔴 Open |
| T-003 | | R — Repudiation | | | | | | | 🔴 Open |
| T-004 | | I — Info Disclosure | | | | | | | 🔴 Open |
| T-005 | | D — Denial of Service | | | | | | | 🔴 Open |
| T-006 | | E — Elevation of Privilege | | | | | | | 🔴 Open |

**Risk Score Key:**
- 🔴 **Critical (20–25):** Immediate action required
- 🟠 **High (13–19):** Address within current sprint/release
- 🟡 **Medium (6–12):** Address within 30–60 days
- 🟢 **Low (1–5):** Accept or address in next cycle

**Status Key:** 🔴 Open | 🟡 Mitigated (controls in place) | ✅ Closed (verified)

---

## 6. Mitigations & Controls

| Threat ID | Mitigation | Owner | OWASP | NIST Control | Target Date | Status |
|---|---|---|---|---|---|---|
| T-001 | | | | | | |
| T-002 | | | | | | |

---

## 7. Residual Risk Summary

| Risk Level | Count | Notes |
|---|---|---|
| 🔴 Critical | | |
| 🟠 High | | |
| 🟡 Medium | | |
| 🟢 Low | | |

**Overall Risk Posture:** ☐ Acceptable ☐ Needs Remediation ☐ Unacceptable

---

## 8. Sign-off

| Role | Name | Date | Signature |
|---|---|---|---|
| Security Analyst | | | |
| System Owner | | | |
| CISO / Security Lead | | | |

---

## 9. Revision History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | | | Initial draft |
