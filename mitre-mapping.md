# STRIDE → MITRE ATT&CK technique mapping

> A pragmatic, opinionated mapping. Use as a starting point, not a definitive answer — STRIDE describes goals, ATT&CK describes techniques, and they don't line up 1:1.

## Why combine them

- **STRIDE** is great for completeness in a feature-scoped review: did we think about all six categories?
- **MITRE ATT&CK** is great for SOC and IR: a finding tagged with `T1190` (Exploit Public-Facing Application) is immediately something a detection engineer can write a rule for.

## Mapping table

| STRIDE | Common ATT&CK techniques |
|---|---|
| **Spoofing** | T1190 Exploit Public-Facing Application · T1078 Valid Accounts · T1556 Modify Authentication Process · T1199 Trusted Relationship |
| **Tampering** | T1565 Data Manipulation · T1486 Data Encrypted for Impact (in destruction context) · T1547 Boot or Logon Autostart Execution · T1554 Compromise Client Software Binary |
| **Repudiation** | T1070 Indicator Removal · T1562.008 Disable Cloud Logs · T1485 Data Destruction (audit logs) |
| **Information Disclosure** | T1213 Data from Information Repositories · T1530 Data from Cloud Storage · T1005 Data from Local System · T1056 Input Capture · T1071 Application Layer Protocol (exfil) |
| **Denial of Service** | T1499 Endpoint DoS · T1498 Network DoS · T1496 Resource Hijacking |
| **Elevation of Privilege** | T1068 Exploitation for Privilege Escalation · T1078 Valid Accounts · T1098 Account Manipulation · T1136 Create Account |

## How to apply

When you fill out the STRIDE worksheet, in the `mitre:` column add the technique IDs that match. A single threat can have several. Be specific: `T1190` is fine; `T1190.001` (a sub-technique) is better when applicable.

Why bother:

- During audit, the mapping shows that your threat model is grounded in observable adversary behavior.
- During incident response, the same IDs that appear in the threat model appear in detection rules and playbooks — the engineer responding doesn't need to translate.
- During hiring, putting MITRE technique IDs in your threat models is a small but unmistakable signal that you operate at security-engineering depth.

## References

- [MITRE ATT&CK enterprise matrix](https://attack.mitre.org/matrices/enterprise/)
- [STRIDE (original Microsoft post)](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
