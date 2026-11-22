# Microsoft Sentinel KQL Threat-Hunting & Endpoint Compliance Pack

A curated collection of production-ready **Kusto Query Language (KQL)** detection rules and compliance audits mapped to **MITRE ATT&CK**, covering Microsoft Entra ID identity attacks, Intune endpoint compliance drift, and Linux SSH authentication telemetry—paired with a Python CI metadata validator.

## Repository Structure

| Category | Detection Rule | Data Table | MITRE ATT&CK |
| :--- | :--- | :--- | :--- |
| **Entra ID** | `entra-id/password-spray-and-mfa-fatigue.kql` | `SigninLogs` | `T1110.003`, `T1621` |
| **Entra ID** | `entra-id/privileged-role-assignment-audit.kql` | `AuditLogs` | `T1098.003` |
| **Intune** | `intune-endpoints/noncompliant-endpoint-drift.kql` | `IntuneDeviceComplianceOrg` | `T1562` |
| **Linux / Syslog** | `network-linux/linux-ssh-brute-force-hunt.kql` | `Syslog` | `T1110`, `T1078` |

## Query Metadata Validation
Run the included Python validator to verify that every `.kql` detection includes standardized title, MITRE ATT&CK technique, and data source annotations:

```bash
python3 validate_queries.py
```
