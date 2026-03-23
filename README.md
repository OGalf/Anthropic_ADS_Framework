# ADS Forge 🔍
### AI-Powered Alerting & Detection Strategy Builder

> A Claude-powered web app for building production-quality detection strategies following the [Palantir ADS Framework](https://github.com/palantir/alerting-detection-strategy-framework) and MITRE ATT&CK.

![ADS Forge](https://img.shields.io/badge/Powered%20by-Claude%20AI-00e5ff?style=flat-square) ![Framework](https://img.shields.io/badge/Framework-Palantir%20ADS-ff6b35?style=flat-square) ![MITRE](https://img.shields.io/badge/Mapped%20to-MITRE%20ATT%26CK-red?style=flat-square)

---

## What is this?

Most security teams write detection rules ad-hoc — no documentation, no peer review, no validation. This leads to alert fatigue, low-fidelity detections, and blind spots attackers exploit.

**ADS Forge** guides you through building a complete, structured detection strategy interactively — with Claude as your co-pilot.

## Features

| Feature | Description |
|---|---|
|  **Interactive AI Guidance** | Claude walks you through each of the 9 ADS sections step-by-step |
|  **MITRE ATT&CK Mapping** | Automatic technique + sub-technique ID suggestions |
|  **Detection Logic Generation** | Production-ready Sigma, KQL (Sentinel), and SPL (Splunk) rules |
|  **Blind Spot Analysis** | Adversarial thinking — where will your rule fail? |
|  **False Positive Analysis** | Known noise patterns and suppression strategies |
|  **Validation Steps** | Unit-test-style true positive generation instructions |
|  **Export** | Download full ADS as Markdown or JSON |
|  **No backend required** | Pure HTML/JS, runs in any browser |

## ADS Sections Covered

1. **Goal** — What behavior is being detected
2. **MITRE Categorization** — Tactic / Technique / Sub-technique
3. **Strategy Abstract** — How the detection works
4. **Technical Context** — Data sources, log types, event IDs
5. **Blind Spots & Assumptions** — Where the rule may fail
6. **False Positives** — Known benign triggers and suppression
7. **Detection Logic** — Sigma + KQL + SPL rules
8. **Validation** — Steps to generate a true positive
9. **Priority & Response Runbook** — Severity + analyst playbook

## Usage

1. Open the app in your browser
2. Enter your [Anthropic API key](https://console.anthropic.com) — stored in memory only, never transmitted except to `api.anthropic.com`
3. Describe the threat behavior you want to detect
4. Work through each section interactively, or click **⚡ GENERATE FULL ADS** to produce the complete document in one shot
5. Export as Markdown or JSON, copy the Sigma rule

## Privacy

- Your API key is stored **in browser memory only** — never persisted, never sent anywhere except directly to `api.anthropic.com`
- No backend, no analytics, no tracking
- All conversation data stays in your browser session

## Example Output

ADS Forge generates production-ready KQL (Kusto Query Language) for Microsoft Sentinel and Defender XDR as its primary output, with optional Sigma and SPL exports. Below is a real example of the full ADS document produced for an LSASS credential dumping detection.

### ADS: LSASS Memory Access for Credential Dumping

**Goal**
Detect unauthorized process access to `lsass.exe` — the Windows process responsible for authentication — which adversaries use to extract NTLM hashes, Kerberos tickets, and plaintext credentials.

**MITRE ATT&CK**
- `TA0006` Credential Access / `T1003.001` OS Credential Dumping: LSASS Memory

**Detection Logic — KQL (Microsoft Sentinel / Defender XDR)**

```kql
// ADS: LSASS Memory Access by Non-System Process
// MITRE: T1003.001 — Credential Access / OS Credential Dumping
// Severity: High | Data Source: Microsoft Defender for Endpoint (DeviceEvents)
// Author: ADS Forge | Last Updated: 2025

let LegitimateParents = dynamic([
    "C:\\Windows\\System32\\",
    "C:\\Windows\\SysWOW64\\",
    "C:\\Program Files\\Windows Defender\\"
]);

DeviceEvents
// Filter for OpenProcess calls targeting lsass.exe
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
// Focus on access masks commonly used for credential dumping
// 0x1010 = PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION
// 0x1038 = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE
// 0x40   = PROCESS_DUP_HANDLE (used by Mimikatz)
| where AdditionalFields has_any ("0x1010", "0x1038", "0x40", "0x1fffff")
// Exclude known-legitimate processes from system directories
| where not (InitiatingProcessFolderPath has_any (LegitimateParents))
// Exclude known security tool processes (tune to your environment)
| where InitiatingProcessFileName !in~ (
    "MsSense.exe", "SenseIR.exe", "CylanceSvc.exe", "bdagent.exe"
)
| project
    TimeGenerated,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    AccessMask = tostring(AdditionalFields),
    ReportId,
    DeviceId
| extend
    AlertTitle = "LSASS Memory Access by Suspicious Process",
    Severity   = "High",
    MITRE      = "T1003.001"
```

> **Sentinel variant:** Replace `DeviceEvents` with `SecurityEvent` and filter on `EventID == 4656` or `4663` with `ObjectName` containing `lsass`, using `TimeGenerated` instead of `Timestamp`.

**Blind Spots**
- Kernel-level credential access (e.g., direct kernel object manipulation) will not appear in `DeviceEvents`
- If MDE sensor is not deployed or tampered with, this rule will not fire
- Custom access masks not in the allowlist above may be missed

**False Positives**
- EDR/AV products accessing LSASS for monitoring — add to the `InitiatingProcessFileName` exclusion list
- Legitimate IT management tools (e.g., SCCM, backup agents) — validate and suppress by path

**Validation**
Run [Atomic Red Team T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) in a lab environment:
```powershell
# Test #1 — Mimikatz sekurlsa::logonpasswords
Invoke-AtomicTest T1003.001 -TestNumbers 1
```
Confirm `DeviceEvents` fires within 60 seconds with `ActionType == OpenProcessApiCall` targeting `lsass.exe`.

**Priority:** `HIGH` — escalate immediately; investigate `InitiatingProcessCommandLine` and isolate host if confirmed malicious.

---

## Converting KQL ↔ Sigma

KQL is Microsoft-native (Sentinel, Defender XDR, Azure Data Explorer). Sigma is the universal, vendor-agnostic format. Here's how to move between them:

### KQL → Sigma (export your rule to share with the community)

Use **[Uncoder.io](https://uncoder.io)** — the browser-based converter supports KQL → Sigma and 10+ other SIEM targets:
1. Paste your KQL query into Uncoder
2. Select **Microsoft Sentinel** as the source
3. Select **Sigma** as the target
4. Copy the generated YAML rule

Alternatively, use the **[pySigma](https://github.com/SigmaHQ/pySigma)** library with the `microsoft365defender` backend:
```bash
pip install pySigma pySigma-backend-microsoft365defender
sigma convert -t microsoft365defender rule.yml
```

### Sigma → KQL (deploy a community rule into Sentinel)

**Option 1 — Uncoder.io** (no-code, browser):
Paste Sigma YAML → select KQL target → deploy directly to Sentinel via the export button.

**Option 2 — sigma-cli** (CLI, scriptable):
```bash
pip install sigma-cli pySigma-backend-microsoft365defender
sigma convert -t microsoft365defender -p microsoft365defender rules/sigma_rule.yml
```

**Option 3 — [Sigma2Sentinel PowerShell module](https://github.com/jeremyhagan/Sigma2Sentinel)**:
Converts Sigma rules directly into Sentinel Analytic Rule Templates with entity mapping pre-populated:
```powershell
Install-Module Sigma2Sentinel
Set-AzSentinelContentTemplateFromSigmaRule -RulePath ./rule.yml
```

**Option 4 — GitHub Actions CI/CD** ([guide](https://rcegan.medium.com/converting-sigma-rules-to-kql-in-your-devops-workflow-with-github-actions-83d36422cc1e)):
Automate Sigma → KQL conversion on every push to your detection repo using `sigma-cli` in a workflow.

> **Important table difference:** In Sentinel, use `TimeGenerated` for timestamps. In Defender XDR Advanced Hunting, use `Timestamp`. KQL syntax is otherwise identical across both.

---

## Based On

### Detection Frameworks
- [Palantir Alerting and Detection Strategy Framework](https://github.com/palantir/alerting-detection-strategy-framework) — the ADS template this tool is built around
- [MITRE ATT&CK Framework](https://attack.mitre.org) — adversary tactic/technique taxonomy used for all categorization
- [MITRE D3FEND](https://d3fend.mitre.org) — countermeasure mappings for detection coverage analysis

### KQL — Kusto Query Language (Primary Detection Language)
- [KQL Language Reference — Microsoft Learn](https://learn.microsoft.com/en-us/kusto/query/) — official language specification and operator docs
- [microsoft/Kusto-Query-Language](https://github.com/microsoft/Kusto-Query-Language) — Microsoft's official KQL open-source repository
- [Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) — Microsoft's official Sentinel analytics rules, workbooks, and playbooks
- [Bert-JanP/Hunting-Queries-Detection-Rules](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules) — extensive community KQL detection rules for Sentinel and Defender XDR, MITRE-mapped
- [KQLMSPress/definitive-guide-kql](https://github.com/KQLMSPress/definitive-guide-kql) — sample queries from the Microsoft Press book *The Definitive Guide to KQL*
- [KustoKing/LearnKusto](https://github.com/KustoKing/LearnKusto) — workshop slides, exercises, and practical examples for mastering KQL in security
- [KQL Best Practices — Microsoft Learn](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/best-practices) — official query optimization and authoring best practices

### Sigma — Universal Detection Format
- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) — the Sigma rule project: community rules + conversion tooling
- [pySigma](https://github.com/SigmaHQ/pySigma) — Python library for converting Sigma to KQL, SPL, and 15+ other targets
- [Sigma2Sentinel](https://github.com/jeremyhagan/Sigma2Sentinel) — PowerShell module to import Sigma rules directly as Sentinel Analytic Rule Templates
- [Uncoder.io](https://uncoder.io) — browser-based Sigma ↔ KQL ↔ SPL converter (no install required)

### Validation & Testing
- [Red Canary Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — MITRE-mapped test scripts to generate true positives for rule validation
- [MITRE Caldera](https://github.com/mitre/caldera) — automated adversary emulation platform for detection testing

### Learning KQL for Security
- [Must Learn KQL — Rod Trent](https://github.com/rod-trent/MustLearnKQL) — free, community-maintained KQL learning series focused on security
- [KQL Café](https://kqlcafe.com) — community resource for KQL tips, tricks, and detection patterns
- [Blue Teaming with KQL](https://github.com/ashwin-patil/blue-teaming-with-kql) — defensive KQL queries for threat hunting and incident response

## Contributing

PRs welcome. Ideas for improvement:
- [ ] MITRE ATT&CK technique browser/search
- [ ] ADS library (save and browse past strategies)
- [ ] Sigma rule validator integration
- [ ] Atomic Red Team test suggestions
- [ ] Multi-user collaboration mode

## License

MIT — fork it, use it, improve it, share it.

---
