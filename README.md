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
| 🧠 **Interactive AI Guidance** | Claude walks you through each of the 9 ADS sections step-by-step |
| 🗺️ **MITRE ATT&CK Mapping** | Automatic technique + sub-technique ID suggestions |
| ⚡ **Detection Logic Generation** | Production-ready Sigma, KQL (Sentinel), and SPL (Splunk) rules |
| 🕳️ **Blind Spot Analysis** | Adversarial thinking — where will your rule fail? |
| 🔇 **False Positive Analysis** | Known noise patterns and suppression strategies |
| ✅ **Validation Steps** | Unit-test-style true positive generation instructions |
| 📄 **Export** | Download full ADS as Markdown or JSON |
| 🌐 **No backend required** | Pure HTML/JS, runs in any browser |

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

## Quickstart

### Option 1: GitHub Pages (zero setup)
1. Fork this repo
2. Go to **Settings → Pages → Deploy from main branch**
3. Share your `https://yourusername.github.io/ads-forge` URL

### Option 2: Run locally
```bash
# No build step needed — just open the HTML file
open index.html
# or serve it
npx serve .
```

### Option 3: Deploy to Netlify / Vercel
Drop the repo into [Netlify Drop](https://app.netlify.com/drop) — done in 30 seconds.

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

```markdown
# ADS: LSASS Memory Access for Credential Dumping

## Goal
Detect unauthorized access to the LSASS process memory, which adversaries use 
to dump credentials including NTLM hashes and Kerberos tickets.

## MITRE ATT&CK
- T1003.001 — OS Credential Dumping: LSASS Memory (Credential Access)

## Detection Logic (Sigma)
title: LSASS Memory Access by Non-System Process
status: production
logsource:
    product: windows
    category: process_access
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1038'
            - '0x40'
    filter_legitimate:
        SourceImage|contains:
            - 'C:\Windows\System32\'
            - 'C:\Program Files\Windows Defender\'
    condition: selection and not filter_legitimate
falsepositives:
    - Security products (EDR, AV) — add to filter list
level: high
```

## Based On

- [Palantir Alerting and Detection Strategy Framework](https://github.com/palantir/alerting-detection-strategy-framework)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Sigma Rules Project](https://github.com/SigmaHQ/sigma)
- [Red Canary Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)

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

*Built with Claude (Anthropic) · Inspired by Palantir's ADS Framework*
