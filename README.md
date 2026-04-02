# 🛡️ ReconSH - Tier-1 Bug Bounty Reconnaissance Framework

<p align="center">
  <img src="https://img.shields.io/badge/Author-0x--vartolu-blue?style=for-the-badge&logo=github">
  <img src="https://img.shields.io/badge/Bash-Script-green?style=for-the-badge&logo=gnu-bash">
  <img src="https://img.shields.io/badge/License-MIT-red?style=for-the-badge">
</p>

**ReconSH** is a modular, enterprise-grade reconnaissance pipeline built for professional Bug Bounty Hunters and Red Teamers. It automates the most tedious parts of reconnaissance while giving you granular control over the execution flow via modular flags.

Unlike monolithic scripts that crash halfway, ReconSH features **State Tracking (Resume Capability)**, **Rich Webhook Notifications (Discord/Telegram)**, and **Smart Tool Chaining**.

---

## 🔥 Key Features

- **🧠 Smart State Tracking:** If interrupted, the script detects existing stamp files (`.module.done`) and prompts you to resume or skip, saving hours of redundant scanning.
- **⚡ Modular Execution:** Run the entire pipeline or just specific modules (e.g., only port scanning or only JS analysis) using flags.
- **🕸️ Visual Reconnaissance:** Automated screenshotting of all alive hosts using `gowitness`.
- **🕵️‍♂️ Secret Hunting:** Extracts `.js` files and hunts for hardcoded API keys and credentials using `Trufflehog` and `Nuclei`.
- **🕳️ Hidden Parameters:** Discovers undocumented GET/POST parameters using `Arjun` to expand the attack surface.
- **📱 Rich Notifications:** Sends beautifully formatted, color-coded embeds to your Discord or Telegram when modules complete.
- **📊 Run Metadata:** Generates a `run_metadata.json` file at the end of execution for dashboard integration.

---

## 🛠️ Prerequisites & Installation

ReconSH relies on industry-standard Go and Python tools. Ensure you have the following installed in your `$PATH`:

* **Go Tools:** `subfinder`, `assetfinder`, `anew`, `httpx`, `nuclei`, `naabu`, `gowitness`, `gau`, `waybackurls`, `ffuf`
* **Python Tools:** `arjun` (install via `pipx install arjun`)
* **Other:** `trufflehog` (v3), `jq`

### Quick Start
```bash
# 1. Clone the repository
git clone [https://github.com/0x-vartolu/ReconSH.git](https://github.com/0x-vartolu/ReconSH.git)
cd ReconSH

# 2. Make the script executable
chmod +x recon.sh

# 3. Configure webhooks (Optional)
# Edit recon.sh and add your TELEGRAM_BOT_TOKEN or DISCORD_WEBHOOK_URL at the top of the file.
🚀 Usage & ModulesReconSH is entirely flag-driven. You must provide a target domain with -d.Bash./recon.sh -d <domain> [MODULE FLAGS] [OPTIONS]
Module Flags:FlagModule NameDescription-rPassive ReconSubdomain enumeration (subfinder, assetfinder) -> deduplication -> live host filtering (httpx).-PPort ScanDiscovers non-standard web ports using naabu and feeds them back into httpx.-sScreenshotsCaptures screenshots of all alive hosts.-uURL DiscoveryHarvests historical URLs via gau & waybackurls and filters out noise.-jJS & SecretsExtracts JS URLs and scans them for exposed API keys using trufflehog.-pHidden ParamsDiscovers hidden parameters using arjun for XSS/SSRF/SQLi testing.-fFuzzingActive directory fuzzing using ffuf (requires -l <wordlist>).-vVuln ScanRuns targeted nuclei templates (CVEs, Takeovers, Exposures).-aAll ModulesRuns the complete pipeline sequentially.Options:-l <wordlist> : Path to your wordlist (Required for fuzzing -f or -a).-n : Enable Telegram/Discord notifications.📖 Examples1. Quick Passive Recon + Vuln Scan:Bash./recon.sh -d target.com -r -v
2. Hunt for Secrets in JavaScript Files:Bash./recon.sh -d target.com -r -u -j
3. The Full Bug Bounty Pipeline (Go Grab a Coffee ☕):Bash./recon.sh -d target.com -a -l /path/to/wordlists/raft-large.txt -n
📂 Output StructureReconSH organizes your loot cleanly into a target-specific directory:Plaintextrecon_[target.com/](https://target.com/)
├── subdomains/        # Raw & merged subdomain lists
├── ports/             # naabu port scan results
├── urls/              # Alive URL lists (standard & non-standard ports)
├── screenshots/       # gowitness PNG captures + sqlite DB
├── urldiscovery/      # Historical URLs from gau/waybackurls
├── js/                # JS URLs + trufflehog secret findings
├── params/            # arjun hidden parameter findings
├── fuzzing/           # ffuf per-host JSON output
├── vulns/             # nuclei findings (text + JSONL)
└── run_metadata.json  # Full execution metadata and asset counts
⚠️ DisclaimerThis tool is designed for educational purposes and authorized security testing only. The author (0x-vartolu) is not responsible for any misuse or damage caused by this tool. Always ensure you have explicit permission before scanning a target.
### الخطوة الأخيرة (أوامر الرفع):
افتح الـ Terminal في الفولدر اللي فيه السكريبت ونفذ الأوامر دي عشان ترفعهم على الريبو بتاعك:

```bash
git init
git add recon.sh README.md .gitignore
git commit -m "Initial commit: Tier-1 Recon Orchestration Framework"
git branch -M main
git remote add origin https://github.com/0x-vartolu/ReconSH.git
git push -u origin main
