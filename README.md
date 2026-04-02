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
\`\`\`bash
# 1. Clone the repository
git clone https://github.com/0x-vartolu/ReconSH.git
cd ReconSH

# 2. Make the script executable
chmod +x recon.sh

# 3. Configure webhooks (Optional)
# Edit recon.sh and add your TELEGRAM_BOT_TOKEN or DISCORD_WEBHOOK_URL at the top of the file.
\`\`\`

---

## 🚀 Usage & Modules

ReconSH is entirely flag-driven. You must provide a target domain with `-d`.

\`\`\`bash
./recon.sh -d <domain> [MODULE FLAGS] [OPTIONS]
\`\`\`

### Module Flags:
| Flag | Module Name | Description |
|---|---|---|
| `-r` | **Passive Recon** | Subdomain enumeration (`subfinder`, `assetfinder`) -> deduplication -> live host filtering (`httpx`). |
| `-P` | **Port Scan** | Discovers non-standard web ports using `naabu` and feeds them back into `httpx`. |
| `-s` | **Screenshots** | Captures screenshots of all alive hosts. |
| `-u` | **URL Discovery** | Harvests historical URLs via `gau` & `waybackurls` and filters out noise. |
| `-j` | **JS & Secrets** | Extracts JS URLs and scans them for exposed API keys using `trufflehog`. |
| `-p` | **Hidden Params** | Discovers hidden parameters using `arjun` for XSS/SSRF/SQLi testing. |
| `-f` | **Fuzzing** | Active directory fuzzing using `ffuf` (requires `-l <wordlist>`). |
| `-v` | **Vuln Scan** | Runs targeted `nuclei` templates (CVEs, Takeovers, Exposures). |
| `-a` | **All Modules** | Runs the complete pipeline sequentially. |

### Options:
* `-l <wordlist>` : Path to your wordlist (Required for fuzzing `-f` or `-a`).
* `-n` : Enable Telegram/Discord notifications.

---

## 📖 Examples

**1. Quick Passive Recon + Vuln Scan:**
\`\`\`bash
./recon.sh -d target.com -r -v
\`\`\`

**2. Hunt for Secrets in JavaScript Files:**
\`\`\`bash
./recon.sh -d target.com -r -u -j
\`\`\`

**3. The Full Bug Bounty Pipeline:**
\`\`\`bash
./recon.sh -d target.com -a -l /path/to/wordlists/raft-large.txt -n
\`\`\`

---

## 📂 Output Structure

ReconSH organizes your loot cleanly into a target-specific directory:

```text
recon_target.com/
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
```
