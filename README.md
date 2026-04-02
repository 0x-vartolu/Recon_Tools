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
