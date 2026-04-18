#!/usr/bin/env bash
# ==============================================================================
#
#  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ███████╗██╗  ██╗
#  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██╔════╝██║  ██║
#  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ███████╗███████║
#  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ╚════██║██╔══██║
#  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ███████║██║  ██║
#  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚══════╝╚═╝  ╚═╝
#
#  Tier-1 Bug Bounty Reconnaissance Orchestration Framework
#  ─────────────────────────────────────────────────────────
#  Version  : 4.0.0
#  Author   : 0x-vartolu
#  License  : MIT
#
#  DESCRIPTION:
#    A modular, flag-driven, enterprise-grade reconnaissance pipeline for
#    professional bug bounty hunting. Integrates 30+ specialised tools across
#    passive enumeration, active bruteforcing, URL harvesting, JS secret
#    analysis, vhost fuzzing, directory bruteforcing, port scanning, and
#    hidden parameter discovery. Features state tracking / resume capability,
#    visual spinners, rich webhook embeds (Telegram + Discord), and a full
#    run metadata JSON report.
#
#  FULL MODULE FLAGS:
#    -r   Passive + Active Recon   Multi-source subdomain enum → dedup → httpx
#    -P   Port Scan                naabu (all ports) + nmap service scan
#    -s   Screenshots              gowitness visual recon on alive hosts
#    -f   Fuzzing                  ffuf dir/vhost fuzzing + feroxbuster (needs -l)
#    -u   URL Discovery            10-source URL harvest → category filtering
#    -j   JS & Secrets             subjs/mantra/jsecret/jsleak + trufflehog
#    -p   Hidden Params            arjun GET/POST + qsreplace FUZZ list
#    -v   Vuln Scan                nuclei CVE/takeover/misconfig/exposure scanning
#    -a   All Modules              Full pipeline in dependency order
#
#  USAGE:
#    ./recon.sh -d target.com -r -P                      # Recon + port scan
#    ./recon.sh -d target.com -r -u -j                   # Recon + URL + secrets
#    ./recon.sh -d target.com -a -l wordlist.txt -n      # Full pipeline + notify
#
#  ENVIRONMENT VARIABLES (optional, loaded automatically if exported):
#    PDCP_API_KEY     ProjectDiscovery chaos tool API key
#    GITHUB_TOKEN     GitHub personal access token (for github-subdomains)
#    NUCLEI_TEMPLATES Path to local nuclei-templates directory
# ==============================================================================

set -uo pipefail   # Undefined vars are errors; pipe failures propagate
IFS=$'\n\t'        # Safer word splitting

# ══════════════════════════════════════════════════════════════════════════════
# §1 ─ ANSI COLOUR PALETTE & LOGGING PREFIXES
# ══════════════════════════════════════════════════════════════════════════════

readonly C_RESET='\033[0m'
readonly C_BOLD='\033[1m'
readonly C_DIM='\033[2m'

readonly C_RED='\033[0;31m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[0;33m'
readonly C_BLUE='\033[0;34m'
readonly C_MAGENTA='\033[0;35m'
readonly C_CYAN='\033[0;36m'
readonly C_WHITE='\033[0;37m'

readonly C_BRED='\033[1;31m'
readonly C_BGREEN='\033[1;32m'
readonly C_BYELLOW='\033[1;33m'
readonly C_BBLUE='\033[1;34m'
readonly C_BMAGENTA='\033[1;35m'
readonly C_BCYAN='\033[1;36m'
readonly C_BWHITE='\033[1;37m'

# Semantic logging prefixes
readonly LOG_OK="${C_BGREEN}[+]${C_RESET}"
readonly LOG_INFO="${C_BCYAN}[*]${C_RESET}"
readonly LOG_WARN="${C_BYELLOW}[~]${C_RESET}"
readonly LOG_ERR="${C_BRED}[!]${C_RESET}"
readonly LOG_SKIP="${C_BBLUE}[→]${C_RESET}"
readonly LOG_SEP="${C_BLUE}$(printf '%0.s─' {1..72})${C_RESET}"

# ══════════════════════════════════════════════════════════════════════════════
# §2 ─ SCRIPT METADATA & MUTABLE RUNTIME GLOBALS
# ══════════════════════════════════════════════════════════════════════════════

readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_VERSION="4.0.0"
readonly SCRIPT_AUTHOR="0x-vartolu"
readonly RUN_START_TS="$(date +%s)"
readonly RUN_START_HUMAN="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

# ── Mutable runtime state ─────────────────────────────────────────────────────
TARGET_DOMAIN=""
WORDLIST_FILE=""
OUTPUT_BASE_DIR=""

# Module activation flags
RUN_RECON=0
RUN_PORTSCAN=0
RUN_SCREENSHOTS=0
RUN_FUZZING=0
RUN_URLDISCOVERY=0
RUN_JSSECRETS=0
RUN_HIDDENPARAMS=0
RUN_VULN=0
RUN_ALL=0
RUN_NOTIFY=0

# ── Notification credentials ──────────────────────────────────────────────────
# Replace placeholder values with real credentials before using -n
readonly TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-__YOUR_TELEGRAM_BOT_TOKEN__}"
readonly TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-__YOUR_TELEGRAM_CHAT_ID__}"
readonly DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-https://discord.com/api/webhooks/__YOUR_WEBHOOK_ID__/__YOUR_WEBHOOK_TOKEN__}"

# ── Global counters (accumulated across modules for metadata report) ──────────
declare -A META_COUNTS=(
    [subdomains]=0
    [ports]=0
    [alive_hosts]=0
    [screenshots]=0
    [total_urls]=0
    [js_files]=0
    [secrets]=0
    [hidden_params]=0
    [vuln_findings]=0
    [fuzz_hits]=0
    [url_categories]=0
    [origin_ips]=0
)

# ── Spinner state ─────────────────────────────────────────────────────────────
SPINNER_PID=0

# ══════════════════════════════════════════════════════════════════════════════
# §3 ─ CORE LOGGING & UI UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

log_info()  { echo -e "${LOG_INFO}  ${C_WHITE}$*${C_RESET}"; }
log_ok()    { echo -e "${LOG_OK}  ${C_BGREEN}$*${C_RESET}"; }
log_warn()  { echo -e "${LOG_WARN}  ${C_BYELLOW}$*${C_RESET}"; }
log_err()   { echo -e "${LOG_ERR}  ${C_BRED}$*${C_RESET}" >&2; }
log_skip()  { echo -e "${LOG_SKIP}  ${C_DIM}$*${C_RESET}"; }

die() {
    local msg="$1"
    local code="${2:-1}"
    log_err "FATAL: ${msg}"
    exit "${code}"
}

log_section() {
    local title="$1"
    echo ""
    echo -e "${LOG_SEP}"
    echo -e "  ${C_BOLD}${C_BMAGENTA}◈  ${title}${C_RESET}"
    echo -e "${LOG_SEP}"
    echo ""
}

log_sub() {
    # Indented sub-step within a module
    echo -e "  ${C_DIM}├─${C_RESET}  ${C_WHITE}$*${C_RESET}"
}

log_sub_ok() {
    echo -e "  ${C_DIM}└─${C_RESET}  ${C_BGREEN}$*${C_RESET}"
}

# ── Spinner ───────────────────────────────────────────────────────────────────
spinner_start() {
    local label="${1:-Working...}"
    [[ "${SPINNER_PID}" -ne 0 ]] && return 0
    (
        local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
        local i=0
        trap 'tput el1 2>/dev/null; printf "\r" >&2; exit 0' TERM
        while true; do
            printf "\r  ${C_BCYAN}%s${C_RESET}  ${C_DIM}%s${C_RESET}" \
                "${frames[$((i % ${#frames[@]}))]}" "${label}" >&2
            (( i++ )) || true
            sleep 0.08
        done
    ) &
    SPINNER_PID=$!
    trap 'spinner_stop' EXIT
}

spinner_stop() {
    if [[ "${SPINNER_PID}" -ne 0 ]]; then
        kill "${SPINNER_PID}" 2>/dev/null || true
        wait "${SPINNER_PID}" 2>/dev/null || true
        SPINNER_PID=0
        printf "\r\033[K" >&2
    fi
}

# elapsed_since <epoch_seconds>  →  "Xm Ys"
elapsed_since() {
    local start="$1"
    local now
    now="$(date +%s)"
    local diff=$(( now - start ))
    printf "%dm %ds" $(( diff / 60 )) $(( diff % 60 ))
}

# ══════════════════════════════════════════════════════════════════════════════
# §4 ─ PREFLIGHT VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

# check_tool <binary>  →  non-fatal, returns 1 if missing
check_tool() {
    local tool="$1"
    if ! command -v "${tool}" &>/dev/null; then
        log_warn "Optional tool not found: ${C_BOLD}${tool}${C_RESET}${C_BYELLOW} — step will be skipped."
        return 1
    fi
    return 0
}

# check_required_tool <binary>  →  fatal if missing
check_required_tool() {
    local tool="$1"
    if ! command -v "${tool}" &>/dev/null; then
        die "Required tool '${tool}' not found in PATH. Please install it and retry." 2
    fi
}

validate_domain() {
    local domain="$1"
    if [[ "${domain}" =~ ^https?:// ]]; then
        die "Provide a bare domain without protocol prefix (e.g. 'target.com')." 2
    fi
    if [[ ! "${domain}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]]; then
        die "Invalid domain format: '${domain}'." 2
    fi
}

validate_file() {
    local filepath="$1"
    local label="${2:-file}"
    [[ -z "${filepath}" ]]   && die "A ${label} path is required but was not provided." 2
    [[ ! -f "${filepath}" ]] && die "The specified ${label} does not exist: '${filepath}'" 2
}

count_lines() {
    local file="$1"
    if [[ -f "${file}" && -s "${file}" ]]; then
        wc -l < "${file}" | tr -d ' '
    else
        echo "0"
    fi
}

# ── Preflight tool table ───────────────────────────────────────────────────────
# Displayed at startup so the user knows what is / isn't available before
# the pipeline begins. Grouped by module for easy reading.
preflight_tool_check() {
    log_section "PREFLIGHT — Tool Availability Check"

    # Format: "tool:module_label"
    local -a tool_map=(
        # Recon
        "subfinder:Recon"
        "assetfinder:Recon"
        "amass:Recon"
        "findomain:Recon"
        "chaos:Recon"
        "github-subdomains:Recon"
        "puredns:Recon(active)"
        "dnsx:Recon(active)"
        "ffuf:Recon(vhost)"
        "httpx:Recon(alive)"
        "anew:All(dedup)"
        # Port scan
        "naabu:PortScan"
        "nmap:PortScan"
        # Screenshots
        "gowitness:Screenshots"
        # URL discovery
        "waybackurls:URLDiscovery"
        "gau:URLDiscovery"
        "gauplus:URLDiscovery"
        "waymore:URLDiscovery"
        "hakrawler:URLDiscovery"
        "katana:URLDiscovery"
        "gospider:URLDiscovery"
        "paramspider:URLDiscovery"
        # JS & Secrets
        "subjs:JS+Secrets"
        "mantra:JS+Secrets"
        "jsecret:JS+Secrets"
        "jsleak:JS+Secrets"
        "trufflehog:JS+Secrets"
        "lazyegg:JS+Secrets"
        # Params
        "arjun:HiddenParams"
        "qsreplace:HiddenParams"
        # Fuzzing
        "feroxbuster:Fuzzing"
        # Vuln
        "nuclei:VulnScan"
        # Utilities
        "jq:Utilities"
        "curl:Utilities"
        "wget:Utilities"
        "python3:Utilities"
    )

    local ok_count=0
    local miss_count=0
    local -A module_miss=()

    for entry in "${tool_map[@]}"; do
        local tool="${entry%%:*}"
        local mod="${entry##*:}"
        if command -v "${tool}" &>/dev/null; then
            printf "  ${C_BGREEN}✔${C_RESET}  %-24s ${C_DIM}%s${C_RESET}\n" "${tool}" "[${mod}]"
            (( ok_count++ )) || true
        else
            printf "  ${C_BYELLOW}○${C_RESET}  %-24s ${C_DIM}%s — not found${C_RESET}\n" "${tool}" "[${mod}]"
            module_miss["${mod}"]="${module_miss["${mod}"]:-}${tool} "
            (( miss_count++ )) || true
        fi
    done

    echo ""
    log_ok  "${ok_count} tool(s) available."
    [[ "${miss_count}" -gt 0 ]] && \
        log_warn "${miss_count} tool(s) missing — dependent steps will be skipped gracefully."
    echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
# §5 ─ OUTPUT DIRECTORY SETUP
# ══════════════════════════════════════════════════════════════════════════════

setup_output_dirs() {
    OUTPUT_BASE_DIR="recon_${TARGET_DOMAIN}"

    log_info "Initialising output tree at: ${C_BOLD}${OUTPUT_BASE_DIR}/${C_RESET}"

    local -a subdirs=(
        "subdomains"          # Raw subdomain files + merged list
        "subdomains/active"   # Brute-force / DNS-based results
        "ports"               # naabu + nmap results
        "urls"                # Alive URL lists
        "screenshots"         # gowitness captures
        "urldiscovery"        # All-source merged URL harvest
        "urldiscovery/categories"   # Filtered category files
        "js"                  # JS URLs + downloaded files
        "js/files"            # Downloaded .js content for local scanning
        "params"              # arjun + qsreplace parameter lists
        "fuzzing"             # ffuf + feroxbuster results
        "fuzzing/vhost"       # vhost-specific ffuf output
        "vulns"               # nuclei findings
    )

    for dir in "${subdirs[@]}"; do
        mkdir -p "${OUTPUT_BASE_DIR}/${dir}"
    done

    log_ok "Directory tree ready."
}

# ══════════════════════════════════════════════════════════════════════════════
# §6 ─ STATE TRACKING & RESUME CAPABILITY
# ══════════════════════════════════════════════════════════════════════════════

mark_done() {
    local module="$1"
    echo "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        > "${OUTPUT_BASE_DIR}/.${module}.done"
}

is_done() {
    local module="$1"
    [[ -f "${OUTPUT_BASE_DIR}/.${module}.done" ]]
}

check_resume() {
    local module="$1"
    local label="$2"

    if is_done "${module}"; then
        local done_ts
        done_ts="$(cat "${OUTPUT_BASE_DIR}/.${module}.done" 2>/dev/null || echo "unknown")"
        echo ""
        echo -e "  ${C_BYELLOW}⚡ Resume detected:${C_RESET} ${C_BOLD}${label}${C_RESET} was completed at ${C_DIM}${done_ts}${C_RESET}"
        echo -ne "  ${C_BCYAN}Skip this module and use existing results? [Y/n]:${C_RESET} "

        if [[ ! -t 0 ]]; then
            echo "y (non-interactive: auto-skip)"
            echo "skip"
            return 0
        fi

        local answer
        read -r answer
        answer="${answer,,}"

        if [[ "${answer}" == "n" || "${answer}" == "no" ]]; then
            log_info "Re-running ${label} as requested."
            rm -f "${OUTPUT_BASE_DIR}/.${module}.done"
            echo "run"
        else
            log_skip "Skipping ${label} — using cached results."
            echo "skip"
        fi
    else
        echo "run"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# §7 ─ RICH NOTIFICATION MODULE
# ══════════════════════════════════════════════════════════════════════════════

notify_module() {
    [[ "${RUN_NOTIFY}" -eq 0 ]] && return 0

    local module_name="${1:-Unknown Module}"
    local status_line="${2:-Completed}"
    local detail_line="${3:-}"
    local elapsed="${4:-N/A}"
    local now_human
    now_human="$(date -u +'%Y-%m-%d %H:%M UTC')"

    # ── Telegram (MarkdownV2) ─────────────────────────────────────────────────
    if [[ "${TELEGRAM_BOT_TOKEN}" != *"__YOUR_TELEGRAM"* ]]; then
        local tg_text
        tg_text="$(printf \
'🔍 *ReconSH v%s* — %s
━━━━━━━━━━━━━━━━━━━━
🎯 Target    \: \`%s\`
📦 Module    \: *%s*
📊 Status    \: %s
📝 Details   \: %s
⏱ Elapsed   \: %s
🕐 Time      \: %s' \
            "${SCRIPT_VERSION}" \
            "${module_name}" \
            "${TARGET_DOMAIN}" \
            "${module_name}" \
            "${status_line}" \
            "${detail_line}" \
            "${elapsed}" \
            "${now_human}"
        )"

        curl -s -X POST \
            "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d "chat_id=${TELEGRAM_CHAT_ID}" \
            --data-urlencode "text=${tg_text}" \
            -d "parse_mode=Markdown" \
            -o /dev/null \
            --max-time 15 \
            && log_ok "Telegram notification sent." \
            || log_warn "Telegram notification failed (check bot token / chat ID)."
    else
        log_warn "Telegram credentials not configured. Edit TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID."
    fi

    # ── Discord (Rich Embed JSON) ─────────────────────────────────────────────
    if [[ "${DISCORD_WEBHOOK_URL}" != *"__YOUR_WEBHOOK_ID__"* ]]; then
        local embed_colour=49151
        [[ "${status_line}" == *"⚠"* || "${status_line}" == *"ERROR"* ]] \
            && embed_colour=15158332

        local discord_payload
        discord_payload="$(cat <<JSON
{
  "username": "ReconSH v${SCRIPT_VERSION}",
  "avatar_url": "https://raw.githubusercontent.com/projectdiscovery/nuclei/master/static/nuclei-logo.png",
  "embeds": [{
    "title": "🔍 ${module_name}",
    "description": "${detail_line}",
    "color": ${embed_colour},
    "fields": [
      { "name": "🎯 Target",  "value": "\`${TARGET_DOMAIN}\`", "inline": true },
      { "name": "📊 Status",  "value": "${status_line}",       "inline": true },
      { "name": "⏱ Elapsed", "value": "${elapsed}",           "inline": true }
    ],
    "footer": {
      "text": "ReconSH by ${SCRIPT_AUTHOR}  •  ${now_human}"
    }
  }]
}
JSON
        )"

        curl -s -X POST \
            "${DISCORD_WEBHOOK_URL}" \
            -H "Content-Type: application/json" \
            -d "${discord_payload}" \
            -o /dev/null \
            --max-time 15 \
            && log_ok "Discord notification sent." \
            || log_warn "Discord notification failed (check webhook URL)."
    else
        log_warn "Discord webhook URL not configured. Edit DISCORD_WEBHOOK_URL."
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# §8 ─ MODULE: PASSIVE + ACTIVE SUBDOMAIN RECON  (-r)
# ══════════════════════════════════════════════════════════════════════════════
#
# PASSIVE SOURCES:
#   subfinder (-all -recursive) · assetfinder · amass · findomain
#   chaos (PDCP_API_KEY) · github-subdomains (GITHUB_TOKEN) · crt.sh
#
# ACTIVE / BRUTE-FORCE:
#   puredns bruteforce (wordlist) · dnsx wordlist · vhost probe via httpx
#
# STEP 2 MERGE LOGIC (from methodology):
#   cat subs_*.txt | anew | tee all_subs.txt   (anew deduplicates in-place)
#   Fallback: sort -u if anew is unavailable
#
# OUTPUT FILES:
#   subdomains/subs_subfinder.txt        Raw subfinder output
#   subdomains/subs_assetfinder.txt      Raw assetfinder output
#   subdomains/subs_amass.txt            Raw amass output
#   subdomains/subs_findomain.txt        Raw findomain output
#   subdomains/subs_chaos.txt            Raw chaos output
#   subdomains/subs_github.txt           Raw github-subdomains output
#   subdomains/subs_crtsh.txt            Certificate transparency results
#   subdomains/active/subs_puredns.txt   puredns brute-force results
#   subdomains/active/subs_dnsx.txt      dnsx brute-force results
#   subdomains/all_subs.txt              Merged + deduplicated master list
#   urls/alive_hosts.txt                 httpx full output (status/title/tech)
#   urls/alive_urls.txt                  Plain URL list for downstream modules
# ──────────────────────────────────────────────────────────────────────────────
module_recon() {
    log_section "MODULE ─ Passive + Active Subdomain Recon  [-r]"

    local decision
    decision="$(check_resume "recon" "Passive + Active Recon")"
    [[ "${decision}" == "skip" ]] && return 0

    local t0; t0="$(date +%s)"
    local subs_dir="${OUTPUT_BASE_DIR}/subdomains"
    local active_dir="${subs_dir}/active"
    local urls_dir="${OUTPUT_BASE_DIR}/urls"
    local all_subs="${subs_dir}/all_subs.txt"

    # ── PASSIVE: subfinder ─────────────────────────────────────────────────────
    if check_tool "subfinder"; then
        log_sub "subfinder (-all -recursive) …"
        spinner_start "subfinder enumerating all sources…"
        subfinder \
            -d "${TARGET_DOMAIN}" \
            -all \
            -recursive \
            -silent \
            -o "${subs_dir}/subs_subfinder.txt" \
            2>/dev/null || true
        spinner_stop
        log_sub_ok "subfinder → $(count_lines "${subs_dir}/subs_subfinder.txt") results"
    fi

    # ── PASSIVE: assetfinder ───────────────────────────────────────────────────
    if check_tool "assetfinder"; then
        log_sub "assetfinder …"
        spinner_start "assetfinder enumerating…"
        echo "${TARGET_DOMAIN}" | assetfinder --subs-only \
            > "${subs_dir}/subs_assetfinder.txt" 2>/dev/null || true
        spinner_stop
        log_sub_ok "assetfinder → $(count_lines "${subs_dir}/subs_assetfinder.txt") results"
    fi

    # ── PASSIVE: amass ─────────────────────────────────────────────────────────
    if check_tool "amass"; then
        log_sub "amass enum (passive) …"
        spinner_start "amass enumerating (passive)…"
        amass enum \
            -d "${TARGET_DOMAIN}" \
            -passive \
            -o "${subs_dir}/subs_amass.txt" \
            2>/dev/null || true
        spinner_stop
        log_sub_ok "amass → $(count_lines "${subs_dir}/subs_amass.txt") results"
    fi

    # ── PASSIVE: findomain ─────────────────────────────────────────────────────
    if check_tool "findomain"; then
        log_sub "findomain …"
        spinner_start "findomain enumerating…"
        findomain \
            -t "${TARGET_DOMAIN}" \
            -u "${subs_dir}/subs_findomain.txt" \
            2>/dev/null || true
        spinner_stop
        log_sub_ok "findomain → $(count_lines "${subs_dir}/subs_findomain.txt") results"
    fi

    # ── PASSIVE: chaos ─────────────────────────────────────────────────────────
    if check_tool "chaos"; then
        if [[ -n "${PDCP_API_KEY:-}" ]]; then
            log_sub "chaos (PDCP) …"
            spinner_start "chaos querying ProjectDiscovery…"
            chaos \
                -d "${TARGET_DOMAIN}" \
                -silent \
                -o "${subs_dir}/subs_chaos.txt" \
                2>/dev/null || true
            spinner_stop
            log_sub_ok "chaos → $(count_lines "${subs_dir}/subs_chaos.txt") results"
        else
            log_warn "chaos installed but PDCP_API_KEY not exported — skipping."
        fi
    fi

    # ── PASSIVE: github-subdomains ─────────────────────────────────────────────
    if check_tool "github-subdomains"; then
        if [[ -n "${GITHUB_TOKEN:-}" ]]; then
            log_sub "github-subdomains …"
            spinner_start "github-subdomains scraping GitHub…"
            github-subdomains \
                -d "${TARGET_DOMAIN}" \
                -t "${GITHUB_TOKEN}" \
                -o "${subs_dir}/subs_github.txt" \
                2>/dev/null || true
            spinner_stop
            log_sub_ok "github-subdomains → $(count_lines "${subs_dir}/subs_github.txt") results"
        else
            log_warn "github-subdomains installed but GITHUB_TOKEN not exported — skipping."
        fi
    fi

    # ── PASSIVE: certificate transparency (crt.sh) ────────────────────────────
    log_sub "crt.sh certificate transparency …"
    spinner_start "querying crt.sh…"
    curl -s --max-time 30 \
        "https://crt.sh/?q=%25.${TARGET_DOMAIN}&output=json" 2>/dev/null \
        | python3 -c "
import sys, json, re
escaped = re.escape('${TARGET_DOMAIN}')
pattern = re.compile(r'[A-Za-z0-9._-]+\.' + escaped + r'$')
seen = set()
try:
    data = json.load(sys.stdin)
    for item in data:
        for name in item.get('name_value','').split('\n'):
            clean = name.strip().lstrip('*.')
            if pattern.fullmatch(clean) and clean not in seen:
                seen.add(clean)
                print(clean)
except Exception:
    pass
" > "${subs_dir}/subs_crtsh.txt" 2>/dev/null || true
    spinner_stop
    log_sub_ok "crt.sh → $(count_lines "${subs_dir}/subs_crtsh.txt") results"

    # ── ACTIVE: puredns bruteforce ─────────────────────────────────────────────
    if [[ -n "${WORDLIST_FILE}" ]] && check_tool "puredns"; then
        log_sub "puredns bruteforce …"

        # Download a public resolver list if not already present
        local resolvers_file="${active_dir}/resolvers.txt"
        if [[ ! -f "${resolvers_file}" ]]; then
            log_sub "Fetching public resolver list …"
            wget -q -O "${resolvers_file}" \
                "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
                2>/dev/null || touch "${resolvers_file}"
        fi

        spinner_start "puredns bruteforcing subdomains…"
        puredns bruteforce \
            "${WORDLIST_FILE}" \
            "${TARGET_DOMAIN}" \
            -r "${resolvers_file}" \
            --write "${active_dir}/subs_puredns.txt" \
            2>/dev/null || true
        spinner_stop
        log_sub_ok "puredns → $(count_lines "${active_dir}/subs_puredns.txt") resolved subdomains"
    elif [[ -z "${WORDLIST_FILE}" ]]; then
        log_skip "puredns — no wordlist supplied (-l). Skipping active bruteforce."
    fi

    # ── ACTIVE: dnsx wordlist brute ────────────────────────────────────────────
    if [[ -n "${WORDLIST_FILE}" ]] && check_tool "dnsx"; then
        log_sub "dnsx wordlist bruteforce …"
        spinner_start "dnsx resolving wordlist entries…"
        dnsx \
            -silent \
            -d "${TARGET_DOMAIN}" \
            -w "${WORDLIST_FILE}" \
            -o "${active_dir}/subs_dnsx.txt" \
            2>/dev/null || true
        spinner_stop
        log_sub_ok "dnsx → $(count_lines "${active_dir}/subs_dnsx.txt") results"
    fi

    # ── STEP 2: Merge & deduplicate (methodology §2 logic) ────────────────────
    log_info "Merging all sources → deduplicating (Step 2: anew / sort -u) …"

    # Collect every per-tool file into one pipe
    local all_raw_combined="${subs_dir}/subs_combined_raw.txt"
    cat \
        "${subs_dir}/subs_subfinder.txt" \
        "${subs_dir}/subs_assetfinder.txt" \
        "${subs_dir}/subs_amass.txt" \
        "${subs_dir}/subs_findomain.txt" \
        "${subs_dir}/subs_chaos.txt" \
        "${subs_dir}/subs_github.txt" \
        "${subs_dir}/subs_crtsh.txt" \
        "${active_dir}/subs_puredns.txt" \
        "${active_dir}/subs_dnsx.txt" \
        2>/dev/null | grep -v '^$' | sort > "${all_raw_combined}" || true

    if check_tool "anew"; then
        touch "${all_subs}"
        anew "${all_subs}" < "${all_raw_combined}" > /dev/null
    else
        log_warn "anew not found — falling back to sort -u"
        sort -u "${all_raw_combined}" > "${all_subs}"
    fi

    if [[ ! -s "${all_subs}" ]]; then
        log_warn "No subdomains discovered. Recon complete with zero results."
        notify_module "Passive + Active Recon" "⚠️ No subdomains found" \
            "Zero subdomains for ${TARGET_DOMAIN}" "$(elapsed_since "${t0}")"
        mark_done "recon"
        return 0
    fi

    META_COUNTS[subdomains]="$(count_lines "${all_subs}")"
    log_ok "Total unique subdomains: ${C_BOLD}${META_COUNTS[subdomains]}${C_RESET} → ${all_subs}"

    # ── httpx: alive host probing ─────────────────────────────────────────────
    check_required_tool "httpx"
    log_info "Probing live hosts with ${C_BOLD}httpx${C_RESET} (-threads 200) …"
    spinner_start "httpx probing alive hosts…"

    httpx \
        -l "${all_subs}" \
        -silent \
        -status-code \
        -content-length \
        -web-server \
        -title \
        -tech-detect \
        -follow-redirects \
        -threads 200 \
        -timeout 10 \
        -o "${urls_dir}/alive_hosts.txt" \
        2>/dev/null || true

    spinner_stop

    if [[ -s "${urls_dir}/alive_hosts.txt" ]]; then
        awk '{print $1}' "${urls_dir}/alive_hosts.txt" \
            | grep -E '^https?://' \
            > "${urls_dir}/alive_urls.txt" 2>/dev/null || true

        META_COUNTS[alive_hosts]="$(count_lines "${urls_dir}/alive_urls.txt")"
        log_ok "Alive hosts: ${C_BOLD}${META_COUNTS[alive_hosts]}${C_RESET}"
    else
        log_warn "httpx found no alive hosts."
    fi

    mark_done "recon"
    notify_module "Passive + Active Recon" "✅ Completed" \
        "Subdomains: ${META_COUNTS[subdomains]} | Alive: ${META_COUNTS[alive_hosts]}" \
        "$(elapsed_since "${t0}")"
    log_ok "Recon module finished.  [${C_DIM}$(elapsed_since "${t0}")${C_RESET}]"
}

# ══════════════════════════════════════════════════════════════════════════════
# §9 ─ MODULE: PORT SCANNING  (-P)
# ══════════════════════════════════════════════════════════════════════════════
#
# Pipeline:
#   all_subs.txt ─► naabu (-p - -rate 2000) ─► ports/naabu_all.txt
#                └─► nmap (-T4 -Pn) service scan ─► ports/nmap_scan.*
#                └─► httpx on non-std ports ─► urls/alive_urls.txt (appended)
#
# Output files:
#   ports/naabu_all.txt        All host:port pairs (all 65535 ports)
#   ports/naabu_filtered.txt   Non-standard web ports only
#   ports/nmap_scan.xml/.txt   nmap XML + greppable output
#   urls/alive_nonstandard.txt httpx results on non-standard ports
# ──────────────────────────────────────────────────────────────────────────────
module_portscan() {
    log_section "MODULE ─ Port Scanning  [-P]"

    local decision
    decision="$(check_resume "portscan" "Port Scan")"
    [[ "${decision}" == "skip" ]] && return 0

    local t0; t0="$(date +%s)"
    local subs_dir="${OUTPUT_BASE_DIR}/subdomains"
    local ports_dir="${OUTPUT_BASE_DIR}/ports"
    local urls_dir="${OUTPUT_BASE_DIR}/urls"
    local all_subs="${subs_dir}/all_subs.txt"

    if [[ ! -s "${all_subs}" ]]; then
        log_warn "No subdomain list at '${all_subs}'. Run -r (Recon) first."
        log_skip "Skipping Port Scan module."
        return 0
    fi

    local sub_count
    sub_count="$(count_lines "${all_subs}")"

    # ── naabu: full-port scan ─────────────────────────────────────────────────
    if check_tool "naabu"; then
        log_info "Running ${C_BOLD}naabu${C_RESET} (-p - -rate 2000) on ${sub_count} subdomains …"
        log_warn "Full port scan (-p -) is comprehensive — may take several minutes."
        spinner_start "naabu scanning all 65535 ports…"

        naabu \
            -list "${all_subs}" \
            -p - \
            -rate 2000 \
            -silent \
            -o "${ports_dir}/naabu_all.txt" \
            -exclude-ports 22,25,53,110,143,587,993,995 \
            2>/dev/null || true

        spinner_stop
        META_COUNTS[ports]="$(count_lines "${ports_dir}/naabu_all.txt")"
        log_ok "naabu discovered ${C_BOLD}${META_COUNTS[ports]}${C_RESET} open port(s)."

        # Filter to non-standard web ports
        grep -vE ':(80|443)$' "${ports_dir}/naabu_all.txt" \
            > "${ports_dir}/naabu_filtered.txt" 2>/dev/null || true

        local filtered_count
        filtered_count="$(count_lines "${ports_dir}/naabu_filtered.txt")"
        log_info "Non-standard web ports: ${C_BOLD}${filtered_count}${C_RESET}"

        # Feed non-standard ports into httpx
        if [[ -s "${ports_dir}/naabu_filtered.txt" ]] && check_tool "httpx"; then
            log_info "Probing non-standard ports with ${C_BOLD}httpx${C_RESET} …"
            spinner_start "httpx probing non-standard ports…"

            httpx \
                -l "${ports_dir}/naabu_filtered.txt" \
                -silent \
                -status-code \
                -title \
                -tech-detect \
                -follow-redirects \
                -threads 50 \
                -timeout 10 \
                -o "${urls_dir}/alive_nonstandard.txt" \
                2>/dev/null || true

            spinner_stop

            if [[ -s "${urls_dir}/alive_nonstandard.txt" ]]; then
                local ns_count
                ns_count="$(count_lines "${urls_dir}/alive_nonstandard.txt")"
                log_ok "Alive on non-standard ports: ${C_BOLD}${ns_count}${C_RESET}"

                if check_tool "anew"; then
                    awk '{print $1}' "${urls_dir}/alive_nonstandard.txt" \
                        | grep -E '^https?://' \
                        | anew "${urls_dir}/alive_urls.txt" > /dev/null
                else
                    awk '{print $1}' "${urls_dir}/alive_nonstandard.txt" \
                        | grep -E '^https?://' \
                        >> "${urls_dir}/alive_urls.txt"
                    sort -u -o "${urls_dir}/alive_urls.txt" "${urls_dir}/alive_urls.txt"
                fi
                META_COUNTS[alive_hosts]="$(count_lines "${urls_dir}/alive_urls.txt")"
            fi
        fi
    else
        log_warn "naabu not found — skipping full-port scan."
    fi

    # ── nmap: service / version detection ─────────────────────────────────────
    if check_tool "nmap"; then
        log_info "Running ${C_BOLD}nmap${C_RESET} (-T4 -Pn) on subdomain list …"
        spinner_start "nmap service fingerprinting…"

        nmap \
            -iL "${all_subs}" \
            -T4 \
            -Pn \
            -oA "${ports_dir}/nmap_scan" \
            2>/dev/null || true

        spinner_stop
        log_ok "nmap scan saved → ${ports_dir}/nmap_scan.{nmap,xml,gnmap}"
    else
        log_warn "nmap not found — skipping service scan."
    fi

    mark_done "portscan"
    notify_module "Port Scan" "✅ Completed" \
        "naabu ports: ${META_COUNTS[ports]} | Alive (total): ${META_COUNTS[alive_hosts]}" \
        "$(elapsed_since "${t0}")"
    log_ok "Port Scan module finished.  [${C_DIM}$(elapsed_since "${t0}")${C_RESET}]"
}

# ══════════════════════════════════════════════════════════════════════════════
# §10 ─ MODULE: SCREENSHOTS  (-s)
# ══════════════════════════════════════════════════════════════════════════════
module_screenshots() {
    log_section "MODULE ─ Visual Recon / Screenshots  [-s]"

    local decision
    decision="$(check_resume "screenshots" "Screenshots")"
    [[ "${decision}" == "skip" ]] && return 0

    local t0; t0="$(date +%s)"
    local alive_urls="${OUTPUT_BASE_DIR}/urls/alive_urls.txt"
    local shots_dir="${OUTPUT_BASE_DIR}/screenshots"

    if [[ ! -s "${alive_urls}" ]]; then
        log_warn "No alive URLs at '${alive_urls}'. Run -r (Recon) first."
        log_skip "Skipping Screenshots module."
        return 0
    fi

    check_required_tool "gowitness"

    local url_count
    url_count="$(count_lines "${alive_urls}")"
    log_info "Taking screenshots of ${C_BOLD}${url_count}${C_RESET} hosts …"

    spinner_start "gowitness capturing screenshots…"
    gowitness file \
        -f "${alive_urls}" \
        --screenshot-path "${shots_dir}" \
        --db-path "${shots_dir}/gowitness.sqlite3" \
        --timeout 10 \
        --threads 4 \
        2>/dev/null || true
    spinner_stop

    META_COUNTS[screenshots]="$(find "${shots_dir}" -name '*.png' 2>/dev/null | wc -l | tr -d ' ')"
    log_ok "Screenshots captured: ${C_BOLD}${META_COUNTS[screenshots]}${C_RESET}"
    log_info "HTML report: ${C_CYAN}gowitness report serve --db-path ${shots_dir}/gowitness.sqlite3${C_RESET}"

    mark_done "screenshots"
    notify_module "Screenshots" "✅ Completed" \
        "Captured ${META_COUNTS[screenshots]} screenshots across ${url_count} hosts" \
        "$(elapsed_since "${t0}")"
    log_ok "Screenshots module finished.  [${C_DIM}$(elapsed_since "${t0}")${C_RESET}]"
}

# ══════════════════════════════════════════════════════════════════════════════
# §11 ─ MODULE: URL DISCOVERY  (-u)
# ══════════════════════════════════════════════════════════════════════════════
#
# 10-SOURCE HARVEST (matching methodology §4):
#   waybackurls · gau (--threads 200) · gauplus (-t 200) · waymore
#   hakrawler · katana (-jc -kf all -d 5 -headless) · gospider
#   paramspider
#
# STEP 4 MERGE LOGIC:
#   cat *_raw.txt | anew | tee all_urls_raw.txt
#
# CATEGORY FILTERING (methodology §4 extract-interesting logic):
#   .js · .php · .asp(x) · .jsp(x) · JSON/XML/GraphQL · sensitive files
#   login flows · admin panels · upload endpoints · IDOR targets
#   cloud leaks · interesting endpoints · injection candidates (= params)
#   Wayback sensitive-extension grep pattern
#
# OUTPUT FILES:
#   urldiscovery/*_raw.txt           Per-tool raw output
#   urldiscovery/all_urls_raw.txt    Merged raw URL list
#   urldiscovery/all_urls_clean.txt  Deduplicated, noise-filtered
#   urldiscovery/urls_params.txt     URLs containing query parameters
#   urldiscovery/categories/*.txt    Category-filtered URL subsets
# ──────────────────────────────────────────────────────────────────────────────
module_url_discovery() {
    log_section "MODULE ─ Multi-Source URL Discovery  [-u]"

    local decision
    decision="$(check_resume "urldiscovery" "URL Discovery")"
    [[ "${decision}" == "skip" ]] && return 0

    local t0; t0="$(date +%s)"
    local urls_dir="${OUTPUT_BASE_DIR}/urls"
    local disc_dir="${OUTPUT_BASE_DIR}/urldiscovery"
    local cats_dir="${disc_dir}/categories"
    local alive_urls="${urls_dir}/alive_urls.txt"
    local alive_subs="${OUTPUT_BASE_DIR}/subdomains/all_subs.txt"
    local all_raw="${disc_dir}/all_urls_raw.txt"

    if [[ ! -s "${alive_urls}" ]]; then
        log_warn "No alive URLs at '${alive_urls}'. Run -r (Recon) first."
        log_skip "Skipping URL Discovery module."
        return 0
    fi

    touch "${all_raw}"

    # ── waybackurls ───────────────────────────────────────────────────────────
    if check_tool "waybackurls"; then
        log_sub "waybackurls …"
        spinner_start "waybackurls querying Wayback Machine…"
        cat "${alive_subs}" 2>/dev/null | waybackurls \
            > "${disc_dir}/wb_raw.txt" 2>/dev/null || true
        spinner_stop
        log_sub_ok "waybackurls → $(count_lines "${disc_dir}/wb_raw.txt") URLs"
    fi

    # ── gau (--threads 200) ───────────────────────────────────────────────────
    if check_tool "gau"; then
        log_sub "gau (--threads 200) …"
        spinner_start "gau harvesting historical URLs…"
        cat "${alive_subs}" 2>/dev/null | gau \
            --threads 200 \
            --blacklist ttf,woff,woff2,ico,jpg,jpeg,gif,png,svg,css \
            --subs \
            > "${disc_dir}/gau_raw.txt" 2>/dev/null || true
        spinner_stop
        log_sub_ok "gau → $(count_lines "${disc_dir}/gau_raw.txt") URLs"
    fi

    # ── gauplus (-t 200) ──────────────────────────────────────────────────────
    if check_tool "gauplus"; then
        log_sub "gauplus (-t 200 -random-agent) …"
        spinner_start "gauplus harvesting URLs…"
        gauplus \
            -t 200 \
            -random-agent \
            < "${alive_subs}" \
            > "${disc_dir}/gauplus_raw.txt" 2>/dev/null || true
        spinner_stop
        log_sub_ok "gauplus → $(count_lines "${disc_dir}/gauplus_raw.txt") URLs"
    fi

    # ── waymore ───────────────────────────────────────────────────────────────
    if check_tool "waymore"; then
        log_sub "waymore (-mode U -l 1000 -from 2021) …"
        spinner_start "waymore harvesting archived URLs…"
        waymore \
            -i "${alive_subs}" \
            -mode U \
            -l 1000 \
            -from 2021 \
            -oU "${disc_dir}/waymore_raw.txt" \
            2>/dev/null || true
        spinner_stop
        log_sub_ok "waymore → $(count_lines "${disc_dir}/waymore_raw.txt") URLs"
    fi

    # ── hakrawler (-subs -u -insecure) ────────────────────────────────────────
    if check_tool "hakrawler"; then
        log_sub "hakrawler (-subs -u -insecure) …"
        spinner_start "hakrawler crawling alive hosts…"
        cat "${alive_urls}" | hakrawler \
            -subs \
            -u \
            -insecure \
            > "${disc_dir}/hakrawler_raw.txt" 2>/dev/null || true
        spinner_stop
        log_sub_ok "hakrawler → $(count_lines "${disc_dir}/hakrawler_raw.txt") URLs"
    fi

    # ── katana (-jc -kf all -d 5 -headless -fx -aff -fs rdn) ─────────────────
    if check_tool "katana"; then
        log_sub "katana (-jc -kf all -d 5 -headless) …"
        spinner_start "katana crawling with JS execution…"
        katana \
            -u "${alive_urls}" \
            -jc \
            -kf all \
            -d 5 \
            -headless \
            -fx \
            -aff \
            -fs rdn \
            -f url \
            -silent \
            -o "${disc_dir}/katana_raw.txt" \
            2>/dev/null || true
        spinner_stop
        log_sub_ok "katana → $(count_lines "${disc_dir}/katana_raw.txt") URLs"
    fi

    # ── gospider (-t 20 -d 3 --js --sitemap --robots) ────────────────────────
    if check_tool "gospider"; then
        log_sub "gospider (-t 20 -d 3 --js --sitemap --robots) …"
        spinner_start "gospider crawling…"
        local gospider_out="${disc_dir}/gospider_raw_dir"
        mkdir -p "${gospider_out}"
        gospider \
            -S "${alive_urls}" \
            -t 20 \
            -d 3 \
            --js \
            --sitemap \
            --robots \
            -o "${gospider_out}" \
            2>/dev/null || true

        # Extract clean URLs from gospider's decorated output format
        find "${gospider_out}" -type f -exec cat {} \; 2>/dev/null \
            | sed -n 's/.*\(https\?:\/\/[^ ]*\).*/\1/p' \
            | grep -E '^https?://' \
            > "${disc_dir}/gospider_raw.txt" 2>/dev/null || true
        spinner_stop
        log_sub_ok "gospider → $(count_lines "${disc_dir}/gospider_raw.txt") URLs"
    fi

    # ── paramspider ───────────────────────────────────────────────────────────
    if check_tool "paramspider"; then
        log_sub "paramspider …"
        spinner_start "paramspider mining parameterised URLs…"
        paramspider \
            -d "${TARGET_DOMAIN}" \
            -o "${disc_dir}/paramspider_raw.txt" \
            2>/dev/null || true
        spinner_stop
        log_sub_ok "paramspider → $(count_lines "${disc_dir}/paramspider_raw.txt") URLs"
    fi

    # ── MERGE (methodology step 4: anew dedup) ────────────────────────────────
    log_info "Merging all URL sources (Step 4 anew merge) …"

    {
        for src in wb_raw gau_raw gauplus_raw waymore_raw \
                   hakrawler_raw katana_raw gospider_raw paramspider_raw; do
            [[ -f "${disc_dir}/${src}.txt" ]] && cat "${disc_dir}/${src}.txt"
        done
    } | grep -E '^https?://' | grep -v '^$' | sort > "${all_raw}" || true

    if [[ ! -s "${all_raw}" ]]; then
        log_warn "No URLs collected from any source."
        mark_done "urldiscovery"
        return 0
    fi

    # Deduplicate with anew or sort -u
    local all_clean="${disc_dir}/all_urls_clean.txt"
    if check_tool "anew"; then
        touch "${all_clean}"
        anew "${all_clean}" < "${all_raw}" > /dev/null
    else
        local noise="jpg|jpeg|gif|png|svg|ico|ttf|woff|woff2|eot|mp4|mp3|webp"
        sort -u "${all_raw}" \
            | grep -vE "\.(${noise})(\?.*)?$" \
            > "${all_clean}" || true
    fi

    META_COUNTS[total_urls]="$(count_lines "${all_clean}")"
    log_ok "Total unique URLs: ${C_BOLD}${META_COUNTS[total_urls]}${C_RESET} → ${all_clean}"

    # Extract parameterised URLs
    grep '?' "${all_clean}" > "${disc_dir}/urls_params.txt" 2>/dev/null || true
    log_ok "URLs with parameters: ${C_BOLD}$(count_lines "${disc_dir}/urls_params.txt")${C_RESET} → urls_params.txt"

    # ── CATEGORY FILTERING (methodology §4 extract-interesting) ───────────────
    log_info "Applying category filters …"

    # Helper: filter all_clean by pattern → output file; log count
    _cat_filter() {
        local label="$1" pattern="$2" outfile="${cats_dir}/$3"
        grep -iE "${pattern}" "${all_clean}" 2>/dev/null | sort -u > "${outfile}" || true
        log_sub_ok "${label}: ${C_BOLD}$(count_lines "${outfile}")${C_RESET} → categories/$3"
    }

    _cat_filter "JS files"             '\.js(\?|$)'                                                           "js_urls.txt"
    _cat_filter "PHP files"            '\.php(\?|$)'                                                          "php_files.txt"
    _cat_filter "ASP/ASPX files"       '\.aspx?(\?|$)'                                                        "asp_files.txt"
    _cat_filter "JSP/JSPX files"       '\.jspx?(\?|$)'                                                        "jsp_files.txt"
    _cat_filter "API (JSON/XML/GQL)"   '\.(json|xml|graphql|gql)(\?|$)'                                       "api_endpoints.txt"
    _cat_filter "Login/Auth flows"     'login|signin|auth|oauth|reset|password'                                "login_flows.txt"
    _cat_filter "Upload endpoints"     'upload|file|download|image|media'                                      "file_uploads.txt"
    _cat_filter "Admin panels"         'admin|dashboard|internal|manage|panel'                                  "admin_panels.txt"
    _cat_filter "Sensitive files"      '\.(env|bak|config|sql|log|pem|key|crt)(\?|$)'                          "sensitive_files.txt"
    _cat_filter "IDOR candidates"      '[0-9]{2,}'                                                             "idor_targets.txt"
    _cat_filter "Interesting endpoints" 'admin|login|signup|redirect|callback|auth|dev|test|beta|debug|staging|url=|r=|u=|goto=|return=|dest=' "interesting.txt"
    _cat_filter "Cloud/secret leaks"   'aws|s3|bucket|gcp|azure|vault|token|apikey|secret'                    "cloud_leaks.txt"
    _cat_filter "Injection params (=)" '='                                                                     "injection_params.txt"

    # Advanced Wayback sensitive-extension grep (full pattern from methodology)
    log_sub "Wayback sensitive extension grep …"
    grep -E \
        '\.xls|\.xlsx|\.csv|\.sql|\.db|\.bak|\.backup|\.old|\.tar\.gz|\.tgz|\.zip|\.7z|\.rar|\.pdf|\.doc|\.docx|\.pptx|\.txt|\.log|\.ini|\.conf|\.config|\.env|\.json|\.xml|\.yml|\.yaml|\.pem|\.key|\.crt|\.ssh|\.git|\.htaccess|\.htpasswd|\.php|\.swp|\.swo|\.dump|\.dmp|\.ds_store|\.npmrc|\.dockerignore|\.gitignore|\.gitconfig|\.eslintrc|\.prettierrc|\.stylelintrc|\.dockerfile|\.docker-compose|\.circleci|\.travis|\.vscode|\.idea' \
        "${all_clean}" 2>/dev/null | sort -u \
        > "${cats_dir}/wayback_sensitive.txt" || true
    log_sub_ok "Wayback sensitive: ${C_BOLD}$(count_lines "${cats_dir}/wayback_sensitive.txt")${C_RESET} matches"

    local cat_total
    cat_total="$(cat "${cats_dir}"/*.txt 2>/dev/null | sort -u | wc -l | tr -d ' ')"
    META_COUNTS[url_categories]="${cat_total}"

    # ── httpx: probe URL list for liveness ────────────────────────────────────
    if check_tool "httpx"; then
        log_info "Probing all URLs for liveness with ${C_BOLD}httpx${C_RESET} (-threads 200) …"
        spinner_start "httpx filtering live URLs…"
        cat "${all_clean}" | httpx \
            -status-code \
            -content-length \
            -silent \
            -threads 200 \
            -o "${disc_dir}/live_urls.txt" \
            2>/dev/null || true
        spinner_stop
        log_ok "Live URLs confirmed: ${C_BOLD}$(count_lines "${disc_dir}/live_urls.txt")${C_RESET} → live_urls.txt"
    fi

    mark_done "urldiscovery"
    notify_module "URL Discovery" "✅ Completed" \
        "Total URLs: ${META_COUNTS[total_urls]} | Categorised: ${META_COUNTS[url_categories]}" \
        "$(elapsed_since "${t0}")"
    log_ok "URL Discovery module finished.  [${C_DIM}$(elapsed_since "${t0}")${C_RESET}]"
}

# ══════════════════════════════════════════════════════════════════════════════
# §12 ─ MODULE: JS FILE ANALYSIS & SECRET SCANNING  (-j)
# ══════════════════════════════════════════════════════════════════════════════
#
# TOOLCHAIN (parallel where possible):
#   1. Collect JS URLs from URL discovery categories + urldiscovery sources
#   2. subjs  — recursive JS extraction from JS files
#   3. mantra — fast secret pattern scanning against JS URLs
#   4. jsecret — deeper JS secret scanning
#   5. jsleak  — xargs -P 20 parallel execution (from methodology)
#   6. Regex grep — api[_-]?key|token|secret|password patterns
#   7. trufflehog filesystem — verified secret detection on downloaded JS
#   8. lazyegg — JS URL/domain/IP extraction
#   9. nuclei fallback — if trufflehog unavailable
#
# OUTPUT FILES:
#   js/js_urls.txt                   Master JS URL list
#   js/subjs_found.txt               Additional JS URLs found by subjs
#   js/mantra_secrets.txt            mantra pattern hits
#   js/jsecret_output.txt            jsecret findings
#   js/jsleak_output.txt             jsleak parallel output
#   js/regex_secrets.txt             grep-based secret hits
#   js/lazyegg_output.txt            lazyegg JS analysis
#   js/files/                        Downloaded JS files for local scan
#   js/trufflehog_findings.json      trufflehog JSON output
#   js/nuclei_js_findings.txt        nuclei fallback output
# ──────────────────────────────────────────────────────────────────────────────
module_js_secrets() {
    log_section "MODULE ─ JS File Analysis & Secret Scanning  [-j]"

    local decision
    decision="$(check_resume "jssecrets" "JS & Secrets")"
    [[ "${decision}" == "skip" ]] && return 0

    local t0; t0="$(date +%s)"
    local js_dir="${OUTPUT_BASE_DIR}/js"
    local js_files_dir="${js_dir}/files"
    local js_urls="${js_dir}/js_urls.txt"
    local cats_dir="${OUTPUT_BASE_DIR}/urldiscovery/categories"
    local disc_clean="${OUTPUT_BASE_DIR}/urldiscovery/all_urls_clean.txt"
    local alive_urls="${OUTPUT_BASE_DIR}/urls/alive_urls.txt"

    mkdir -p "${js_files_dir}"

    # ── Collect JS URLs from all available sources ────────────────────────────
    log_info "Collecting JS URLs from all available URL sources …"
    touch "${js_urls}"

    {
        # Category-filtered JS list (preferred — already deduplicated)
        [[ -s "${cats_dir}/js_urls.txt" ]] && cat "${cats_dir}/js_urls.txt"
        # Fallback: grep from full clean URL list
        [[ -s "${disc_clean}" ]] && \
            grep -iE '\.js(\?.*)?$' "${disc_clean}" | grep -ivE '\.json'
        # Also grep alive_urls in case -u was not run
        [[ -s "${alive_urls}" ]] && \
            grep -iE '\.js(\?.*)?$' "${alive_urls}" | grep -ivE '\.json'
    } | grep -E '^https?://' | sort -u > "${js_urls}" 2>/dev/null || true

    META_COUNTS[js_files]="$(count_lines "${js_urls}")"
    log_ok "Unique JS URLs: ${C_BOLD}${META_COUNTS[js_files]}${C_RESET} → js/js_urls.txt"

    if [[ "${META_COUNTS[js_files]}" -eq 0 ]]; then
        log_warn "No JS URLs found. Run -r and/or -u modules first."
        mark_done "jssecrets"
        return 0
    fi

    # ── 1. subjs — recursive JS discovery ─────────────────────────────────────
    if check_tool "subjs"; then
        log_sub "subjs (recursive JS extraction) …"
        spinner_start "subjs finding more JS files…"
        cat "${js_urls}" | subjs \
            > "${js_dir}/subjs_found.txt" 2>/dev/null || true
        spinner_stop

        # Feed subjs results back into the master JS URL list
        if [[ -s "${js_dir}/subjs_found.txt" ]]; then
            if check_tool "anew"; then
                anew "${js_urls}" < "${js_dir}/subjs_found.txt" > /dev/null
            else
                cat "${js_dir}/subjs_found.txt" >> "${js_urls}"
                sort -u -o "${js_urls}" "${js_urls}"
            fi
            META_COUNTS[js_files]="$(count_lines "${js_urls}")"
        fi
        log_sub_ok "subjs → $(count_lines "${js_dir}/subjs_found.txt") additional JS URLs (total: ${META_COUNTS[js_files]})"
    fi

    # ── 2. mantra — fast pattern scanning ─────────────────────────────────────
    if check_tool "mantra"; then
        log_sub "mantra (JS secret pattern scanning) …"
        spinner_start "mantra scanning JS for secrets…"
        cat "${js_urls}" | mantra \
            > "${js_dir}/mantra_secrets.txt" 2>/dev/null || true
        spinner_stop
        log_sub_ok "mantra → $(count_lines "${js_dir}/mantra_secrets.txt") findings"
    fi

    # ── 3. jsecret ─────────────────────────────────────────────────────────────
    if check_tool "jsecret"; then
        log_sub "jsecret …"
        spinner_start "jsecret scanning…"
        cat "${js_urls}" | jsecret \
            > "${js_dir}/jsecret_output.txt" 2>/dev/null || true
        spinner_stop
        log_sub_ok "jsecret → $(count_lines "${js_dir}/jsecret_output.txt") findings"
    fi

    # ── 4. jsleak — xargs -P 20 parallel (exact methodology flags) ────────────
    if check_tool "jsleak"; then
        log_sub "jsleak (-P 20 parallel, -s -l -k -e) …"
        spinner_start "jsleak parallel scanning (20 workers)…"
        # Exact command from methodology: xargs -P 20 -I {} jsleak -s -l -k -e {}
        cat "${js_urls}" | xargs -P 20 -I {} \
            bash -c 'jsleak -s -l -k -e "$1" 2>/dev/null' _ {} \
            >> "${js_dir}/jsleak_output.txt" 2>/dev/null || true
        spinner_stop
        log_sub_ok "jsleak → $(count_lines "${js_dir}/jsleak_output.txt") findings"
    fi

    # ── 5. Regex secret grep (methodology pattern) ────────────────────────────
    log_sub "Regex secret grep (api_key|token|secret|password) …"
    spinner_start "curl+grep fetching and scanning JS content…"
    cat "${js_urls}" | xargs -P 10 -I {} \
        bash -c '
            content=$(curl -sk --max-time 15 "$1" 2>/dev/null)
            matches=$(echo "$content" | grep -oE "(api[_-]?key|apikey|token|secret|password|auth_token|access_token|bearer|private_key)[\"'"'"'\s:=]+[A-Za-z0-9+/=_\-\.]{8,}" 2>/dev/null)
            [[ -n "$matches" ]] && echo "$matches" | sed "s|^|[$1] |"
        ' _ {} \
        > "${js_dir}/regex_secrets.txt" 2>/dev/null || true
    spinner_stop
    log_sub_ok "Regex grep → $(count_lines "${js_dir}/regex_secrets.txt") potential secret lines"

    # ── 6. lazyegg ────────────────────────────────────────────────────────────
    if check_tool "lazyegg" && command -v python3 &>/dev/null; then
        log_sub "lazyegg (parallel -P 10) …"
        spinner_start "lazyegg extracting JS metadata…"
        cat "${js_urls}" | xargs -P 10 -I {} \
            bash -c 'python3 lazyegg.py "$1" --js_urls --domains --ips 2>/dev/null' _ {} \
            >> "${js_dir}/lazyegg_output.txt" 2>/dev/null || true
        spinner_stop
        log_sub_ok "lazyegg → $(count_lines "${js_dir}/lazyegg_output.txt") lines"
    fi

    # ── 7. Download JS files for local analysis ────────────────────────────────
    log_sub "Downloading JS files for trufflehog local scan …"
    spinner_start "wget fetching JS files…"
    local dl_count=0
    while IFS= read -r js_url; do
        [[ -z "${js_url}" ]] && continue
        local safe_fn
        safe_fn="$(echo "${js_url}" | md5sum | awk '{print $1}').js"
        wget -q --timeout=10 --tries=2 \
            -O "${js_files_dir}/${safe_fn}" \
            "${js_url}" 2>/dev/null || true
        (( dl_count++ )) || true
    done < "${js_urls}"
    spinner_stop
    log_sub_ok "Downloaded ${dl_count} JS files → js/files/"

    # ── 8. trufflehog filesystem scan (primary) ────────────────────────────────
    if check_tool "trufflehog"; then
        log_sub "trufflehog filesystem scan …"
        spinner_start "trufflehog scanning for verified secrets…"
        trufflehog filesystem \
            "${js_files_dir}" \
            --json \
            --no-verification \
            2>/dev/null \
            > "${js_dir}/trufflehog_findings.json" || true
        spinner_stop

        META_COUNTS[secrets]="$(count_lines "${js_dir}/trufflehog_findings.json")"
        if [[ "${META_COUNTS[secrets]}" -gt 0 ]]; then
            log_ok "${C_BRED}⚠  trufflehog: ${META_COUNTS[secrets]} potential secret(s) detected!${C_RESET}"
            log_info "Review: ${js_dir}/trufflehog_findings.json"
        else
            log_sub_ok "trufflehog: No verified secrets detected."
        fi

    # ── 9. nuclei fallback ─────────────────────────────────────────────────────
    elif check_tool "nuclei"; then
        log_warn "trufflehog not found — falling back to ${C_BOLD}nuclei exposures/tokens${C_RESET}"
        spinner_start "nuclei scanning JS for token exposures…"
        nuclei \
            -l "${js_urls}" \
            -tags "token,exposure,api-key,secret" \
            -severity "low,medium,high,critical" \
            -silent \
            -o "${js_dir}/nuclei_js_findings.txt" \
            2>/dev/null || true
        spinner_stop

        META_COUNTS[secrets]="$(count_lines "${js_dir}/nuclei_js_findings.txt")"
        if [[ "${META_COUNTS[secrets]}" -gt 0 ]]; then
            log_ok "${C_BRED}⚠  nuclei JS: ${META_COUNTS[secrets]} exposure(s) found!${C_RESET}"
        fi
    else
        log_warn "Neither trufflehog nor nuclei found. Cannot run deep secret scanning."
    fi

    # Tally total findings across all tools
    local total_findings
    total_findings=$(( \
        $(count_lines "${js_dir}/mantra_secrets.txt") + \
        $(count_lines "${js_dir}/jsleak_output.txt") + \
        $(count_lines "${js_dir}/regex_secrets.txt") + \
        ${META_COUNTS[secrets]} \
    ))
    META_COUNTS[secrets]="${total_findings}"

    mark_done "jssecrets"
    notify_module "JS & Secrets" "✅ Completed" \
        "JS files: ${META_COUNTS[js_files]} | Total findings: ${total_findings}" \
        "$(elapsed_since "${t0}")"
    log_ok "JS & Secrets module finished.  [${C_DIM}$(elapsed_since "${t0}")${C_RESET}]"
}

# ══════════════════════════════════════════════════════════════════════════════
# §13 ─ MODULE: HIDDEN PARAMETER DISCOVERY  (-p)
# ══════════════════════════════════════════════════════════════════════════════
#
# APPROACH:
#   1. arjun (GET + POST) on curated target list (methodology §param-discovery)
#   2. qsreplace FUZZ — build injection-ready URL list from all param URLs
#   3. param key extraction: sed 's/=[^&]*/=/g'
#
# OUTPUT FILES:
#   params/arjun_targets.txt      URL list fed to arjun
#   params/arjun_findings.json    arjun JSON results
#   params/params_summary.txt     Human-readable arjun summary
#   params/params_fuzz.txt        qsreplace FUZZ-ready URLs
#   params/param_keys.txt         Parameter key names (no values)
# ──────────────────────────────────────────────────────────────────────────────
readonly MAX_ARJUN_TARGETS=100

module_hidden_params() {
    log_section "MODULE ─ Hidden Parameter Discovery  [-p]"

    local decision
    decision="$(check_resume "hiddenparams" "Hidden Params")"
    [[ "${decision}" == "skip" ]] && return 0

    local t0; t0="$(date +%s)"
    local params_dir="${OUTPUT_BASE_DIR}/params"
    local urls_dir="${OUTPUT_BASE_DIR}/urls"
    local disc_dir="${OUTPUT_BASE_DIR}/urldiscovery"
    local cats_dir="${disc_dir}/categories"
    local arjun_targets="${params_dir}/arjun_targets.txt"

    touch "${arjun_targets}"

    # ── Build arjun target list ────────────────────────────────────────────────
    # Priority 1: parameterised URLs from URL discovery
    if [[ -s "${disc_dir}/urls_params.txt" ]]; then
        head -n "${MAX_ARJUN_TARGETS}" "${disc_dir}/urls_params.txt" \
            >> "${arjun_targets}"
    fi
    # Priority 2: injection candidates from category filter
    if [[ -s "${cats_dir}/injection_params.txt" ]]; then
        head -n "${MAX_ARJUN_TARGETS}" "${cats_dir}/injection_params.txt" \
            >> "${arjun_targets}"
    fi
    # Priority 3: fill remaining slots with plain alive URLs
    local remaining=$(( MAX_ARJUN_TARGETS - $(count_lines "${arjun_targets}") ))
    if [[ "${remaining}" -gt 0 && -s "${urls_dir}/alive_urls.txt" ]]; then
        head -n "${remaining}" "${urls_dir}/alive_urls.txt" >> "${arjun_targets}"
    fi

    sort -u -o "${arjun_targets}" "${arjun_targets}"
    local target_count
    target_count="$(count_lines "${arjun_targets}")"

    if [[ "${target_count}" -eq 0 ]]; then
        log_warn "No URLs available for parameter discovery. Run -r and/or -u first."
        mark_done "hiddenparams"
        return 0
    fi

    # ── arjun ─────────────────────────────────────────────────────────────────
    if check_tool "arjun"; then
        log_info "Running ${C_BOLD}arjun${C_RESET} (GET + POST) on ${target_count} URLs …"
        spinner_start "arjun discovering hidden parameters…"
        arjun \
            -i "${arjun_targets}" \
            -oJ "${params_dir}/arjun_findings.json" \
            -m GET POST \
            -t 10 \
            --passive \
            2>/dev/null || true
        spinner_stop

        # Python summary parser (identical to original v3 logic)
        local findings_count=0
        local arjun_json="${params_dir}/arjun_findings.json"
        local arjun_summary="${params_dir}/params_summary.txt"

        if [[ -s "${arjun_json}" ]] && command -v python3 &>/dev/null; then
            findings_count="$(ARJUN_JSON="${arjun_json}" python3 - <<'PYEOF'
import json, os, sys
try:
    path = os.environ["ARJUN_JSON"]
    with open(path) as fh:
        data = json.load(fh)
    total = sum(len(v) for v in data.values() if isinstance(v, list))
    print(total)
except Exception:
    print(0)
PYEOF
            )" 2>/dev/null || findings_count=0

            ARJUN_JSON="${arjun_json}" python3 - > "${arjun_summary}" 2>/dev/null || true <<'PYEOF'
import json, os
try:
    path = os.environ["ARJUN_JSON"]
    with open(path) as fh:
        data = json.load(fh)
    for url, params in data.items():
        if params:
            print(f"[URL] {url}")
            print(f"  Params: {', '.join(params)}")
            print()
except Exception as e:
    print(f"Parse error: {e}")
PYEOF
        fi

        META_COUNTS[hidden_params]="${findings_count}"
        if [[ "${findings_count}" -gt 0 ]]; then
            log_ok "${C_BRED}⚠  arjun: ${findings_count} hidden parameter(s) discovered!${C_RESET}"
            log_info "Summary: ${params_dir}/params_summary.txt"
        else
            log_info "arjun: No hidden parameters found."
        fi
    else
        log_warn "arjun not found — skipping hidden param brute-force."
    fi

    # ── qsreplace FUZZ-ready list (methodology §param) ────────────────────────
    if check_tool "qsreplace"; then
        log_sub "qsreplace FUZZ — building injection-ready URL list …"
        if [[ -s "${disc_dir}/urls_params.txt" ]]; then
            if check_tool "anew"; then
                cat "${disc_dir}/urls_params.txt" \
                    | qsreplace "FUZZ" \
                    | anew "${params_dir}/params_fuzz.txt" > /dev/null 2>/dev/null || true
            else
                cat "${disc_dir}/urls_params.txt" \
                    | qsreplace "FUZZ" \
                    | sort -u > "${params_dir}/params_fuzz.txt" 2>/dev/null || true
            fi
            log_sub_ok "FUZZ-ready URLs: ${C_BOLD}$(count_lines "${params_dir}/params_fuzz.txt")${C_RESET} → params/params_fuzz.txt"
        fi
    fi

    # ── Parameter key extraction (sed pattern from methodology) ───────────────
    if [[ -s "${disc_dir}/urls_params.txt" ]]; then
        log_sub "Extracting parameter key names …"
        sed 's/=[^&]*/=/g' "${disc_dir}/urls_params.txt" \
            | sort -u > "${params_dir}/param_keys.txt" 2>/dev/null || true
        log_sub_ok "Unique param keys: ${C_BOLD}$(count_lines "${params_dir}/param_keys.txt")${C_RESET} → params/param_keys.txt"
    fi

    mark_done "hiddenparams"
    notify_module "Hidden Params" "✅ Completed" \
        "Scanned: ${target_count} URLs | Hidden params: ${META_COUNTS[hidden_params]}" \
        "$(elapsed_since "${t0}")"
    log_ok "Hidden Params module finished.  [${C_DIM}$(elapsed_since "${t0}")${C_RESET}]"
}

# ══════════════════════════════════════════════════════════════════════════════
# §14 ─ MODULE: ACTIVE FUZZING  (-f)
# ══════════════════════════════════════════════════════════════════════════════
#
# THREE-STAGE FUZZING PIPELINE:
#
#   Stage A — Directory Fuzzing (ffuf)
#     • Per-host directory brute-force with extension expansion
#     • Flags: -t 200 -ac -mc 200,204,301,302,307,401,403,405 -fs 0
#     • Extensions: php,html,json,js,log,txt,bak,old,zip,tar,gz,asp,aspx,config,env,xml
#
#   Stage B — VHost Fuzzing (ffuf)
#     • Host-header injection: ffuf -H "Host: FUZZ.target.com"
#     • IP-based probe (if resolvable): ffuf -u http://<ip> -H "Host: FUZZ.target.com"
#     • Subdomain prefix patterns: FUZZ.target.com, FUZZ-target.com
#
#   Stage C — Deep Directory Scanning (feroxbuster)
#     • Recursive depth-3 scan on top alive hosts
#     • Flags: -t 300 -k -d 3 -e (auto-expand extensions)
#
# OUTPUT FILES:
#   fuzzing/<host>_dir.json             ffuf directory results (per host)
#   fuzzing/vhost/vhost_hostinject.json ffuf vhost header-injection results
#   fuzzing/vhost/sub_prefix_*.json     Subdomain prefix pattern results
#   fuzzing/<host>_ferox.txt            feroxbuster output (per host)
# ──────────────────────────────────────────────────────────────────────────────

# Cap: fuzz only the first N alive hosts to avoid runaway runtimes
readonly MAX_FUZZ_HOSTS=20

module_fuzzing() {
    log_section "MODULE ─ Active Directory, VHost & Deep Fuzzing  [-f]"

    local decision
    decision="$(check_resume "fuzzing" "Fuzzing")"
    [[ "${decision}" == "skip" ]] && return 0

    local t0; t0="$(date +%s)"
    local fuzzing_dir="${OUTPUT_BASE_DIR}/fuzzing"
    local vhost_dir="${fuzzing_dir}/vhost"
    local alive_urls="${OUTPUT_BASE_DIR}/urls/alive_urls.txt"
    local all_subs="${OUTPUT_BASE_DIR}/subdomains/all_subs.txt"

    validate_file "${WORDLIST_FILE}" "fuzzing wordlist"
    check_required_tool "ffuf"

    if [[ ! -s "${alive_urls}" ]]; then
        log_warn "No alive URLs. Run -r (Recon) first."
        log_skip "Skipping Fuzzing module."
        return 0
    fi

    local url_count wl_count
    url_count="$(count_lines "${alive_urls}")"
    wl_count="$(count_lines "${WORDLIST_FILE}")"
    local fuzz_count=$(( url_count < MAX_FUZZ_HOSTS ? url_count : MAX_FUZZ_HOSTS ))

    log_info "Fuzzing ${C_BOLD}${fuzz_count}${C_RESET} hosts (cap: ${MAX_FUZZ_HOSTS}) | Wordlist: ${C_BOLD}${wl_count}${C_RESET} entries"

    local total_hits=0
    local ext="php,html,json,js,log,txt,bak,old,zip,tar,gz,asp,aspx,config,env,xml,jsp,cfm,cgi"

    # ── STAGE A: ffuf directory fuzzing ───────────────────────────────────────
    log_info "${C_BOLD}Stage A${C_RESET} — ffuf directory fuzzing (-t 200) …"

    head -n "${MAX_FUZZ_HOSTS}" "${alive_urls}" | while IFS= read -r target_url; do
        [[ -z "${target_url}" ]] && continue

        local safe_name
        safe_name="$(echo "${target_url}" \
            | sed 's|https\?://||g' | tr '/.:@' '____' | tr -cd '[:alnum:]_-')"
        local out_file="${fuzzing_dir}/${safe_name}_dir.json"

        log_sub "ffuf dir: ${C_CYAN}${target_url}${C_RESET}"

        ffuf \
            -u "${target_url}/FUZZ" \
            -w "${WORDLIST_FILE}" \
            -t 200 \
            -ac \
            -mc 200,204,301,302,307,401,403,405 \
            -fs 0 \
            -e ".${ext//,/.,.}" \
            -o "${out_file}" \
            -of json \
            -timeout 10 \
            -silent \
            2>/dev/null || true

        if command -v jq &>/dev/null && [[ -f "${out_file}" ]]; then
            local hits
            hits="$(jq '.results | length' "${out_file}" 2>/dev/null || echo 0)"
            if [[ "${hits}" -gt 0 ]]; then
                log_sub_ok "${C_BOLD}${hits}${C_RESET} paths found → ${safe_name}_dir.json"
                (( total_hits += hits )) || true
            fi
        fi
    done

    # ── STAGE B: VHost fuzzing ─────────────────────────────────────────────────
    log_info "${C_BOLD}Stage B${C_RESET} — ffuf vhost fuzzing (Host header injection) …"

    # B1: Host-header injection on the root domain
    log_sub "ffuf vhost (Host: FUZZ.${TARGET_DOMAIN}) …"
    ffuf \
        -u "https://${TARGET_DOMAIN}" \
        -w "${WORDLIST_FILE}" \
        -H "Host: FUZZ.${TARGET_DOMAIN}" \
        -t 200 \
        -mc 200,301,302,307,401,403 \
        -fs 0 \
        -ac \
        -o "${vhost_dir}/vhost_hostinject.json" \
        -of json \
        -timeout 10 \
        -silent \
        2>/dev/null || true
    log_sub_ok "vhost header-inject → $(
        command -v jq &>/dev/null \
        && jq '.results | length' "${vhost_dir}/vhost_hostinject.json" 2>/dev/null \
        || echo '?') hits"

    # B2: Subdomain prefix patterns from methodology
    local -a vhost_patterns=(
        "https://FUZZ.${TARGET_DOMAIN}"
        "https://FUZZ-${TARGET_DOMAIN}"
    )

    for pattern in "${vhost_patterns[@]}"; do
        local safe_pat
        safe_pat="$(echo "${pattern}" | tr -dc '[:alnum:]_-' | cut -c1-60)"
        log_sub "ffuf pattern: ${pattern} …"
        ffuf \
            -u "${pattern}" \
            -w "${WORDLIST_FILE}" \
            -t 200 \
            -mc 200,301,302,307,401,403 \
            -fs 0 \
            -ac \
            -o "${vhost_dir}/sub_prefix_${safe_pat}.json" \
            -of json \
            -timeout 10 \
            -silent \
            2>/dev/null || true
    done

    # B3: 403 bypass with header fuzzing (methodology advanced pattern)
    if [[ -f "${WORDLIST_FILE}" ]]; then
        log_sub "ffuf 403 bypass header fuzzing on first 5 hosts …"
        head -n 5 "${alive_urls}" | while IFS= read -r target_url; do
            [[ -z "${target_url}" ]] && continue
            local safe_name
            safe_name="$(echo "${target_url}" | sed 's|https\?://||g' | tr '/.:@' '____' | tr -cd '[:alnum:]_-')"
            ffuf \
                -u "${target_url}/FUZZ" \
                -w "${WORDLIST_FILE}" \
                -H "X-Forwarded-For: 127.0.0.1" \
                -H "X-Original-URL: /FUZZ" \
                -t 200 \
                -mc 200,301,302 \
                -ac \
                -o "${vhost_dir}/${safe_name}_403bypass.json" \
                -of json \
                -timeout 10 \
                -silent \
                2>/dev/null || true
        done
    fi

    # ── STAGE C: feroxbuster deep recursive scan ───────────────────────────────
    if check_tool "feroxbuster"; then
        log_info "${C_BOLD}Stage C${C_RESET} — feroxbuster (-t 300 -d 3 -k -e) on top 10 hosts …"

        head -n 10 "${alive_urls}" | while IFS= read -r target_url; do
            [[ -z "${target_url}" ]] && continue
            local safe_name
            safe_name="$(echo "${target_url}" | sed 's|https\?://||g' | tr '/.:@' '____' | tr -cd '[:alnum:]_-')"
            log_sub "feroxbuster: ${C_CYAN}${target_url}${C_RESET} …"

            feroxbuster \
                -u "${target_url}" \
                -w "${WORDLIST_FILE}" \
                -t 300 \
                -k \
                -d 3 \
                -e \
                -x "${ext}" \
                -o "${fuzzing_dir}/${safe_name}_ferox.txt" \
                --silent \
                --no-recursion-limit \
                2>/dev/null || true

            if [[ -f "${fuzzing_dir}/${safe_name}_ferox.txt" ]]; then
                local ferox_hits
                ferox_hits="$(grep -c '200' "${fuzzing_dir}/${safe_name}_ferox.txt" 2>/dev/null || echo 0)"
                [[ "${ferox_hits}" -gt 0 ]] && \
                    log_sub_ok "feroxbuster: ${C_BOLD}${ferox_hits}${C_RESET} 200-status paths"
                (( total_hits += ferox_hits )) || true
            fi
        done
    else
        log_warn "feroxbuster not found — skipping Stage C deep scan."
    fi

    META_COUNTS[fuzz_hits]="${total_hits}"
    log_ok "Total interesting paths discovered: ${C_BOLD}${total_hits}${C_RESET}"

    mark_done "fuzzing"
    notify_module "Fuzzing" "✅ Completed" \
        "Hosts: ${fuzz_count} | Total hits: ${total_hits}" \
        "$(elapsed_since "${t0}")"
    log_ok "Fuzzing module finished.  [${C_DIM}$(elapsed_since "${t0}")${C_RESET}]"
}

# ══════════════════════════════════════════════════════════════════════════════
# §15 ─ MODULE: VULNERABILITY SCANNING  (-v)
# ══════════════════════════════════════════════════════════════════════════════
#
# Runs nuclei against alive_urls.txt with curated template tags.
# Also feeds category-filtered URLs (admin panels, login flows, sensitive
# files) as supplementary targets for higher-signal scanning.
#
# Output files:
#   vulns/nuclei_findings.txt     Human-readable nuclei output
#   vulns/nuclei_findings.json    JSONL machine-readable output
#   vulns/nuclei_exposures.txt    Exposure-template-specific output
# ──────────────────────────────────────────────────────────────────────────────
module_vuln_scan() {
    log_section "MODULE ─ Vulnerability & Takeover Scanning  [-v]"

    local decision
    decision="$(check_resume "vulnscan" "Vuln Scan")"
    [[ "${decision}" == "skip" ]] && return 0

    local t0; t0="$(date +%s)"
    local vulns_dir="${OUTPUT_BASE_DIR}/vulns"
    local alive_urls="${OUTPUT_BASE_DIR}/urls/alive_urls.txt"
    local cats_dir="${OUTPUT_BASE_DIR}/urldiscovery/categories"

    if [[ ! -s "${alive_urls}" ]]; then
        log_warn "No alive URLs at '${alive_urls}'. Run -r (Recon) first."
        log_skip "Skipping Vuln Scan module."
        return 0
    fi

    check_required_tool "nuclei"

    # Build an enriched target list by appending category-filtered URLs
    local vuln_targets="${vulns_dir}/vuln_targets.txt"
    cp "${alive_urls}" "${vuln_targets}" 2>/dev/null || true
    for extra in admin_panels.txt login_flows.txt sensitive_files.txt interesting.txt; do
        [[ -f "${cats_dir}/${extra}" ]] && \
            cat "${cats_dir}/${extra}" >> "${vuln_targets}"
    done
    if check_tool "anew"; then
        sort "${vuln_targets}" | anew "${vuln_targets}" > /dev/null 2>&1 || true
    else
        sort -u -o "${vuln_targets}" "${vuln_targets}"
    fi

    local url_count
    url_count="$(count_lines "${vuln_targets}")"
    log_info "Running ${C_BOLD}nuclei${C_RESET} against ${url_count} targets …"

    # Update templates (non-fatal)
    log_info "Refreshing nuclei templates …"
    spinner_start "nuclei updating templates…"
    nuclei -update-templates -silent 2>/dev/null || true
    spinner_stop
    log_ok "Templates up to date."

    local findings_txt="${vulns_dir}/nuclei_findings.txt"
    local findings_json="${vulns_dir}/nuclei_findings.json"
    local exposures_txt="${vulns_dir}/nuclei_exposures.txt"
    local tmpl_root="${NUCLEI_TEMPLATES:-${HOME}/nuclei-templates}"

    # Scan 1: full tag-based scan
    log_sub "nuclei (takeover|exposure|cve|default-login|misconfig|panel) …"
    spinner_start "nuclei scanning for vulnerabilities…"
    nuclei \
        -l "${vuln_targets}" \
        -tags "takeover,exposure,cve,default-login,misconfig,panel" \
        -severity "medium,high,critical" \
        -c 25 \
        -rl 150 \
        -o "${findings_txt}" \
        -jsonl "${findings_json}" \
        -silent \
        -stats \
        2>/dev/null || true
    spinner_stop

    # Scan 2: exposure templates specifically (methodology §full-vuln-scan)
    if [[ -d "${tmpl_root}/http/exposures" ]]; then
        log_sub "nuclei exposures templates …"
        spinner_start "nuclei scanning http/exposures…"
        nuclei \
            -l "${vuln_targets}" \
            -t "${tmpl_root}/http/exposures" \
            -silent \
            -o "${exposures_txt}" \
            2>/dev/null || true
        spinner_stop
        log_sub_ok "Exposures scan → $(count_lines "${exposures_txt}") findings"
    fi

    META_COUNTS[vuln_findings]="$(count_lines "${findings_txt}")"

    if [[ "${META_COUNTS[vuln_findings]}" -gt 0 ]]; then
        log_ok "${C_BRED}⚠  nuclei: ${META_COUNTS[vuln_findings]} potential vulnerabilit(ies) found!${C_RESET}"
        echo ""
        log_info "=== Top findings (first 20) ==="
        head -n 20 "${findings_txt}" | while IFS= read -r line; do
            echo -e "  ${C_YELLOW}${line}${C_RESET}"
        done
        echo ""
    else
        log_info "Nuclei: No medium+ findings for selected template tags."
    fi

    mark_done "vulnscan"
    notify_module "Vuln Scan" "✅ Completed" \
        "Targets: ${url_count} | Findings: ${META_COUNTS[vuln_findings]}" \
        "$(elapsed_since "${t0}")"
    log_ok "Vuln Scan module finished.  [${C_DIM}$(elapsed_since "${t0}")${C_RESET}]"
}

# ══════════════════════════════════════════════════════════════════════════════
# §16 ─ RUN METADATA JSON REPORT
# ══════════════════════════════════════════════════════════════════════════════
write_run_metadata() {
    local end_ts; end_ts="$(date +%s)"
    local end_human; end_human="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    local total_elapsed; total_elapsed="$(elapsed_since "${RUN_START_TS}")"
    local metadata_file="${OUTPUT_BASE_DIR}/run_metadata.json"

    local modules_run=()
    [[ "${RUN_RECON}" -eq 1 ]]        && modules_run+=("\"recon\"")
    [[ "${RUN_PORTSCAN}" -eq 1 ]]     && modules_run+=("\"portscan\"")
    [[ "${RUN_SCREENSHOTS}" -eq 1 ]]  && modules_run+=("\"screenshots\"")
    [[ "${RUN_URLDISCOVERY}" -eq 1 ]] && modules_run+=("\"url_discovery\"")
    [[ "${RUN_JSSECRETS}" -eq 1 ]]    && modules_run+=("\"js_secrets\"")
    [[ "${RUN_HIDDENPARAMS}" -eq 1 ]] && modules_run+=("\"hidden_params\"")
    [[ "${RUN_FUZZING}" -eq 1 ]]      && modules_run+=("\"fuzzing\"")
    [[ "${RUN_VULN}" -eq 1 ]]         && modules_run+=("\"vuln_scan\"")
    local modules_json
    modules_json="$(IFS=','; echo "[${modules_run[*]}]")"

    cat > "${metadata_file}" <<JSON
{
  "meta": {
    "script":        "${SCRIPT_NAME}",
    "version":       "${SCRIPT_VERSION}",
    "author":        "${SCRIPT_AUTHOR}"
  },
  "run": {
    "target":        "${TARGET_DOMAIN}",
    "start_utc":     "${RUN_START_HUMAN}",
    "end_utc":       "${end_human}",
    "elapsed":       "${total_elapsed}",
    "modules_run":   ${modules_json},
    "output_dir":    "${OUTPUT_BASE_DIR}"
  },
  "counts": {
    "unique_subdomains":    ${META_COUNTS[subdomains]},
    "open_ports":           ${META_COUNTS[ports]},
    "alive_hosts":          ${META_COUNTS[alive_hosts]},
    "screenshots":          ${META_COUNTS[screenshots]},
    "total_urls":           ${META_COUNTS[total_urls]},
    "categorised_urls":     ${META_COUNTS[url_categories]},
    "js_files":             ${META_COUNTS[js_files]},
    "secrets_found":        ${META_COUNTS[secrets]},
    "hidden_params":        ${META_COUNTS[hidden_params]},
    "vuln_findings":        ${META_COUNTS[vuln_findings]},
    "fuzz_hits":            ${META_COUNTS[fuzz_hits]}
  }
}
JSON

    log_ok "Run metadata written: ${C_BOLD}${metadata_file}${C_RESET}"
}

# ══════════════════════════════════════════════════════════════════════════════
# §17 ─ FINAL SUMMARY REPORT
# ══════════════════════════════════════════════════════════════════════════════
print_summary() {
    local total_elapsed
    total_elapsed="$(elapsed_since "${RUN_START_TS}")"

    echo ""
    log_section "Reconnaissance Complete — Final Summary"

    printf "  ${C_BOLD}%-32s${C_RESET} ${C_BCYAN}%s${C_RESET}\n" \
        "Target:"         "${TARGET_DOMAIN}"
    printf "  ${C_BOLD}%-32s${C_RESET} ${C_BCYAN}%s${C_RESET}\n" \
        "Output Directory:" "${OUTPUT_BASE_DIR}/"
    printf "  ${C_BOLD}%-32s${C_RESET} ${C_BCYAN}%s${C_RESET}\n" \
        "Total Elapsed:"   "${total_elapsed}"
    echo ""

    local -A label_map=(
        [subdomains]="Unique Subdomains"
        [ports]="Open Ports (naabu)"
        [alive_hosts]="Alive HTTP Hosts"
        [screenshots]="Screenshots Taken"
        [total_urls]="Total URLs Harvested"
        [url_categories]="Categorised URL Entries"
        [js_files]="JS Files Found"
        [secrets]="Secret Findings (all tools)"
        [hidden_params]="Hidden Parameters"
        [fuzz_hits]="Fuzzing Hits"
        [vuln_findings]="Vuln Findings (nuclei)"
    )

    local ordered_keys=(
        subdomains ports alive_hosts screenshots
        total_urls url_categories js_files
        secrets hidden_params fuzz_hits vuln_findings
    )

    for key in "${ordered_keys[@]}"; do
        local val="${META_COUNTS[$key]}"
        local label="${label_map[$key]}"
        local colour="${C_CYAN}"

        if [[ "${key}" == "secrets" || "${key}" == "hidden_params" || \
              "${key}" == "vuln_findings" ]] && [[ "${val}" -gt 0 ]]; then
            colour="${C_BRED}"
        elif [[ "${val}" -gt 0 ]]; then
            colour="${C_BGREEN}"
        fi

        printf "  ${C_BOLD}%-32s${C_RESET} ${colour}%s${C_RESET}\n" \
            "${label}:" "${val}"
    done

    echo ""
    echo -e "${LOG_SEP}"
    log_ok "All selected modules completed. Stay legal, stay ethical. Happy hunting! 🎯"
    echo ""

    notify_module "Pipeline Complete" "✅ All modules finished" \
        "Subdomains: ${META_COUNTS[subdomains]} | Alive: ${META_COUNTS[alive_hosts]} | URLs: ${META_COUNTS[total_urls]} | Vulns: ${META_COUNTS[vuln_findings]} | Secrets: ${META_COUNTS[secrets]}" \
        "${total_elapsed}"
}

# ══════════════════════════════════════════════════════════════════════════════
# §18 ─ BANNER & USAGE
# ══════════════════════════════════════════════════════════════════════════════
print_banner() {
    echo -e "${C_BCYAN}"
    cat << 'BANNER'
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ███████╗██╗  ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██╔════╝██║  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ███████╗███████║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ╚════██║██╔══██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ███████║██║  ██║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚══════╝╚═╝  ╚═╝
BANNER
    echo -e "${C_RESET}"
    echo -e "  ${C_BOLD}Tier-1 Bug Bounty Reconnaissance Framework${C_RESET}  ${C_DIM}v${SCRIPT_VERSION}${C_RESET}"
    echo -e "  ${C_DIM}Author: ${C_BMAGENTA}${SCRIPT_AUTHOR}${C_RESET}  ${C_DIM}·  30+ Tools · Passive · Active · Modular · Automated${C_RESET}"
    echo -e "${LOG_SEP}"
    echo ""
}

usage() {
    cat << EOF
${C_BOLD}USAGE:${C_RESET}
  ${C_CYAN}${SCRIPT_NAME}${C_RESET} ${C_WHITE}-d <domain>${C_RESET} [MODULE FLAGS] [OPTIONS]

${C_BOLD}REQUIRED:${C_RESET}
  ${C_YELLOW}-d <domain>${C_RESET}   Target root domain  (e.g. target.com)

${C_BOLD}MODULES:${C_RESET}
  ${C_YELLOW}-r${C_RESET}   Passive + Active Recon   subfinder/assetfinder/amass/findomain/chaos/
               github-subdomains/crt.sh → puredns/dnsx brute → httpx
  ${C_YELLOW}-P${C_RESET}   Port Scan                naabu (all ports -p -) + nmap service scan
  ${C_YELLOW}-s${C_RESET}   Screenshots              gowitness visual recon on alive hosts
  ${C_YELLOW}-f${C_RESET}   Fuzzing                  ffuf dir+vhost + feroxbuster deep scan (requires -l)
  ${C_YELLOW}-u${C_RESET}   URL Discovery            10-source harvest → 14-category filtering
  ${C_YELLOW}-j${C_RESET}   JS & Secrets             subjs/mantra/jsecret/jsleak/trufflehog/lazyegg
  ${C_YELLOW}-p${C_RESET}   Hidden Params            arjun GET/POST + qsreplace FUZZ list
  ${C_YELLOW}-v${C_RESET}   Vuln Scan                nuclei CVE/takeover/misconfig/exposure scanning
  ${C_YELLOW}-a${C_RESET}   All Modules              Full pipeline in dependency order

${C_BOLD}OPTIONS:${C_RESET}
  ${C_YELLOW}-l <wordlist>${C_RESET}   Wordlist path   Required for -f/-a; also used by -r (active brute)
  ${C_YELLOW}-n${C_RESET}             Notify          Rich Telegram/Discord webhook on module completion
  ${C_YELLOW}-h${C_RESET}             Help            Show this screen

${C_BOLD}ENVIRONMENT VARIABLES (optional):${C_RESET}
  PDCP_API_KEY        ProjectDiscovery chaos API key
  GITHUB_TOKEN        GitHub token for github-subdomains
  NUCLEI_TEMPLATES    Path to local nuclei-templates checkout
  TELEGRAM_BOT_TOKEN  Override inline credential (for -n)
  TELEGRAM_CHAT_ID    Override inline credential (for -n)
  DISCORD_WEBHOOK_URL Override inline credential (for -n)

${C_BOLD}EXAMPLES:${C_RESET}
  ${C_CYAN}${SCRIPT_NAME} -d target.com -r -P${C_RESET}
    → Passive+active recon + full port scan

  ${C_CYAN}${SCRIPT_NAME} -d target.com -r -u -j -n${C_RESET}
    → Recon + 10-source URL harvest + JS secret scan + notifications

  ${C_CYAN}${SCRIPT_NAME} -d target.com -a -l ~/wordlists/raft-large.txt -n${C_RESET}
    → Full pipeline with brute-forcing, fuzzing, and rich notifications

${C_BOLD}OUTPUT STRUCTURE:${C_RESET}
  recon_<domain>/
  ├── subdomains/
  │   ├── subs_*.txt              Per-tool raw subdomain files
  │   ├── active/                 puredns + dnsx brute-force results
  │   └── all_subs.txt            Merged + deduplicated master list
  ├── ports/
  │   ├── naabu_all.txt           All open host:port pairs
  │   ├── naabu_filtered.txt      Non-standard web ports
  │   └── nmap_scan.*             nmap XML/greppable/text output
  ├── urls/
  │   ├── alive_hosts.txt         httpx full output (status/title/tech)
  │   ├── alive_urls.txt          Plain URL list for downstream tools
  │   └── alive_nonstandard.txt   Alive hosts on non-standard ports
  ├── screenshots/                gowitness captures + sqlite DB
  ├── urldiscovery/
  │   ├── *_raw.txt               Per-tool raw URL output
  │   ├── all_urls_raw.txt        Merged raw URLs
  │   ├── all_urls_clean.txt      Deduplicated, filtered master URL list
  │   ├── urls_params.txt         URLs containing query parameters
  │   ├── live_urls.txt           httpx-confirmed live URLs
  │   └── categories/             14 category-filtered URL subsets
  │       ├── js_urls.txt         JS file URLs
  │       ├── php_files.txt       PHP endpoints
  │       ├── asp_files.txt       ASP/ASPX endpoints
  │       ├── api_endpoints.txt   JSON/XML/GraphQL endpoints
  │       ├── login_flows.txt     Auth-related endpoints
  │       ├── admin_panels.txt    Admin/management endpoints
  │       ├── sensitive_files.txt .env/.bak/.sql/config files
  │       ├── idor_targets.txt    Numeric ID patterns
  │       ├── interesting.txt     High-value redirect/debug endpoints
  │       ├── cloud_leaks.txt     AWS/GCP/Azure references
  │       ├── injection_params.txt URLs with query parameters
  │       └── wayback_sensitive.txt Sensitive extension matches
  ├── js/
  │   ├── js_urls.txt             Master JS URL list
  │   ├── subjs_found.txt         Additional JS found by subjs
  │   ├── mantra_secrets.txt      mantra pattern findings
  │   ├── jsecret_output.txt      jsecret findings
  │   ├── jsleak_output.txt       jsleak parallel findings
  │   ├── regex_secrets.txt       Regex grep findings
  │   ├── lazyegg_output.txt      lazyegg extraction
  │   ├── trufflehog_findings.json trufflehog verified secrets
  │   └── files/                  Downloaded .js content for local scan
  ├── params/
  │   ├── arjun_targets.txt       URLs submitted to arjun
  │   ├── arjun_findings.json     arjun JSON output
  │   ├── params_summary.txt      Human-readable param breakdown
  │   ├── params_fuzz.txt         qsreplace FUZZ-ready URLs
  │   └── param_keys.txt          Extracted parameter key names
  ├── fuzzing/
  │   ├── *_dir.json              ffuf per-host directory results
  │   ├── *_ferox.txt             feroxbuster per-host results
  │   └── vhost/                  VHost fuzzing results
  │       ├── vhost_hostinject.json Host-header injection results
  │       ├── sub_prefix_*.json    Subdomain prefix pattern results
  │       └── *_403bypass.json     403 bypass header fuzzing results
  ├── vulns/
  │   ├── vuln_targets.txt        Enriched target list (alive + categories)
  │   ├── nuclei_findings.txt     Human-readable findings
  │   ├── nuclei_findings.json    JSONL machine-readable findings
  │   └── nuclei_exposures.txt    Exposure-template output
  └── run_metadata.json           Full run report (timestamps, counts, modules)

${C_BOLD}RESUME CAPABILITY:${C_RESET}
  Completed modules write a stamp file (.<module>.done).
  On re-run, the script prompts to skip or re-execute each module.
  Non-interactive sessions (piped stdin) auto-skip completed modules.

EOF
}

# ══════════════════════════════════════════════════════════════════════════════
# §19 ─ ARGUMENT PARSING (getopts)
# ══════════════════════════════════════════════════════════════════════════════
parse_args() {
    if [[ $# -eq 0 ]]; then
        print_banner
        usage
        exit 0
    fi

    while getopts ":d:l:rPsfujpvanh" opt; do
        case "${opt}" in
            d)  TARGET_DOMAIN="${OPTARG}" ;;
            l)  WORDLIST_FILE="${OPTARG}" ;;
            r)  RUN_RECON=1 ;;
            P)  RUN_PORTSCAN=1 ;;
            s)  RUN_SCREENSHOTS=1 ;;
            f)  RUN_FUZZING=1 ;;
            u)  RUN_URLDISCOVERY=1 ;;
            j)  RUN_JSSECRETS=1 ;;
            p)  RUN_HIDDENPARAMS=1 ;;
            v)  RUN_VULN=1 ;;
            a)
                RUN_ALL=1
                RUN_RECON=1
                RUN_PORTSCAN=1
                RUN_SCREENSHOTS=1
                RUN_FUZZING=1
                RUN_URLDISCOVERY=1
                RUN_JSSECRETS=1
                RUN_HIDDENPARAMS=1
                RUN_VULN=1
                ;;
            n)  RUN_NOTIFY=1 ;;
            h)
                print_banner
                usage
                exit 0
                ;;
            :)  die "Flag -${OPTARG} requires an argument. Use -h for help." 2 ;;
            \?) die "Unknown flag: -${OPTARG}. Use -h for help." 2 ;;
        esac
    done

    shift $(( OPTIND - 1 ))

    [[ -z "${TARGET_DOMAIN}" ]] && \
        die "Target domain (-d) is required." 2

    validate_domain "${TARGET_DOMAIN}"

    # Fuzzing requires a wordlist
    if [[ "${RUN_FUZZING}" -eq 1 && -z "${WORDLIST_FILE}" ]]; then
        die "The Fuzzing module (-f / -a) requires a wordlist (-l <path>)." 2
    fi

    # Validate wordlist path if provided
    if [[ -n "${WORDLIST_FILE}" ]]; then
        validate_file "${WORDLIST_FILE}" "wordlist"
    fi

    local any_module=$(( RUN_RECON + RUN_PORTSCAN + RUN_SCREENSHOTS + \
                         RUN_FUZZING + RUN_URLDISCOVERY + RUN_JSSECRETS + \
                         RUN_HIDDENPARAMS + RUN_VULN ))
    if [[ "${any_module}" -eq 0 ]]; then
        die "No module selected. Use -r -P -s -f -u -j -p -v or -a. See -h." 2
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# §20 ─ MAIN ENTRYPOINT
# ══════════════════════════════════════════════════════════════════════════════
main() {
    parse_args "$@"
    print_banner

    echo -e "  ${LOG_INFO} ${C_BOLD}Target   :${C_RESET}  ${C_BCYAN}${TARGET_DOMAIN}${C_RESET}"
    [[ -n "${WORDLIST_FILE}" ]] && \
        echo -e "  ${LOG_INFO} ${C_BOLD}Wordlist :${C_RESET}  ${C_WHITE}${WORDLIST_FILE}${C_RESET}"

    local active_modules=()
    [[ "${RUN_RECON}" -eq 1 ]]        && active_modules+=("Recon")
    [[ "${RUN_PORTSCAN}" -eq 1 ]]     && active_modules+=("PortScan")
    [[ "${RUN_SCREENSHOTS}" -eq 1 ]]  && active_modules+=("Screenshots")
    [[ "${RUN_URLDISCOVERY}" -eq 1 ]] && active_modules+=("URLDiscovery")
    [[ "${RUN_JSSECRETS}" -eq 1 ]]    && active_modules+=("JS+Secrets")
    [[ "${RUN_HIDDENPARAMS}" -eq 1 ]] && active_modules+=("HiddenParams")
    [[ "${RUN_FUZZING}" -eq 1 ]]      && active_modules+=("Fuzzing")
    [[ "${RUN_VULN}" -eq 1 ]]         && active_modules+=("VulnScan")
    [[ "${RUN_NOTIFY}" -eq 1 ]]       && active_modules+=("Notify")

    echo -e "  ${LOG_INFO} ${C_BOLD}Modules  :${C_RESET}  ${C_BMAGENTA}$(IFS=', '; echo "${active_modules[*]}")${C_RESET}"
    echo -e "  ${LOG_INFO} ${C_BOLD}Started  :${C_RESET}  ${C_DIM}${RUN_START_HUMAN}${C_RESET}"
    echo ""

    # Show tool availability before any disk work
    preflight_tool_check

    # Initialise output directory tree
    setup_output_dirs

    # ── Module pipeline dispatch ───────────────────────────────────────────────
    # Dependency order: recon → portscan → screenshots → url_discovery
    #                   → js_secrets → hidden_params → fuzzing → vuln_scan
    [[ "${RUN_RECON}" -eq 1 ]]        && module_recon
    [[ "${RUN_PORTSCAN}" -eq 1 ]]     && module_portscan
    [[ "${RUN_SCREENSHOTS}" -eq 1 ]]  && module_screenshots
    [[ "${RUN_URLDISCOVERY}" -eq 1 ]] && module_url_discovery
    [[ "${RUN_JSSECRETS}" -eq 1 ]]    && module_js_secrets
    [[ "${RUN_HIDDENPARAMS}" -eq 1 ]] && module_hidden_params
    [[ "${RUN_FUZZING}" -eq 1 ]]      && module_fuzzing
    [[ "${RUN_VULN}" -eq 1 ]]         && module_vuln_scan

    write_run_metadata
    print_summary
}

# ══════════════════════════════════════════════════════════════════════════════
# GUARD: Prevent execution when sourced (allows unit-testing individual fns)
# ══════════════════════════════════════════════════════════════════════════════
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
