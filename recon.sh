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
#  Version  : 3.0.0
#  Author   : 0x-vartolu
#  License  : MIT
#
#  DESCRIPTION:
#    A modular, flag-driven, enterprise-grade reconnaissance pipeline for
#    professional bug bounty hunting. Features port scanning, historical URL
#    discovery, JS secret analysis, hidden parameter discovery, state
#    tracking / resume capability, visual spinners, rich webhook embeds,
#    and a full run metadata report.
#
#  FULL MODULE FLAGS:
#    -r   Passive Recon        Subdomain enum → dedup → live host filter
#    -P   Port Scan            naabu port scan → feed into httpx (non-std ports)
#    -s   Screenshots          gowitness visual recon on alive hosts
#    -f   Fuzzing              ffuf active directory/param fuzzing (needs -l)
#    -u   URL Discovery        gau/waybackurls historical URL harvest
#    -j   JS & Secrets         JS extraction → trufflehog / nuclei secrets scan
#    -p   Hidden Params        arjun hidden GET/POST parameter discovery
#    -v   Vuln Scan            nuclei CVE/takeover/misconfig scanning
#    -a   All Modules          Full pipeline in dependency order
#
#  USAGE:
#    ./recon.sh -d target.com -r -P                      # Recon + port scan
#    ./recon.sh -d target.com -r -u -j                   # Recon + URL + secrets
#    ./recon.sh -d target.com -a -l wordlist.txt -n      # Full pipeline + notify
# ==============================================================================

set -euo pipefail   # Exit on error | undefined vars | pipe failures
IFS=$'\n\t'         # Safer word splitting (tabs & newlines only)

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

# Semantic logging prefixes (visual glyph + colour)
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
readonly SCRIPT_VERSION="3.0.0"
readonly SCRIPT_AUTHOR="0x-vartolu"
readonly RUN_START_TS="$(date +%s)"          # Unix epoch – used for timing
readonly RUN_START_HUMAN="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

# ── Mutable runtime state (populated by getopts) ─────────────────────────────
TARGET_DOMAIN=""
WORDLIST_FILE=""
OUTPUT_BASE_DIR=""

# Module activation flags (0 = off, 1 = on)
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

# ── Notification configuration ────────────────────────────────────────────────
# Replace placeholder values with real credentials before using -n
readonly TELEGRAM_BOT_TOKEN="__YOUR_TELEGRAM_BOT_TOKEN__"
readonly TELEGRAM_CHAT_ID="__YOUR_TELEGRAM_CHAT_ID__"
readonly DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/__YOUR_WEBHOOK_ID__/__YOUR_WEBHOOK_TOKEN__"

# ── Global counters (accumulated across modules for metadata report) ──────────
declare -A META_COUNTS=(
    [subdomains]=0
    [ports]=0
    [alive_hosts]=0
    [screenshots]=0
    [historical_urls]=0
    [js_files]=0
    [secrets]=0
    [hidden_params]=0
    [vuln_findings]=0
    [fuzz_hits]=0
)

# ── Spinner state ─────────────────────────────────────────────────────────────
SPINNER_PID=0   # PID of any currently-running spinner background process

# ══════════════════════════════════════════════════════════════════════════════
# §3 ─ CORE LOGGING & UI UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

log_info()  { echo -e "${LOG_INFO}  ${C_WHITE}$*${C_RESET}"; }
log_ok()    { echo -e "${LOG_OK}  ${C_BGREEN}$*${C_RESET}"; }
log_warn()  { echo -e "${LOG_WARN}  ${C_BYELLOW}$*${C_RESET}"; }
log_err()   { echo -e "${LOG_ERR}  ${C_BRED}$*${C_RESET}" >&2; }
log_skip()  { echo -e "${LOG_SKIP}  ${C_DIM}$*${C_RESET}"; }

# Fatal error → print message and exit immediately
die() {
    local msg="$1"
    local code="${2:-1}"
    log_err "FATAL: ${msg}"
    exit "${code}"
}

# Section header with double-rule border
log_section() {
    local title="$1"
    echo ""
    echo -e "${LOG_SEP}"
    echo -e "  ${C_BOLD}${C_BMAGENTA}◈  ${title}${C_RESET}"
    echo -e "${LOG_SEP}"
    echo ""
}

# ── Spinner ───────────────────────────────────────────────────────────────────
# spinner_start <label>
#   Launches a background spinner. Call spinner_stop when the job finishes.
#   The spinner writes directly to stderr so it doesn't pollute stdout/logs.
spinner_start() {
    local label="${1:-Working...}"
    # Don't start a second spinner if one is already running
    [[ "${SPINNER_PID}" -ne 0 ]] && return 0

    # Run spinner in a subshell so it can be killed cleanly
    (
        local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
        local i=0
        # Disable SIGTERM default exit so we can clear the line first
        trap 'tput el1 2>/dev/null; printf "\r" >&2; exit 0' TERM
        while true; do
            printf "\r  ${C_BCYAN}%s${C_RESET}  ${C_DIM}%s${C_RESET}" \
                "${frames[$((i % ${#frames[@]}))]}" "${label}" >&2
            (( i++ )) || true
            sleep 0.08
        done
    ) &

    SPINNER_PID=$!
    # Ensure the spinner is always stopped on script exit (safety net)
    trap 'spinner_stop' EXIT
}

# spinner_stop
#   Kills the background spinner and clears the spinner line.
spinner_stop() {
    if [[ "${SPINNER_PID}" -ne 0 ]]; then
        kill "${SPINNER_PID}" 2>/dev/null || true
        wait "${SPINNER_PID}" 2>/dev/null || true
        SPINNER_PID=0
        # Clear the spinner line
        printf "\r\033[K" >&2
    fi
}

# ── Elapsed time helper ───────────────────────────────────────────────────────
# elapsed_since <epoch_seconds>  →  prints "Xm Ys"
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

# check_tool <binary>
#   Non-fatal: returns 1 if missing (caller decides whether to skip or die).
check_tool() {
    local tool="$1"
    if ! command -v "${tool}" &>/dev/null; then
        log_warn "Optional tool not found in PATH: ${C_BOLD}${tool}${C_RESET}${C_BYELLOW} — dependent step will be skipped."
        return 1
    fi
    return 0
}

# check_required_tool <binary>
#   Fatal variant: exits the script if the tool is missing.
check_required_tool() {
    local tool="$1"
    if ! command -v "${tool}" &>/dev/null; then
        die "Required tool '${tool}' not found in PATH. Please install it and retry." 2
    fi
}

# validate_domain <string>
#   Enforces a basic FQDN pattern; rejects bare IPs and protocol-prefixed strings.
validate_domain() {
    local domain="$1"
    if [[ "${domain}" =~ ^https?:// ]]; then
        die "Provide a bare domain without a protocol prefix (e.g. 'target.com', not 'https://target.com')." 2
    fi
    if [[ ! "${domain}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]]; then
        die "Invalid domain format: '${domain}'. Expected something like 'target.com'." 2
    fi
}

# validate_file <path> <label>
#   Ensures a file path is non-empty and the file actually exists on disk.
validate_file() {
    local filepath="$1"
    local label="${2:-file}"
    [[ -z "${filepath}" ]]   && die "A ${label} path is required but was not provided." 2
    [[ ! -f "${filepath}" ]] && die "The specified ${label} does not exist: '${filepath}'" 2
}

# ── Helper: safe line count ───────────────────────────────────────────────────
# count_lines <file>  →  prints integer (0 if file missing/empty)
count_lines() {
    local file="$1"
    if [[ -f "${file}" && -s "${file}" ]]; then
        wc -l < "${file}" | tr -d ' '
    else
        echo "0"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# §5 ─ OUTPUT DIRECTORY SETUP
# ══════════════════════════════════════════════════════════════════════════════

setup_output_dirs() {
    OUTPUT_BASE_DIR="recon_${TARGET_DOMAIN}"

    log_info "Initialising output tree at: ${C_BOLD}${OUTPUT_BASE_DIR}/${C_RESET}"

    # All subdirectories created here — add new module dirs in this list
    local -a subdirs=(
        "subdomains"    # Raw + merged subdomain lists
        "ports"         # naabu port scan results
        "urls"          # Alive URL lists
        "screenshots"   # gowitness captures
        "fuzzing"       # ffuf output
        "urldiscovery"  # gau / waybackurls historical URLs
        "js"            # Extracted JS files + secret scan results
        "params"        # arjun hidden parameter findings
        "vulns"         # nuclei findings
    )

    for dir in "${subdirs[@]}"; do
        mkdir -p "${OUTPUT_BASE_DIR}/${dir}"
    done

    log_ok "Directory tree ready."
}

# ══════════════════════════════════════════════════════════════════════════════
# §6 ─ STATE TRACKING & RESUME CAPABILITY
# ══════════════════════════════════════════════════════════════════════════════
#
# Each module writes a tiny "stamp" file (.<module>.done) to the output root
# when it completes successfully. On the next invocation, the script detects
# these stamps and prompts the user to skip or re-run that module.
#
# Stamp file format:  recon_<domain>/.<module_name>.done
# Contents           :  ISO-8601 completion timestamp (human reference only)
# ──────────────────────────────────────────────────────────────────────────────

# mark_done <module_name>
#   Writes a completion stamp for the given module.
mark_done() {
    local module="$1"
    echo "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        > "${OUTPUT_BASE_DIR}/.${module}.done"
}

# is_done <module_name>
#   Returns 0 (true) if the completion stamp exists, 1 otherwise.
is_done() {
    local module="$1"
    [[ -f "${OUTPUT_BASE_DIR}/.${module}.done" ]]
}

# check_resume <module_name> <display_label>
#   Called at the top of each module.
#   If the module has already run, asks the user whether to re-run or skip.
#   Echoes "skip" if the module should be skipped, "run" if it should execute.
#
# Usage:
#   local resume_decision
#   resume_decision="$(check_resume "recon" "Passive Recon")"
#   [[ "${resume_decision}" == "skip" ]] && return 0
check_resume() {
    local module="$1"
    local label="$2"

    if is_done "${module}"; then
        local done_ts
        done_ts="$(cat "${OUTPUT_BASE_DIR}/.${module}.done" 2>/dev/null || echo "unknown")"
        echo ""
        echo -e "  ${C_BYELLOW}⚡ Resume detected:${C_RESET} ${C_BOLD}${label}${C_RESET} was completed at ${C_DIM}${done_ts}${C_RESET}"
        echo -ne "  ${C_BCYAN}Skip this module and use existing results? [Y/n]:${C_RESET} "

        # If stdin is not a terminal (e.g. piped), auto-skip for non-interactive runs
        if [[ ! -t 0 ]]; then
            echo "y (non-interactive: auto-skip)"
            echo "skip"
            return 0
        fi

        local answer
        read -r answer
        answer="${answer,,}"   # lowercase

        if [[ "${answer}" == "n" || "${answer}" == "no" ]]; then
            log_info "Re-running ${label} as requested."
            # Remove the old stamp so a fresh one is written at the end
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
#
# Sends richly-formatted notifications to Telegram (MarkdownV2) and/or
# Discord (Embed JSON) upon module completion.
#
# Usage:
#   notify_module \
#       "Port Scan" \           ← Module name
#       "✅ Completed" \         ← Status line
#       "Discovered 42 ports"   ← Detail line
#       "1m 12s"                ← Elapsed time
# ──────────────────────────────────────────────────────────────────────────────

notify_module() {
    # Guard: skip entirely if -n flag was not passed
    [[ "${RUN_NOTIFY}" -eq 0 ]] && return 0

    local module_name="${1:-Unknown Module}"
    local status_line="${2:-Completed}"
    local detail_line="${3:-}"
    local elapsed="${4:-N/A}"
    local now_human
    now_human="$(date -u +'%Y-%m-%d %H:%M UTC')"

    # ── Telegram (MarkdownV2) ─────────────────────────────────────────────────
    # MarkdownV2 requires escaping: _ * [ ] ( ) ~ ` > # + - = | { } . !
    if [[ "${TELEGRAM_BOT_TOKEN}" != *"__YOUR_TELEGRAM"* ]]; then

        # Build a nicely formatted Markdown message
        # Escaping is minimal here for readability — add \-escapes for special chars
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

        # Discord embeds use a colour integer: 0x00BFFF = 49151 (deep sky blue)
        # Swap colour for RED (15158332) on critical findings, etc.
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
# §8 ─ MODULE: PASSIVE RECON  (-r)
# ══════════════════════════════════════════════════════════════════════════════
#
# Pipeline:
#   subfinder ─┐
#              ├─ anew ─► all_subs.txt ─► httpx ─► alive_hosts.txt
#   assetfinder┘                                  └─► alive_urls.txt (plain)
#
# Output files:
#   subdomains/subfinder.txt      Raw subfinder hits
#   subdomains/assetfinder.txt    Raw assetfinder hits
#   subdomains/all_subs.txt       Merged + deduplicated
#   urls/alive_hosts.txt          httpx full output (status/title/tech)
#   urls/alive_urls.txt           Plain URL list for downstream tools
# ──────────────────────────────────────────────────────────────────────────────
module_recon() {
    log_section "MODULE ─ Passive Subdomain Recon  [-r]"

    local decision
    decision="$(check_resume "recon" "Passive Recon")"
    [[ "${decision}" == "skip" ]] && return 0

    local t0; t0="$(date +%s)"
    local subs_dir="${OUTPUT_BASE_DIR}/subdomains"
    local urls_dir="${OUTPUT_BASE_DIR}/urls"
    local all_subs="${subs_dir}/all_subs.txt"

    # ── subfinder ──────────────────────────────────────────────────────────────
    if check_tool "subfinder"; then
        log_info "Running ${C_BOLD}subfinder${C_RESET} on ${TARGET_DOMAIN}..."
        spinner_start "subfinder enumerating…"
        subfinder \
            -d "${TARGET_DOMAIN}" \
            -silent \
            -all \
            -o "${subs_dir}/subfinder.txt" \
            2>/dev/null || true
        spinner_stop
        log_ok "subfinder → $(count_lines "${subs_dir}/subfinder.txt") results"
    fi

    # ── assetfinder ───────────────────────────────────────────────────────────
    if check_tool "assetfinder"; then
        log_info "Running ${C_BOLD}assetfinder${C_RESET} on ${TARGET_DOMAIN}..."
        spinner_start "assetfinder enumerating…"
        assetfinder --subs-only "${TARGET_DOMAIN}" \
            > "${subs_dir}/assetfinder.txt" 2>/dev/null || true
        spinner_stop
        log_ok "assetfinder → $(count_lines "${subs_dir}/assetfinder.txt") results"
    fi

    # ── Merge & deduplicate ───────────────────────────────────────────────────
    log_info "Merging sources and deduplicating..."
    if check_tool "anew"; then
        touch "${all_subs}"
        cat "${subs_dir}"/*.txt 2>/dev/null \
            | grep -v '^$' | sort \
            | anew "${all_subs}" > /dev/null
    else
        log_warn "'anew' not found — falling back to sort -u"
        cat "${subs_dir}"/*.txt 2>/dev/null \
            | grep -v '^$' | sort -u > "${all_subs}"
    fi

    if [[ ! -s "${all_subs}" ]]; then
        log_warn "No subdomains discovered. Recon module complete with zero results."
        notify_module "Passive Recon" "⚠️ No subdomains found" \
            "Zero subdomains discovered for ${TARGET_DOMAIN}" "$(elapsed_since "${t0}")"
        return 0
    fi

    META_COUNTS[subdomains]="$(count_lines "${all_subs}")"
    log_ok "Total unique subdomains: ${C_BOLD}${META_COUNTS[subdomains]}${C_RESET}"

    # ── httpx live-host probing ────────────────────────────────────────────────
    check_required_tool "httpx"
    log_info "Probing live hosts with ${C_BOLD}httpx${C_RESET}..."
    spinner_start "httpx probing live hosts…"

    httpx \
        -l "${all_subs}" \
        -silent \
        -status-code \
        -title \
        -tech-detect \
        -follow-redirects \
        -threads 50 \
        -timeout 10 \
        -o "${urls_dir}/alive_hosts.txt" \
        2>/dev/null || true

    spinner_stop

    if [[ -s "${urls_dir}/alive_hosts.txt" ]]; then
        # Extract clean URL column (first whitespace-delimited field)
        awk '{print $1}' "${urls_dir}/alive_hosts.txt" \
            | grep -E '^https?://' \
            > "${urls_dir}/alive_urls.txt" 2>/dev/null || true

        META_COUNTS[alive_hosts]="$(count_lines "${urls_dir}/alive_urls.txt")"
        log_ok "Alive hosts: ${C_BOLD}${META_COUNTS[alive_hosts]}${C_RESET}"
    else
        log_warn "httpx found no alive hosts."
    fi

    mark_done "recon"
    notify_module "Passive Recon" "✅ Completed" \
        "Subdomains: ${META_COUNTS[subdomains]} | Alive: ${META_COUNTS[alive_hosts]}" \
        "$(elapsed_since "${t0}")"
    log_ok "Recon module finished.  [${C_DIM}$(elapsed_since "${t0}")${C_RESET}]"
}

# ══════════════════════════════════════════════════════════════════════════════
# §9 ─ MODULE: PORT SCANNING  (-P)
# ══════════════════════════════════════════════════════════════════════════════
#
# Motivation: Default recon only probes 80/443. Admin panels, dev servers, and
# vulnerable APIs frequently live on non-standard ports (8080, 8443, 9200, etc.).
#
# Pipeline:
#   all_subs.txt ─► naabu ─► open_ports.txt (host:port)
#                         └─► httpx on host:port pairs ─► alive_urls.txt (appended)
#
# Output files:
#   ports/naabu_all.txt       All naabu "host:port" pairs
#   ports/naabu_filtered.txt  Filtered to non-standard web ports only
# ──────────────────────────────────────────────────────────────────────────────
module_portscan() {
    log_section "MODULE ─ Port Scanning via naabu  [-P]"

    local decision
    decision="$(check_resume "portscan" "Port Scan")"
    [[ "${decision}" == "skip" ]] && return 0

    local t0; t0="$(date +%s)"
    local subs_dir="${OUTPUT_BASE_DIR}/subdomains"
    local ports_dir="${OUTPUT_BASE_DIR}/ports"
    local urls_dir="${OUTPUT_BASE_DIR}/urls"
    local all_subs="${subs_dir}/all_subs.txt"

    # Prereq: subdomain list must exist
    if [[ ! -s "${all_subs}" ]]; then
        log_warn "No subdomain list found at '${all_subs}'. Run -r (Recon) first."
        log_skip "Skipping Port Scan module."
        return 0
    fi

    check_required_tool "naabu"
    check_required_tool "httpx"

    local sub_count
    sub_count="$(count_lines "${all_subs}")"
    log_info "Running ${C_BOLD}naabu${C_RESET} against ${sub_count} subdomains..."
    log_warn "Port scanning can be slow. Consider using -p for specific ports."

    # naabu flags:
    #   -list    : input file of hosts
    #   -top-ports 1000 : scan the 1000 most common ports
    #   -silent  : suppress banner
    #   -o       : output file
    #   -c       : concurrent hosts
    #   -rate    : packets per second (tune to avoid triggering WAF)
    #   -exclude-ports : skip pure non-HTTP ports (22,25,53,110,143,587,993)
    spinner_start "naabu scanning ports…"
    naabu \
        -list "${all_subs}" \
        -top-ports 1000 \
        -silent \
        -o "${ports_dir}/naabu_all.txt" \
        -c 50 \
        -rate 1000 \
        -exclude-ports 22,25,53,110,143,587,993,995 \
        2>/dev/null || true
    spinner_stop

    META_COUNTS[ports]="$(count_lines "${ports_dir}/naabu_all.txt")"
    log_ok "naabu discovered ${C_BOLD}${META_COUNTS[ports]}${C_RESET} open port(s)."

    if [[ ! -s "${ports_dir}/naabu_all.txt" ]]; then
        log_warn "No open ports found beyond defaults."
        mark_done "portscan"
        return 0
    fi

    # ── Filter to non-standard web ports ─────────────────────────────────────
    # Keep entries whose port is NOT 80 or 443 — these are the interesting ones
    grep -vE ':(80|443)$' "${ports_dir}/naabu_all.txt" \
        > "${ports_dir}/naabu_filtered.txt" 2>/dev/null || true

    local filtered_count
    filtered_count="$(count_lines "${ports_dir}/naabu_filtered.txt")"
    log_info "Non-standard web ports: ${C_BOLD}${filtered_count}${C_RESET}"

    # ── Feed non-standard ports back into httpx ────────────────────────────────
    if [[ -s "${ports_dir}/naabu_filtered.txt" ]]; then
        log_info "Probing non-standard ports with ${C_BOLD}httpx${C_RESET}..."
        spinner_start "httpx probing non-standard ports…"

        local nonstandard_alive="${urls_dir}/alive_nonstandard.txt"
        httpx \
            -l "${ports_dir}/naabu_filtered.txt" \
            -silent \
            -status-code \
            -title \
            -tech-detect \
            -follow-redirects \
            -threads 50 \
            -timeout 10 \
            -o "${nonstandard_alive}" \
            2>/dev/null || true

        spinner_stop

        if [[ -s "${nonstandard_alive}" ]]; then
            local ns_count
            ns_count="$(count_lines "${nonstandard_alive}")"
            log_ok "Alive on non-standard ports: ${C_BOLD}${ns_count}${C_RESET}"

            # Append unique new URLs to the master alive_urls.txt
            if check_tool "anew"; then
                awk '{print $1}' "${nonstandard_alive}" \
                    | grep -E '^https?://' \
                    | anew "${urls_dir}/alive_urls.txt" >> /dev/null
            else
                awk '{print $1}' "${nonstandard_alive}" \
                    | grep -E '^https?://' \
                    >> "${urls_dir}/alive_urls.txt"
                sort -u -o "${urls_dir}/alive_urls.txt" "${urls_dir}/alive_urls.txt"
            fi

            log_ok "Master alive_urls.txt updated with non-standard port hosts."
            META_COUNTS[alive_hosts]="$(count_lines "${urls_dir}/alive_urls.txt")"
        fi
    fi

    mark_done "portscan"
    notify_module "Port Scan" "✅ Completed" \
        "Open ports: ${META_COUNTS[ports]} | Non-standard: ${filtered_count}" \
        "$(elapsed_since "${t0}")"
    log_ok "Port Scan module finished.  [${C_DIM}$(elapsed_since "${t0}")${C_RESET}]"
}

# ══════════════════════════════════════════════════════════════════════════════
# §10 ─ MODULE: SCREENSHOTS  (-s)
# ══════════════════════════════════════════════════════════════════════════════
#
# Visual recon: captures screenshots of every alive host using gowitness.
# Essential for quickly triaging large asset sets without visiting each URL.
#
# Output files:
#   screenshots/*.png            Individual screenshots
#   screenshots/gowitness.sqlite3  gowitness database (for report generation)
# ──────────────────────────────────────────────────────────────────────────────
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
    log_info "Taking screenshots of ${C_BOLD}${url_count}${C_RESET} hosts..."

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
    log_info "Generate HTML report: ${C_CYAN}gowitness report serve --db-path ${shots_dir}/gowitness.sqlite3${C_RESET}"

    mark_done "screenshots"
    notify_module "Screenshots" "✅ Completed" \
        "Captured ${META_COUNTS[screenshots]} screenshots across ${url_count} hosts" \
        "$(elapsed_since "${t0}")"
    log_ok "Screenshots module finished.  [${C_DIM}$(elapsed_since "${t0}")${C_RESET}]"
}

# ══════════════════════════════════════════════════════════════════════════════
# §11 ─ MODULE: HISTORICAL URL DISCOVERY  (-u)
# ══════════════════════════════════════════════════════════════════════════════
#
# Mines archived/historical URLs from:
#   - gau        (GetAllUrls: Wayback, AlienVault OTX, Common Crawl)
#   - waybackurls (Wayback Machine specifically)
#
# Post-processing pipeline:
#   raw URLs → strip params → filter extensions → dedup → clean_urls.txt
#
# Output files:
#   urldiscovery/gau_raw.txt          Raw gau output
#   urldiscovery/wayback_raw.txt      Raw waybackurls output
#   urldiscovery/all_urls_raw.txt     Merged raw URLs
#   urldiscovery/all_urls_clean.txt   Deduplicated, extension-filtered URLs
#   urldiscovery/urls_params.txt      URLs that contain query parameters
# ──────────────────────────────────────────────────────────────────────────────
module_url_discovery() {
    log_section "MODULE ─ Historical URL Discovery  [-u]"

    local decision
    decision="$(check_resume "urldiscovery" "URL Discovery")"
    [[ "${decision}" == "skip" ]] && return 0

    local t0; t0="$(date +%s)"
    local urls_dir="${OUTPUT_BASE_DIR}/urls"
    local disc_dir="${OUTPUT_BASE_DIR}/urldiscovery"
    local alive_urls="${urls_dir}/alive_urls.txt"
    local all_raw="${disc_dir}/all_urls_raw.txt"

    if [[ ! -s "${alive_urls}" ]]; then
        log_warn "No alive URLs found. Run -r (Recon) first."
        log_skip "Skipping URL Discovery module."
        return 0
    fi

    # ── gau ──────────────────────────────────────────────────────────────────
    if check_tool "gau"; then
        log_info "Running ${C_BOLD}gau${C_RESET} against ${TARGET_DOMAIN}..."
        spinner_start "gau harvesting historical URLs…"
        gau \
            --threads 5 \
            --blacklist ttf,woff,woff2,ico,jpg,jpeg,gif,png,svg,css \
            --subs \
            "${TARGET_DOMAIN}" \
            > "${disc_dir}/gau_raw.txt" 2>/dev/null || true
        spinner_stop
        log_ok "gau → $(count_lines "${disc_dir}/gau_raw.txt") URLs"
    else
        log_warn "gau not found — skipping gau step."
    fi

    # ── waybackurls ───────────────────────────────────────────────────────────
    if check_tool "waybackurls"; then
        log_info "Running ${C_BOLD}waybackurls${C_RESET} against ${TARGET_DOMAIN}..."
        spinner_start "waybackurls querying Wayback Machine…"
        echo "${TARGET_DOMAIN}" \
            | waybackurls \
            > "${disc_dir}/wayback_raw.txt" 2>/dev/null || true
        spinner_stop
        log_ok "waybackurls → $(count_lines "${disc_dir}/wayback_raw.txt") URLs"
    else
        log_warn "waybackurls not found — skipping Wayback step."
    fi

    # ── Merge and deduplicate ─────────────────────────────────────────────────
    log_info "Merging and deduplicating URL sources..."
    touch "${all_raw}"

    local src
    for src in "${disc_dir}/gau_raw.txt" "${disc_dir}/wayback_raw.txt"; do
        [[ -f "${src}" ]] && cat "${src}" >> "${all_raw}"
    done

    if [[ ! -s "${all_raw}" ]]; then
        log_warn "No historical URLs collected. Both gau and waybackurls may be missing."
        mark_done "urldiscovery"
        return 0
    fi

    # ── Clean + filter URLs ───────────────────────────────────────────────────
    # Remove static/binary asset extensions that are noise for bug bounty
    local noise_exts="jpg|jpeg|gif|png|svg|ico|ttf|woff|woff2|eot|mp4|mp3|webp|zip|tar|gz"

    sort -u "${all_raw}" \
        | grep -vE "\.(${noise_exts})(\?.*)?$" \
        | grep -E "^https?://" \
        > "${disc_dir}/all_urls_clean.txt" 2>/dev/null || true

    # Extract URLs with query parameters (high-value for injection testing)
    grep '?' "${disc_dir}/all_urls_clean.txt" \
        > "${disc_dir}/urls_params.txt" 2>/dev/null || true

    META_COUNTS[historical_urls]="$(count_lines "${disc_dir}/all_urls_clean.txt")"
    local params_count
    params_count="$(count_lines "${disc_dir}/urls_params.txt")"

    log_ok "Clean historical URLs: ${C_BOLD}${META_COUNTS[historical_urls]}${C_RESET}"
    log_ok "URLs with parameters:  ${C_BOLD}${params_count}${C_RESET} (saved to urls_params.txt)"

    mark_done "urldiscovery"
    notify_module "URL Discovery" "✅ Completed" \
        "Clean URLs: ${META_COUNTS[historical_urls]} | With params: ${params_count}" \
        "$(elapsed_since "${t0}")"
    log_ok "URL Discovery module finished.  [${C_DIM}$(elapsed_since "${t0}")${C_RESET}]"
}

# ══════════════════════════════════════════════════════════════════════════════
# §12 ─ MODULE: JS FILE ANALYSIS & SECRET SCANNING  (-j)
# ══════════════════════════════════════════════════════════════════════════════
#
# Pipeline:
#  1. Extract all .js URLs from historical + alive URL lists.
#  2. Deduplicate the JS URL list.
#  3. Run trufflehog (filesystem mode, via wget'd copies) to find secrets.
#  4. Fall back to `nuclei -t exposures/tokens` if trufflehog is unavailable.
#
# Output files:
#   js/js_urls.txt              Unique JS file URLs
#   js/js_files/                Downloaded JS files for local scanning
#   js/trufflehog_findings.json trufflehog JSON output
#   js/nuclei_js_findings.txt   nuclei secret exposure results (fallback)
# ──────────────────────────────────────────────────────────────────────────────
module_js_secrets() {
    log_section "MODULE ─ JS File Analysis & Secret Scanning  [-j]"

    local decision
    decision="$(check_resume "jssecrets" "JS & Secrets")"
    [[ "${decision}" == "skip" ]] && return 0

    local t0; t0="$(date +%s)"
    local js_dir="${OUTPUT_BASE_DIR}/js"
    local js_urls="${js_dir}/js_urls.txt"
    local disc_clean="${OUTPUT_BASE_DIR}/urldiscovery/all_urls_clean.txt"
    local alive_urls="${OUTPUT_BASE_DIR}/urls/alive_urls.txt"

    # ── Extract JS URLs from available URL sources ────────────────────────────
    log_info "Extracting .js URLs from URL lists..."
    touch "${js_urls}"

    # Pull JS URLs from every available source and deduplicate
    {
        [[ -s "${disc_clean}" ]] && grep -iE '\.js(\?.*)?$' "${disc_clean}" || true
        [[ -s "${alive_urls}" ]] && grep -iE '\.js(\?.*)?$' "${alive_urls}" || true
    } | sort -u | grep -E '^https?://' > "${js_urls}" 2>/dev/null || true

    META_COUNTS[js_files]="$(count_lines "${js_urls}")"
    log_ok "Unique JS file URLs found: ${C_BOLD}${META_COUNTS[js_files]}${C_RESET}"

    if [[ "${META_COUNTS[js_files]}" -eq 0 ]]; then
        log_warn "No JS URLs found. Run -r and/or -u modules first."
        mark_done "jssecrets"
        return 0
    fi

    # ── trufflehog branch ─────────────────────────────────────────────────────
    if check_tool "trufflehog"; then
        log_info "Running ${C_BOLD}trufflehog${C_RESET} against JS URLs..."

        # trufflehog v3 supports scanning directly from a list of URLs
        # using its 'filesystem' or 'git' source. We use the 'filesystem'
        # source on a directory of downloaded JS files.
        local js_files_dir="${js_dir}/js_files"
        mkdir -p "${js_files_dir}"

        log_info "Downloading JS files for local analysis..."
        spinner_start "wget fetching JS files…"

        # Download each JS file, preserving a flat structure
        local dl_count=0
        while IFS= read -r js_url; do
            [[ -z "${js_url}" ]] && continue
            # Sanitize URL into a filename
            local safe_fn
            safe_fn="$(echo "${js_url}" | md5sum | awk '{print $1}').js"
            wget -q --timeout=10 --tries=2 \
                -O "${js_files_dir}/${safe_fn}" \
                "${js_url}" 2>/dev/null || true
            (( dl_count++ )) || true
        done < "${js_urls}"

        spinner_stop
        log_ok "Downloaded ${dl_count} JS files to ${js_files_dir}/"

        # Run trufflehog on the downloaded JS directory
        log_info "Scanning JS files with ${C_BOLD}trufflehog${C_RESET}..."
        spinner_start "trufflehog scanning for secrets…"

        trufflehog filesystem \
            "${js_files_dir}" \
            --json \
            --no-verification \
            2>/dev/null \
            > "${js_dir}/trufflehog_findings.json" || true

        spinner_stop

        META_COUNTS[secrets]="$(count_lines "${js_dir}/trufflehog_findings.json")"
        if [[ "${META_COUNTS[secrets]}" -gt 0 ]]; then
            log_ok "${C_BRED}⚠  trufflehog found ${META_COUNTS[secrets]} potential secret(s)!${C_RESET}"
            log_info "Results: ${js_dir}/trufflehog_findings.json"
        else
            log_info "trufflehog: No secrets detected."
        fi

    # ── nuclei fallback branch ────────────────────────────────────────────────
    elif check_tool "nuclei"; then
        log_warn "trufflehog not found — falling back to ${C_BOLD}nuclei exposures/tokens${C_RESET}..."
        spinner_start "nuclei scanning JS for secret tokens…"

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
            log_ok "${C_BRED}⚠  nuclei found ${META_COUNTS[secrets]} secret exposure(s)!${C_RESET}"
        else
            log_info "nuclei JS scan: No secret exposures detected."
        fi
    else
        log_warn "Neither trufflehog nor nuclei found. Cannot perform secret scanning."
    fi

    mark_done "jssecrets"
    notify_module "JS & Secrets" "✅ Completed" \
        "JS files: ${META_COUNTS[js_files]} | Secrets found: ${META_COUNTS[secrets]}" \
        "$(elapsed_since "${t0}")"
    log_ok "JS & Secrets module finished.  [${C_DIM}$(elapsed_since "${t0}")${C_RESET}]"
}

# ══════════════════════════════════════════════════════════════════════════════
# §13 ─ MODULE: HIDDEN PARAMETER DISCOVERY  (-p)
# ══════════════════════════════════════════════════════════════════════════════
#
# Runs arjun against a curated subset of alive URLs to discover undocumented
# GET and POST parameters. These are extremely valuable for SQLi, XSS, IDOR,
# and SSRF testing.
#
# Filtering logic before arjun:
#   - Take alive_urls.txt
#   - Prefer URLs that already have a query string (likely parameterised pages)
#   - Cap at MAX_ARJUN_TARGETS to prevent runaway scanning
#
# Output files:
#   params/arjun_findings.json   arjun JSON output (per-URL parameter map)
#   params/params_summary.txt    Human-readable summary (URL + found params)
# ──────────────────────────────────────────────────────────────────────────────

# Maximum number of URLs fed into arjun (tune based on programme scope)
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

    # ── Build the arjun target list ────────────────────────────────────────────
    local arjun_targets="${params_dir}/arjun_targets.txt"
    touch "${arjun_targets}"

    # Priority 1: URLs with existing query params (already parameterised endpoints)
    if [[ -s "${disc_dir}/urls_params.txt" ]]; then
        head -n "${MAX_ARJUN_TARGETS}" "${disc_dir}/urls_params.txt" \
            >> "${arjun_targets}"
        log_info "Loaded $(count_lines "${arjun_targets}") URLs with existing params from URL discovery."
    fi

    # Priority 2: Fill remaining slots with plain alive URLs
    if [[ -s "${urls_dir}/alive_urls.txt" ]]; then
        local remaining=$(( MAX_ARJUN_TARGETS - $(count_lines "${arjun_targets}") ))
        if [[ "${remaining}" -gt 0 ]]; then
            head -n "${remaining}" "${urls_dir}/alive_urls.txt" \
                >> "${arjun_targets}"
        fi
    fi

    # Final dedup
    sort -u -o "${arjun_targets}" "${arjun_targets}"

    local target_count
    target_count="$(count_lines "${arjun_targets}")"

    if [[ "${target_count}" -eq 0 ]]; then
        log_warn "No URLs available for parameter discovery. Run -r and/or -u first."
        mark_done "hiddenparams"
        return 0
    fi

    check_required_tool "arjun"

    log_info "Running ${C_BOLD}arjun${C_RESET} against ${target_count} target URLs..."
    log_warn "arjun can be slow; sending ~$((target_count * 2)) requests per URL."

    # arjun flags:
    #   -i  : input file of URLs
    #   -oJ : JSON output file
    #   -m  : methods to test (GET and POST)
    #   -t  : threads
    #   --passive : use passive sources where possible to reduce noise
    spinner_start "arjun discovering hidden parameters…"

    arjun \
        -i "${arjun_targets}" \
        -oJ "${params_dir}/arjun_findings.json" \
        -m GET POST \
        -t 5 \
        --passive \
        2>/dev/null || true

    spinner_stop

    # ── Parse and summarise arjun JSON output ─────────────────────────────────
    # We pass the file path via an environment variable so Python receives it
    # even though the heredoc uses single-quoted (non-interpolating) PYEOF.
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

        # Write human-readable summary
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
        log_ok "${C_BRED}⚠  arjun discovered ${findings_count} hidden parameter(s)!${C_RESET}"
        log_info "See ${params_dir}/params_summary.txt for the full breakdown."
    else
        log_info "arjun: No hidden parameters discovered."
    fi

    mark_done "hiddenparams"
    notify_module "Hidden Params" "✅ Completed" \
        "Scanned: ${target_count} URLs | Hidden params found: ${findings_count}" \
        "$(elapsed_since "${t0}")"
    log_ok "Hidden Params module finished.  [${C_DIM}$(elapsed_since "${t0}")${C_RESET}]"
}

# ══════════════════════════════════════════════════════════════════════════════
# §14 ─ MODULE: ACTIVE FUZZING  (-f)
# ══════════════════════════════════════════════════════════════════════════════
#
# Runs ffuf against every alive host, feeding the user-supplied wordlist.
# Auto-calibration (-ac) removes false positives without manual filter tuning.
#
# Output files:
#   fuzzing/<sanitized_host>_fuzz.json   per-host ffuf JSON results
# ──────────────────────────────────────────────────────────────────────────────
module_fuzzing() {
    log_section "MODULE ─ Active Directory & Endpoint Fuzzing  [-f]"

    local decision
    decision="$(check_resume "fuzzing" "Fuzzing")"
    [[ "${decision}" == "skip" ]] && return 0

    local t0; t0="$(date +%s)"
    local fuzzing_dir="${OUTPUT_BASE_DIR}/fuzzing"
    local alive_urls="${OUTPUT_BASE_DIR}/urls/alive_urls.txt"

    validate_file "${WORDLIST_FILE}" "fuzzing wordlist"
    check_required_tool "ffuf"

    if [[ ! -s "${alive_urls}" ]]; then
        log_warn "No alive URLs at '${alive_urls}'. Run -r (Recon) first."
        log_skip "Skipping Fuzzing module."
        return 0
    fi

    local url_count wl_count
    url_count="$(count_lines "${alive_urls}")"
    wl_count="$(count_lines "${WORDLIST_FILE}")"
    log_info "Fuzzing ${C_BOLD}${url_count}${C_RESET} hosts | Wordlist: ${C_BOLD}${wl_count}${C_RESET} entries"

    local total_hits=0

    while IFS= read -r target_url; do
        [[ -z "${target_url}" ]] && continue

        local safe_name
        safe_name="$(echo "${target_url}" \
            | sed 's|https\?://||g' \
            | tr '/.:@' '____' \
            | tr -cd '[:alnum:]_-')"

        local out_file="${fuzzing_dir}/${safe_name}_fuzz.json"

        log_info "Fuzzing: ${C_CYAN}${target_url}${C_RESET}"

        # ffuf flags:
        #   -u        URL with FUZZ keyword as path segment
        #   -w        wordlist
        #   -ac       auto-calibrate (removes false-positive response sizes)
        #   -mc       match HTTP codes of interest
        #   -fs 0     filter zero-byte responses
        #   -o        output file
        #   -of json  JSON format for structured parsing
        #   -t 40     goroutine threads
        #   -timeout  per-request timeout
        #   -silent   no per-request console output
        ffuf \
            -u "${target_url}/FUZZ" \
            -w "${WORDLIST_FILE}" \
            -ac \
            -mc 200,204,301,302,307,401,403,405 \
            -fs 0 \
            -o "${out_file}" \
            -of json \
            -t 40 \
            -timeout 10 \
            -silent \
            2>/dev/null || true

        if command -v jq &>/dev/null && [[ -f "${out_file}" ]]; then
            local hits
            hits="$(jq '.results | length' "${out_file}" 2>/dev/null || echo 0)"
            if [[ "${hits}" -gt 0 ]]; then
                log_ok "  ↳ ${C_BOLD}${hits}${C_RESET} paths found on ${target_url}"
                (( total_hits += hits )) || true
            fi
        fi

    done < "${alive_urls}"

    META_COUNTS[fuzz_hits]="${total_hits}"
    log_ok "Total interesting paths discovered: ${C_BOLD}${total_hits}${C_RESET}"

    mark_done "fuzzing"
    notify_module "Fuzzing" "✅ Completed" \
        "Hosts: ${url_count} | Paths found: ${total_hits}" \
        "$(elapsed_since "${t0}")"
    log_ok "Fuzzing module finished.  [${C_DIM}$(elapsed_since "${t0}")${C_RESET}]"
}

# ══════════════════════════════════════════════════════════════════════════════
# §15 ─ MODULE: VULNERABILITY SCANNING  (-v)
# ══════════════════════════════════════════════════════════════════════════════
#
# Runs nuclei with a curated set of template tags targeting high-signal,
# low-noise vulnerabilities. Severity filtered to medium+ to reduce noise.
#
# Output files:
#   vulns/nuclei_findings.txt    Human-readable nuclei output
#   vulns/nuclei_findings.json   JSONL machine-readable output
# ──────────────────────────────────────────────────────────────────────────────
module_vuln_scan() {
    log_section "MODULE ─ Vulnerability & Takeover Scanning  [-v]"

    local decision
    decision="$(check_resume "vulnscan" "Vuln Scan")"
    [[ "${decision}" == "skip" ]] && return 0

    local t0; t0="$(date +%s)"
    local vulns_dir="${OUTPUT_BASE_DIR}/vulns"
    local alive_urls="${OUTPUT_BASE_DIR}/urls/alive_urls.txt"

    if [[ ! -s "${alive_urls}" ]]; then
        log_warn "No alive URLs at '${alive_urls}'. Run -r (Recon) first."
        log_skip "Skipping Vuln Scan module."
        return 0
    fi

    check_required_tool "nuclei"

    local url_count
    url_count="$(count_lines "${alive_urls}")"
    log_info "Running ${C_BOLD}nuclei${C_RESET} against ${url_count} hosts..."

    # Update templates (silent – failure is non-fatal)
    log_info "Refreshing nuclei templates..."
    spinner_start "nuclei updating templates…"
    nuclei -update-templates -silent 2>/dev/null || true
    spinner_stop
    log_ok "Templates up to date."

    # nuclei flags:
    #   -l       input URL list
    #   -tags    curated template tag selection
    #   -severity only medium, high, critical (reduces noise)
    #   -c       concurrency (parallel hosts)
    #   -rl      rate limit (req/s)
    #   -o       text output
    #   -jsonl   JSONL output for automation
    #   -silent  suppress banner
    #   -stats   show progress
    local findings_txt="${vulns_dir}/nuclei_findings.txt"
    local findings_json="${vulns_dir}/nuclei_findings.json"

    spinner_start "nuclei scanning for vulnerabilities…"
    nuclei \
        -l "${alive_urls}" \
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

    META_COUNTS[vuln_findings]="$(count_lines "${findings_txt}")"

    if [[ "${META_COUNTS[vuln_findings]}" -gt 0 ]]; then
        log_ok "${C_BRED}⚠  nuclei found ${META_COUNTS[vuln_findings]} potential vulnerabilities!${C_RESET}"
        echo ""
        log_info "=== Top findings (first 20) ==="
        head -n 20 "${findings_txt}" | while IFS= read -r line; do
            echo -e "  ${C_YELLOW}${line}${C_RESET}"
        done
        echo ""
    else
        log_info "Nuclei: No medium+ findings for the selected template tags."
    fi

    mark_done "vulnscan"
    notify_module "Vuln Scan" "✅ Completed" \
        "Hosts: ${url_count} | Findings: ${META_COUNTS[vuln_findings]}" \
        "$(elapsed_since "${t0}")"
    log_ok "Vuln Scan module finished.  [${C_DIM}$(elapsed_since "${t0}")${C_RESET}]"
}

# ══════════════════════════════════════════════════════════════════════════════
# §16 ─ RUN METADATA JSON REPORT
# ══════════════════════════════════════════════════════════════════════════════
#
# Writes a structured JSON file capturing the full run context:
#   - Script version & author
#   - Target domain
#   - Start / end timestamps + total elapsed time
#   - Exact asset counts for every module
#   - List of modules that were executed in this session
#
# Output file: recon_<domain>/run_metadata.json
# ──────────────────────────────────────────────────────────────────────────────
write_run_metadata() {
    local end_ts; end_ts="$(date +%s)"
    local end_human; end_human="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    local total_elapsed; total_elapsed="$(elapsed_since "${RUN_START_TS}")"
    local metadata_file="${OUTPUT_BASE_DIR}/run_metadata.json"

    # Build a comma-separated list of modules that ran in this session
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
    "unique_subdomains":  ${META_COUNTS[subdomains]},
    "open_ports":         ${META_COUNTS[ports]},
    "alive_hosts":        ${META_COUNTS[alive_hosts]},
    "screenshots":        ${META_COUNTS[screenshots]},
    "historical_urls":    ${META_COUNTS[historical_urls]},
    "js_files":           ${META_COUNTS[js_files]},
    "secrets_found":      ${META_COUNTS[secrets]},
    "hidden_params":      ${META_COUNTS[hidden_params]},
    "vuln_findings":      ${META_COUNTS[vuln_findings]},
    "fuzz_hits":          ${META_COUNTS[fuzz_hits]}
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

    printf "  ${C_BOLD}%-30s${C_RESET} ${C_BCYAN}%s${C_RESET}\n" \
        "Target:"         "${TARGET_DOMAIN}"
    printf "  ${C_BOLD}%-30s${C_RESET} ${C_BCYAN}%s${C_RESET}\n" \
        "Output Directory:" "${OUTPUT_BASE_DIR}/"
    printf "  ${C_BOLD}%-30s${C_RESET} ${C_BCYAN}%s${C_RESET}\n" \
        "Total Elapsed:"   "${total_elapsed}"
    echo ""

    # Asset count table
    local -A label_map=(
        [subdomains]="Unique Subdomains"
        [ports]="Open Ports (naabu)"
        [alive_hosts]="Alive HTTP Hosts"
        [screenshots]="Screenshots Taken"
        [historical_urls]="Historical URLs"
        [js_files]="JS Files Found"
        [secrets]="Secrets Detected"
        [hidden_params]="Hidden Parameters"
        [fuzz_hits]="Fuzzing Hits"
        [vuln_findings]="Vuln Findings"
    )

    local ordered_keys=(
        subdomains ports alive_hosts screenshots
        historical_urls js_files secrets hidden_params
        fuzz_hits vuln_findings
    )

    for key in "${ordered_keys[@]}"; do
        local val="${META_COUNTS[$key]}"
        local label="${label_map[$key]}"
        local colour="${C_CYAN}"

        # Highlight non-zero security findings in yellow/red
        if [[ "${key}" == "secrets" || "${key}" == "hidden_params" || \
              "${key}" == "vuln_findings" ]] && [[ "${val}" -gt 0 ]]; then
            colour="${C_BRED}"
        elif [[ "${val}" -gt 0 ]]; then
            colour="${C_BGREEN}"
        fi

        printf "  ${C_BOLD}%-30s${C_RESET} ${colour}%s${C_RESET}\n" \
            "${label}:" "${val}"
    done

    echo ""
    echo -e "${LOG_SEP}"
    log_ok "All selected modules completed. Stay legal, stay ethical. Happy hunting! 🎯"
    echo ""

    # Final rich notification summarising the entire run
    notify_module "Pipeline Complete" "✅ All modules finished" \
        "Subdomains: ${META_COUNTS[subdomains]} | Alive: ${META_COUNTS[alive_hosts]} | Vulns: ${META_COUNTS[vuln_findings]} | Secrets: ${META_COUNTS[secrets]}" \
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
    echo -e "  ${C_DIM}Author: ${C_BMAGENTA}${SCRIPT_AUTHOR}${C_RESET}  ${C_DIM}·  Passive · Active · Modular · Automated${C_RESET}"
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
  ${C_YELLOW}-r${C_RESET}            Passive Recon       Subdomain enum → dedup → httpx live filter
  ${C_YELLOW}-P${C_RESET}            Port Scan           naabu → discover non-standard web ports → httpx
  ${C_YELLOW}-s${C_RESET}            Screenshots         gowitness visual recon on alive hosts
  ${C_YELLOW}-f${C_RESET}            Fuzzing             ffuf directory fuzzing (requires -l)
  ${C_YELLOW}-u${C_RESET}            URL Discovery       gau + waybackurls historical URL harvest
  ${C_YELLOW}-j${C_RESET}            JS & Secrets        Extract JS URLs → trufflehog/nuclei secret scan
  ${C_YELLOW}-p${C_RESET}            Hidden Params       arjun GET/POST parameter discovery
  ${C_YELLOW}-v${C_RESET}            Vuln Scan           nuclei CVE/takeover/misconfig scanning
  ${C_YELLOW}-a${C_RESET}            All Modules         Full pipeline in dependency order

${C_BOLD}OPTIONS:${C_RESET}
  ${C_YELLOW}-l <wordlist>${C_RESET} Wordlist path       Required when using -f or -a
  ${C_YELLOW}-n${C_RESET}            Notify              Rich Telegram/Discord webhook on module completion
  ${C_YELLOW}-h${C_RESET}            Help                Show this screen

${C_BOLD}EXAMPLES:${C_RESET}
  ${C_CYAN}${SCRIPT_NAME} -d target.com -r -P${C_RESET}
    → Passive recon + port scan (discover non-standard web services)

  ${C_CYAN}${SCRIPT_NAME} -d target.com -r -u -j -n${C_RESET}
    → Recon + historical URLs + JS secret scan + notifications

  ${C_CYAN}${SCRIPT_NAME} -d target.com -a -l ~/wordlists/raft-large.txt -n${C_RESET}
    → Full pipeline with fuzzing and rich notifications

${C_BOLD}OUTPUT STRUCTURE:${C_RESET}
  recon_<domain>/
  ├── subdomains/    Raw + merged subdomain lists
  ├── ports/         naabu port scan results
  ├── urls/          Alive URL lists (standard + non-standard ports)
  ├── screenshots/   gowitness captures + sqlite DB
  ├── urldiscovery/  gau / waybackurls historical URLs
  ├── js/            JS URLs + trufflehog/nuclei secret findings
  ├── params/        arjun hidden parameter findings
  ├── fuzzing/       ffuf per-host JSON output
  ├── vulns/         nuclei findings (text + JSONL)
  └── run_metadata.json  Full run report (timestamps, counts, modules)

${C_BOLD}RESUME CAPABILITY:${C_RESET}
  If a module was completed in a previous run, the script will detect the
  completion stamp and ask whether to skip or re-run it. Non-interactive
  sessions auto-skip completed modules.

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

    # Option string explained:
    #   d: → takes argument (domain)
    #   l: → takes argument (wordlist)
    #   r P s f u j p v a n h → boolean flags
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

    # ── Post-parse validation ──────────────────────────────────────────────────
    [[ -z "${TARGET_DOMAIN}" ]] && \
        die "Target domain (-d) is required." 2

    validate_domain "${TARGET_DOMAIN}"

    # Fuzzing requires a wordlist — validate early before any disk work
    if [[ "${RUN_FUZZING}" -eq 1 && -z "${WORDLIST_FILE}" ]]; then
        die "The Fuzzing module (-f / -a) requires a wordlist. Provide one with -l <path>." 2
    fi

    # At least one module flag must be set
    local any_module=$(( RUN_RECON + RUN_PORTSCAN + RUN_SCREENSHOTS + \
                         RUN_FUZZING + RUN_URLDISCOVERY + RUN_JSSECRETS + \
                         RUN_HIDDENPARAMS + RUN_VULN ))
    if [[ "${any_module}" -eq 0 ]]; then
        die "No module selected. Use -r -P -s -f -u -j -p -v or -a. See -h for help." 2
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# §20 ─ MAIN ENTRYPOINT
# ══════════════════════════════════════════════════════════════════════════════
main() {
    parse_args "$@"
    print_banner

    # ── Print session header ───────────────────────────────────────────────────
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

    # ── Setup output directory tree ────────────────────────────────────────────
    setup_output_dirs

    # ── Module pipeline dispatch ───────────────────────────────────────────────
    # Dependency order: recon → portscan → screenshots → url_discovery
    #                   → js_secrets → hidden_params → fuzzing → vuln_scan
    #
    # Each module checks for its own prerequisite files and logs a warning
    # (not an error) if they're missing, allowing partial runs to work.

    [[ "${RUN_RECON}" -eq 1 ]]        && module_recon
    [[ "${RUN_PORTSCAN}" -eq 1 ]]     && module_portscan
    [[ "${RUN_SCREENSHOTS}" -eq 1 ]]  && module_screenshots
    [[ "${RUN_URLDISCOVERY}" -eq 1 ]] && module_url_discovery
    [[ "${RUN_JSSECRETS}" -eq 1 ]]    && module_js_secrets
    [[ "${RUN_HIDDENPARAMS}" -eq 1 ]] && module_hidden_params
    [[ "${RUN_FUZZING}" -eq 1 ]]      && module_fuzzing
    [[ "${RUN_VULN}" -eq 1 ]]         && module_vuln_scan

    # ── Finalise ───────────────────────────────────────────────────────────────
    write_run_metadata
    print_summary
}

# ══════════════════════════════════════════════════════════════════════════════
# GUARD: Prevent execution when sourced (allows unit-testing individual fns)
# ══════════════════════════════════════════════════════════════════════════════
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
