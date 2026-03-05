#!/usr/bin/env bash
# 
#  Android Bug Bounty Static Analyzer  v2.3
#  Kali Linux WSL2 Edition
#
#  Usage:
#    bash android_static_audit_v2.3.sh <target.apk>              # full audit
#    bash android_static_audit_v2.3.sh <new.apk> <old.apk>       # diff mode
#    bash android_static_audit_v2.3.sh --check-tools              # tool check only
#    bash android_static_audit_v2.3.sh <apk> --skip modules:X,Y  # skip modules
#    bash android_static_audit_v2.3.sh <apk> --resume            # reuse cache
#    bash android_static_audit_v2.3.sh <apk> --whitelist wl.txt  # suppress findings
#    bash android_static_audit_v2.3.sh <apk> --no-live           # skip net checks
#
#  All modules: metadata manifest secrets crypto webview storage intents
#               netconfig native firebase misc smali aidl contentprovider
#               backup rn flutter cordova semgrep apkid live
#
#  v2.1 Fixes & Additions:
#     FIX: Parallel race condition  each subshell writes its own shard,
#            merged atomically after all workers finish (no lost findings)
#     FIX: add_finding batched  no per-finding Python spawn overhead
#     FIX: grep --text flag to avoid binary file false negatives
#     NEW: APKiD packer/protector detection (silent false-clean prevention)
#     NEW: Semgrep OWASP Mobile Top 10 ruleset invocation
#     NEW: React Native bundle analysis (assets/index.android.bundle)
#     NEW: Flutter/Dart snapshot analysis (libflutter.so + strings)
#     NEW: Apache Cordova / Ionic analysis (assets/www/)
#     NEW: API-level context on exploitability (minSdk-aware findings)
#     NEW: MobSF REST integration (fully implemented)
#     NEW: SARIF output format (GitHub Code Scanning / Burp Enterprise)
#     NEW: FlowDroid inter-procedural taint analysis (v2.3)
#            multi-hop data flow: getIntent()  parseData()  rawQuery()
#            Android lifecycle-aware source/sink modelling
#            auto-download FlowDroid JAR + platform stubs
#            full taint path evidence with line numbers
# 

set -uo pipefail
export LC_ALL=C

#  Augment PATH so tools installed in common locations are always found 
# This ensures subshells (parallel modules) inherit the full PATH
for _p in \
    "${HOME}/jadx/bin" \
    "${HOME}/.local/bin" \
    "/opt/jadx/bin" \
    "/usr/local/bin" \
    "/usr/share/jadx/bin" \
    "${HOME}/.android_audit" \
    "/opt/ghidra/support"; do
    [ -d "$_p" ] && [[ ":$PATH:" != *":$_p:"* ]] && export PATH="$_p:$PATH"
done
export PATH

#  ANSI Colors 
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; RESET='\033[0m'

#  Global Config 
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_BASE="android_audit_${TIMESTAMP}"
REPORT_HTML="${REPORT_BASE}.html"
REPORT_JSON="${REPORT_BASE}.json"
REPORT_MD="${REPORT_BASE}.md"

WORK_DIR="/tmp/android_audit_${TIMESTAMP}"
CACHE_BASE="/tmp/android_audit_cache"
FINDINGS_JSON="${WORK_DIR}/findings.json"
SHARD_DIR="${WORK_DIR}/shards"       #  per-subshell finding shards (race-fix)
FINDING_COUNTER=0

REPORT_SARIF="${REPORT_BASE}.sarif"  #  new SARIF output

SKIP_MODULES=()
RESUME_MODE=false
DIFF_MODE=false
APK2=""
WHITELIST_FILE=""
DO_LIVE_CHECKS=true
MOBSF_URL="${MOBSF_URL:-http://localhost:8000}"
MOBSF_APIKEY="${MOBSF_APIKEY:-}"
MIN_SDK=0   # populated by mod_metadata, used for API-context on findings

# Parallel job tracking
declare -a BG_PIDS=()
declare -a BG_NAMES=()
PARALLEL_LOG="${WORK_DIR}/parallel"

MISSING_TOOLS=()

#  Banner 
banner() {
cat << 'BANNER'
  ___           _           _     _  
 / _ \  _ __  / \   _   _ __| |(_) |_ 
| | | || '_ \/ _ \ | | | |/ _` || || __|
| |_| || | | / ___ \| |_| | (_| || || |_ 
 \___/ |_| |_/_/   \_\\__,_|\__,_||_| \__|
  ____  _        _   _        _                   _
 / ___|| |_ __ _| |_(_) ___  / \   _ __   __ _| |_   _ _______ _ __
 \___ \| __/ _` | __| |/ __| / _ \ | '_ \ / _` | | | | |_  / _ \ '__|
  ___) | || (_| | |_| | (__ / ___ \| | | | (_| | | |_| |/ /  __/ |
 |____/ \__\__,_|\__|_|\___/_/   \_\_| |_|\__,_|_|\__, /___\___|_|
                                                   |___/  v2.0
BANNER
echo -e "  ${CYAN}Kali Linux WSL2  Android Bug Bounty Static Analysis Suite${RESET}\n"
}

#  Logging 
info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
fail()    { echo -e "${RED}[-]${RESET} $*"; }
section() {
    echo -e "\n${BOLD}${MAGENTA} $* ${RESET}"
    echo -e "${MAGENTA}$(printf '%.0s' $(seq 1 60))${RESET}"
}

#  Usage 
usage() {
    echo -e "Usage:"
    echo -e "  ${BOLD}bash $0 <apk>${RESET}                         Full audit"
    echo -e "  ${BOLD}bash $0 <new.apk> <old.apk>${RESET}           Diff mode"
    echo -e "  ${BOLD}bash $0 <apk> --resume${RESET}                Reuse cached decompile"
    echo -e "  ${BOLD}bash $0 <apk> --skip modules:X,Y${RESET}     Skip modules (e.g. crypto,webview)"
    echo -e "  ${BOLD}bash $0 <apk> --whitelist wl.txt${RESET}     Suppress exact title/category or regex rules"
    echo -e "  ${BOLD}bash $0 --check-tools${RESET}                 Tool check only"
    echo -e "\nAvailable modules: metadata manifest secrets crypto webview storage intents"
    echo -e "                   netconfig native firebase misc smali aidl contentprovider backup"
    exit 1
}

# 
# FINDINGS ENGINE
# 

refresh_runtime_paths() {
    FINDINGS_JSON="${WORK_DIR}/findings.json"
    SHARD_DIR="${WORK_DIR}/shards"
    PARALLEL_LOG="${WORK_DIR}/parallel"
}

init_findings() {
    refresh_runtime_paths
    mkdir -p "${WORK_DIR}" "${SHARD_DIR}" "${PARALLEL_LOG}"
    echo '[]' > "${FINDINGS_JSON}"
}

# 
# FAST MULTI-PATTERN SCANNER
# Reads each source file ONCE and applies ALL patterns simultaneously.
# 50-100x faster than N separate grep -rP calls on large codebases.
#
# Usage:
#   scan_source <src_dir> <shard_file> <category> <severity_default> \
#               "PAT1|TITLE1|SEV1|REM1" "PAT2|TITLE2|SEV2|REM2" ...
#
# Each pattern spec: "regex|finding_title|severity|remediation_key"
# 
scan_source() {
    local src_dir="$1"
    local shard_out="$2"
    shift 2
    local specs=("$@")

    [ ! -d "$src_dir" ] && return

    python3 - "$src_dir" "$shard_out" "${specs[@]}" << 'PYEOF'
import sys, os, re, json, glob

src_dir   = sys.argv[1]
shard_out = sys.argv[2]
specs     = sys.argv[3:]   # "regex|title|severity|rem_key"

# Parse specs
patterns = []
for spec in specs:
    parts = spec.split('|', 3)
    if len(parts) == 4:
        pat_str, title, sev, rem = parts
        try:
            patterns.append((re.compile(pat_str, re.IGNORECASE if pat_str.startswith('(?i)') else 0), title, sev, rem, pat_str))
        except re.error as e:
            print(f"  Bad pattern '{pat_str[:40]}': {e}", file=sys.stderr)

if not patterns:
    sys.exit(0)

# Collect all source files
EXTS = ('.java', '.kt', '.smali', '.xml', '.json', '.properties', '.gradle', '.js', '.html', '.ts')
SKIP_DIRS = {'test', 'androidtest', 'debug', 'mock', 'fixture', 'sample', 'example', '__test__'}

files = []
for root, dirs, filenames in os.walk(src_dir):
    # Prune test/debug directories
    dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
    for fn in filenames:
        if any(fn.endswith(e) for e in EXTS):
            files.append(os.path.join(root, fn))

# Match tracking: title  list of (file, line, snippet)
matches = {title: [] for _, title, _, _, _ in patterns}
MAX_EV = 5   # max evidence lines per finding

for fpath in files:
    fname = os.path.basename(fpath)
    rel   = os.path.relpath(fpath, src_dir)
    try:
        # Read file once
        content = open(fpath, encoding='utf-8', errors='replace').read()
    except:
        continue

    for compiled_pat, title, sev, rem, pat_str in patterns:
        if len(matches[title]) >= MAX_EV:
            continue
        m = compiled_pat.search(content)
        if m:
            # Find the line number
            line_no = content[:m.start()].count('\n') + 1
            # Get surrounding line for evidence
            lines = content.splitlines()
            snippet = lines[line_no-1].strip()[:120] if line_no <= len(lines) else m.group(0)[:120]
            matches[title].append(f"{rel}:{line_no}: {snippet}")

# Emit findings
findings = []
for compiled_pat, title, sev, rem, pat_str in patterns:
    hits = matches[title]
    if not hits:
        continue
    ev = '\n'.join(hits[:MAX_EV])
    cvss = {'CRITICAL':9.0,'HIGH':7.5,'MEDIUM':5.5,'LOW':3.0,'INFO':2.0}.get(sev, 5.0)
    findings.append(json.dumps({
        'severity':    sev,
        'category':    title.split(':')[0].strip() if ':' in title else title,
        'title':       title,
        'description': f'Pattern matched in source: {pat_str[:80]}',
        'evidence':    ev,
        'confidence':  'CONFIRMED',
        'cvss_score':  cvss,
        'remediation': rem
    }))

if findings:
    mode = 'a' if os.path.exists(shard_out) else 'w'
    with open(shard_out, mode) as f:
        f.write('\n'.join(findings) + '\n')

print(f"scan_source: {len(findings)} findings from {len(files)} files")
PYEOF
}

#  Shard-based add_finding 
# Each subshell writes to its own NDJSON shard file (no shared state).
# merge_shards() collects all shards into findings.json after workers finish.
# The main shell (sequential modules) writes directly to the shard dir too.
is_whitelisted() {
    # whitelist formats:
    #   Title
    #   Category|Title
    #   re:<regex>
    local cat="$1" title="$2"
    [ -z "${WHITELIST_FILE}" ] && return 1
    [ ! -f "${WHITELIST_FILE}" ] && return 1

    grep -qFx "$title" "${WHITELIST_FILE}" 2>/dev/null && return 0
    grep -qFx "${cat}|${title}" "${WHITELIST_FILE}" 2>/dev/null && return 0

    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" =~ ^re:(.+)$ ]] || continue
        local expr="${BASH_REMATCH[1]}"
        [[ "$title" =~ $expr ]] && return 0
        [[ "${cat}|${title}" =~ $expr ]] && return 0
    done < "${WHITELIST_FILE}"

    return 1
}

add_finding() {
    # add_finding <severity> <category> <title> <description> <evidence> <confidence> <remediation_key>
    local sev="$1" cat="$2" title="$3" desc="$4" evidence="$5"
    local conf="${6:-LIKELY}" rem_key="${7:-general}"

    refresh_runtime_paths
    mkdir -p "${SHARD_DIR}"

    # Deduplication across parallel workers: title+category fingerprint
    local dedup_hash
    dedup_hash=$(printf '%s|%s' "$title" "$cat" | md5sum | cut -c1-12)
    local dedup_lock="${SHARD_DIR}/.dedup_${dedup_hash}.lock"
    if ! mkdir "${dedup_lock}" 2>/dev/null; then
        return
    fi

    # Whitelist suppression (exact title, category|title, or regex)
    if is_whitelisted "$cat" "$title"; then
        info "Whitelisted: ${cat} | ${title}"
        return
    fi

    # Keep reports readable even when evidence is very large
    if [ "${#evidence}" -gt 6000 ]; then
        evidence="${evidence:0:5900}\n...[truncated]"
    fi

    local score
    score=$(cvss_score "$sev" "$conf")
    local remediation
    remediation=$(remediation_for "$rem_key")

    # Each process/subshell writes to its own shard (PID-namespaced)
    local shard="${SHARD_DIR}/shard_$$.ndjson"

    python3 -c "
import json, sys
entry = {
    'severity':    str(sys.argv[1]).upper(),
    'category':    sys.argv[2],
    'title':       sys.argv[3],
    'description': sys.argv[4],
    'evidence':    sys.argv[5],
    'confidence':  str(sys.argv[6]).upper(),
    'cvss_score':  float(sys.argv[7]),
    'remediation': sys.argv[8],
}
print(json.dumps(entry))
" "$sev" "$cat" "$title" "$desc" "$evidence" "$conf" "$score" "$remediation" >> "$shard"
}

merge_shards() {
    python3 - "${SHARD_DIR}" "${FINDINGS_JSON}" << 'PYEOF'
import sys, json, os, glob, re

shard_dir   = sys.argv[1]
output_path = sys.argv[2]

sev_rank = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
conf_rank = {'CONFIRMED': 3, 'LIKELY': 2, 'POSSIBLE': 1}

def norm_sev(v):
    v = str(v or 'INFO').upper()
    return v if v in sev_rank else 'INFO'

def norm_conf(v):
    v = str(v or 'LIKELY').upper()
    return v if v in conf_rank else 'LIKELY'

def clip_text(v, limit=5000):
    s = '' if v is None else str(v).strip()
    if len(s) > limit:
        return s[: limit - 15] + '\n...[truncated]'
    return s

def merge_evidence(old_ev, new_ev, max_lines=12):
    out = []
    for chunk in (old_ev, new_ev):
        for raw in str(chunk or '').splitlines():
            line = raw.strip()
            if not line or line in out:
                continue
            out.append(line)
            if len(out) >= max_lines:
                return '\n'.join(out)
    return '\n'.join(out)


def extract_locations(evidence, max_items=5):
    locs = []
    seen = set()
    for raw in str(evidence or '').splitlines():
        m = re.match(r'^(.+?):(\d+):', raw.strip())
        if not m:
            continue
        loc = f"{m.group(1)}:{m.group(2)}"
        if loc in seen:
            continue
        seen.add(loc)
        locs.append(loc)
        if len(locs) >= max_items:
            break
    return locs

def verify_steps_for(entry, title, category):
    t = f"{title} {category}".lower()
    evidence = clip_text(entry.get('evidence', ''), 5000)
    locs = extract_locations(evidence)

    loc_block = ''
    if locs:
        loc_block = "\n".join(f"   - {loc}" for loc in locs[:3])
    else:
        loc_block = "   - Use the Evidence block shown in this finding"

    if 'live: firebase' in t or 'firebase realtime db publicly readable' in t:
        return (
            "1. Run unauthenticated read request: `curl -i <firebase_url>/.json`.\n"
            "2. If response contains JSON data (not `null` and not an `error` object), treat as confirmed public read.\n"
            "3. If response contains `\"error\": \"Permission denied\"` or auth-related errors, do NOT treat as public.\n"
            "4. If response says database is disabled, classify as non-vulnerable/inactive endpoint, not exposure."
        )

    if 'debuggable' in t:
        return (
            "1. Decode the APK manifest with apktool and open `apktool_out/AndroidManifest.xml`.\n"
            "2. Locate `<application ... android:debuggable=\"true\">`.\n"
            "3. Confirm this is present in the release build variant (not only debug flavor).\n"
            "4. Install app on test device and run `adb shell run-as <package_name> id`; successful app-context shell confirms debuggable risk."
        )

    if 'allowbackup' in t or 'backup' in t:
        return (
            "1. Decode the APK and open `apktool_out/AndroidManifest.xml`.\n"
            "2. Confirm `<application ... android:allowBackup=\"true\">` or missing restrictive backup rules.\n"
            "3. On test device, run `adb shell bmgr backupnow <package_name>` (or equivalent backup flow) and verify app data can be requested.\n"
            "4. Confirm sensitive files (tokens/db/preferences) are included in backup set."
        )

    if 'cleartext' in t or 'network security config' in t:
        return (
            "1. Open manifest and verify `android:usesCleartextTraffic=\"true\"` or missing strict network config.\n"
            "2. Open referenced `network_security_config.xml` and confirm cleartext is permitted for base/domain config.\n"
            "3. Run app through a proxy and trigger API calls to an `http://` endpoint.\n"
            "4. Confirm request succeeds over plaintext (no TLS)."
        )

    if 'sql injection' in t:
        return (
            "1. Open the exact evidence location(s):\n"
            f"{loc_block}\n"
            "2. Confirm `rawQuery`/`execSQL` concatenates untrusted input (Intent extra, URI param, or user input).\n"
            "3. Trigger the component with payload like `' OR 1=1 --` via `adb shell am start ... --es <key> \"' OR 1=1 --\"`.\n"
            "4. Confirm altered query behavior, expanded result set, or SQL error indicating injection."
        )

    if 'path traversal' in t:
        return (
            "1. Open the exact evidence location(s):\n"
            f"{loc_block}\n"
            "2. Confirm file path is built from untrusted input (`getStringExtra`, URI segment, web input).\n"
            "3. Provide `../` traversal payload to the same entry point.\n"
            "4. Confirm file access escapes the intended directory boundary."
        )

    if 'command injection' in t or 'runtime.exec' in t:
        return (
            "1. Open the exact evidence location(s):\n"
            f"{loc_block}\n"
            "2. Confirm untrusted input reaches `Runtime.exec`, `ProcessBuilder`, or shell wrapper.\n"
            "3. Pass a controlled argument containing shell metacharacters to the same sink path.\n"
            "4. Confirm unintended command execution or argument injection in logs/output."
        )

    if 'javascriptinterface' in t or 'webview' in t:
        return (
            "1. Open the exact evidence location(s):\n"
            f"{loc_block}\n"
            "2. Confirm insecure WebView setting (`setJavaScriptEnabled(true)`, `addJavascriptInterface`, file URL access, or TLS bypass).\n"
            "3. Trace whether content source is attacker-influenced (deep link, Intent, remote URL).\n"
            "4. Reproduce by loading controlled content and confirm Java bridge/script execution or policy bypass."
        )

    if 'hardcoded' in t or 'secret' in t or 'credential' in t or 'api key' in t:
        return (
            "1. Open the exact evidence location(s):\n"
            f"{loc_block}\n"
            "2. Confirm the secret/token/key literal is hardcoded (not test fixture).\n"
            "3. Decode/normalize if obfuscated (base64/hex/xor) and validate full value.\n"
            "4. Test key/token in the intended service scope and confirm it is active."
        )

    if 'ecb' in t or 'md5' in t or 'sha-1' in t or 'des' in t or 'trustmanager' in t or 'hostnameverifier' in t:
        return (
            "1. Open the exact evidence location(s):\n"
            f"{loc_block}\n"
            "2. Confirm insecure crypto/TLS primitive is actually used in reachable runtime code.\n"
            "3. Trace call path from entry point to sink to rule out dead code/test stubs.\n"
            "4. Run a controlled test case to observe weak algorithm/TLS bypass behavior."
        )

    return (
        "1. Open the exact evidence location(s) listed below:\n"
        f"{loc_block}\n"
        "2. Confirm the vulnerable API/pattern appears exactly as reported.\n"
        "3. Trace one caller upstream and one callee downstream to confirm attacker-controllable input can reach this code path.\n"
        "4. Reproduce on a test device/emulator with controlled input and verify the security impact described in this finding."
    )
def infer_cwe(title, category):
    t = f"{title} {category}".lower()
    rules = [
        ('sql injection', 'CWE-89'),
        ('path traversal', 'CWE-22'),
        ('open redirect', 'CWE-601'),
        ('command injection', 'CWE-78'),
        ('deserialization', 'CWE-502'),
        ('hardcoded', 'CWE-798'),
        ('secret', 'CWE-798'),
        ('credential', 'CWE-798'),
        ('private key', 'CWE-321'),
        ('ecb', 'CWE-327'),
        ('md5', 'CWE-327'),
        ('sha-1', 'CWE-327'),
        ('des cipher', 'CWE-327'),
        ('3des', 'CWE-327'),
        ('trustmanager', 'CWE-295'),
        ('hostnameverifier', 'CWE-295'),
        ('ssl error', 'CWE-295'),
        ('cleartext', 'CWE-319'),
        ('debuggable', 'CWE-489'),
        ('allowbackup', 'CWE-530'),
        ('world-readable', 'CWE-922'),
        ('world-writeable', 'CWE-922'),
        ('pendingintent', 'CWE-927'),
        ('javascriptinterface', 'CWE-749'),
        ('exported component', 'CWE-926'),
    ]
    for needle, cwe in rules:
        if needle in t:
            return cwe
    return 'CWE-693'

merged = {}
shard_files = sorted(glob.glob(os.path.join(shard_dir, 'shard_*.ndjson')))

for shard_file in shard_files:
    try:
        with open(shard_file, encoding='utf-8', errors='replace') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                title = clip_text(entry.get('title', ''), 300)
                category = clip_text(entry.get('category', 'General'), 160)
                if not title:
                    continue

                sev = norm_sev(entry.get('severity'))
                conf = norm_conf(entry.get('confidence'))
                try:
                    cvss = float(entry.get('cvss_score', 0) or 0)
                except Exception:
                    cvss = 0.0

                key = f"{title}|{category}"
                incoming = {
                    'severity': sev,
                    'category': category,
                    'title': title,
                    'description': clip_text(entry.get('description', ''), 2000),
                    'evidence': clip_text(entry.get('evidence', ''), 5000),
                    'confidence': conf,
                    'cvss_score': round(max(0.0, cvss), 1),
                    'remediation': clip_text(entry.get('remediation', ''), 2000),
                    'cwe': clip_text(entry.get('cwe', ''), 40) or infer_cwe(title, category),
                    'steps_to_verify': clip_text(entry.get('steps_to_verify', ''), 3000),
                }

                if not incoming['steps_to_verify']:
                    incoming['steps_to_verify'] = verify_steps_for(incoming, title, category)

                if key not in merged:
                    merged[key] = incoming
                    continue

                cur = merged[key]
                if sev_rank[incoming['severity']] > sev_rank[cur['severity']]:
                    cur['severity'] = incoming['severity']
                if conf_rank[incoming['confidence']] > conf_rank[cur['confidence']]:
                    cur['confidence'] = incoming['confidence']
                if incoming['cvss_score'] > cur['cvss_score']:
                    cur['cvss_score'] = incoming['cvss_score']

                if len(incoming['description']) > len(cur['description']):
                    cur['description'] = incoming['description']
                if len(incoming['remediation']) > len(cur['remediation']):
                    cur['remediation'] = incoming['remediation']
                if len(incoming.get('steps_to_verify', '')) > len(cur.get('steps_to_verify', '')):
                    cur['steps_to_verify'] = incoming.get('steps_to_verify', '')

                cur['evidence'] = merge_evidence(cur.get('evidence', ''), incoming.get('evidence', ''))
                if not cur.get('cwe'):
                    cur['cwe'] = incoming['cwe']
                if not cur.get('steps_to_verify'):
                    cur['steps_to_verify'] = verify_steps_for(cur, cur.get('title', ''), cur.get('category', ''))
    except OSError:
        continue

findings = list(merged.values())
findings.sort(key=lambda x: (-sev_rank.get(x.get('severity', 'INFO'), 0), -x.get('cvss_score', 0), x.get('title', '').lower()))

for i, item in enumerate(findings, 1):
    item['id'] = i

with open(output_path, 'w', encoding='utf-8') as out:
    json.dump(findings, out, indent=2)

print(f"Merged {len(findings)} unique findings from {len(shard_files)} shards")
PYEOF
}

cvss_score() {
    local sev="$1" conf="$2"
    local base
    case "$sev" in
        CRITICAL) base=9.0 ;;
        HIGH)     base=7.0 ;;
        MEDIUM)   base=5.0 ;;
        LOW)      base=3.0 ;;
        INFO)     base=1.0 ;;
        *)        base=1.0 ;;
    esac
    # Confidence modifier
    case "$conf" in
        CONFIRMED) echo "$base" ;;
        LIKELY)    python3 -c "import sys; print(round(float(sys.argv[1]) * 0.85, 1))" "$base" ;;
        POSSIBLE)  python3 -c "import sys; print(round(float(sys.argv[1]) * 0.65, 1))" "$base" ;;
        *)         echo "$base" ;;
    esac
}

# Remediation library  maps finding type key  remediation text
remediation_for() {
    local key="$1"
    case "$key" in
        "debuggable")
            echo "Remove android:debuggable=\"true\" from your <application> tag in AndroidManifest.xml. In build.gradle, ensure release builds have debuggable false set in the release buildType." ;;
        "allowBackup")
            echo "Set android:allowBackup=\"false\" or define android:fullBackupContent / android:dataExtractionRules XML to explicitly exclude sensitive files (databases, SharedPreferences, tokens) from backup." ;;
        "cleartext")
            echo "Set android:usesCleartextTraffic=\"false\" in your manifest or add a network_security_config.xml with <base-config cleartextTrafficPermitted=\"false\">. Migrate all endpoints to HTTPS." ;;
        "debugCert")
            echo "Re-sign the APK with a production keystore using jarsigner or apksigner. Never publish APKs signed with the Android debug keystore (androiddebugkey)." ;;
        "weakKey")
            echo "Generate a new signing key with at least 2048-bit RSA or 256-bit EC: keytool -genkeypair -keyalg RSA -keysize 2048 -sigalg SHA256withRSA" ;;
        "exported_activity")
            echo "Add android:exported=\"false\" to the Activity if it does not need to be accessed by other apps. If it must be exported, add android:permission with a signature-level protectionLevel to restrict callers." ;;
        "exported_service")
            echo "Add android:exported=\"false\" to the Service if inter-app access is not required. For bound services, validate Binder.getCallingUid() inside onBind() and all AIDL method implementations." ;;
        "exported_receiver")
            echo "Add android:exported=\"false\" or set android:permission to restrict which apps can send broadcasts. For dynamically registered receivers, pass RECEIVER_NOT_EXPORTED flag on API 33+." ;;
        "exported_provider")
            echo "Set android:exported=\"false\" on the ContentProvider if not needed externally, or add android:readPermission and android:writePermission at signature level. Implement parameterized queries to prevent SQL injection." ;;
        "implicit_export")
            echo "Explicitly set android:exported=\"true\" or \"false\" on all components that declare intent-filters. Since Android 12 (API 31), components with intent-filters must explicitly declare exported status or the build will fail." ;;
        "aes_ecb")
            echo "Replace AES/ECB with AES/GCM/NoPadding (authenticated encryption) or AES/CBC/PKCS7Padding with a random IV. Never reuse IVs. Example: Cipher.getInstance(\"AES/GCM/NoPadding\")" ;;
        "des_cipher")
            echo "Replace DES/3DES with AES-256-GCM. DES has an effective key size of 56 bits and is trivially brute-forceable. 3DES is also deprecated per NIST SP 800-131A." ;;
        "md5_sha1")
            echo "Replace MD5/SHA-1 with SHA-256 or better (SHA-3). For passwords, use a proper KDF: PBKDF2WithHmacSHA256, bcrypt, or Argon2 with at least 100,000 iterations." ;;
        "static_iv")
            echo "Generate a cryptographically random IV for every encryption operation: byte[] iv = new byte[12]; new SecureRandom().nextBytes(iv); Prepend the IV to the ciphertext so it can be retrieved for decryption." ;;
        "trust_all_certs")
            echo "Remove the empty checkServerTrusted() override. Use the default SSLContext or implement real certificate pinning via network_security_config.xml <pin-set> with backup pins. Consider using OkHttp's CertificatePinner." ;;
        "no_pinning")
            echo "Implement certificate pinning in network_security_config.xml: <pin-set expiration=\"2026-01-01\"><pin digest=\"SHA-256\">BASE64_HASH</pin></pin-set>. Always include at least one backup pin. Use tools like ssl-pin-scraper to extract current pins." ;;
        "js_enabled")
            echo "Disable JavaScript in WebViews that do not require it: webView.getSettings().setJavaScriptEnabled(false). If JS is required, load only trusted content over HTTPS and validate all URLs before loading." ;;
        "js_interface")
            echo "Annotate all @JavascriptInterface methods carefully  they are callable from any page loaded in the WebView. Restrict what URLs can load in the WebView, validate all input, and avoid passing sensitive data back to JS." ;;
        "file_access_universal")
            echo "Set webView.getSettings().setAllowUniversalAccessFromFileURLs(false) and setAllowFileAccessFromFileURLs(false). These settings allow file:// pages to read arbitrary local files, enabling data exfiltration." ;;
        "ssl_error_proceed")
            echo "Never call handler.proceed() in onReceivedSslError() unconditionally. Show the user an error or cancel the request. If you must proceed for testing, restrict it to debug builds only." ;;
        "external_storage")
            echo "Store sensitive files in internal storage using Context.getFilesDir() or Context.getDataDir() instead of getExternalStorageDirectory(). For sharing files with other apps, use FileProvider with explicit permissions." ;;
        "world_readable")
            echo "Replace MODE_WORLD_READABLE/MODE_WORLD_WRITEABLE with MODE_PRIVATE (value 0). World-readable files are accessible to any app on the device. Use FileProvider for controlled sharing." ;;
        "log_sensitive")
            echo "Remove all Log.d/v/i/e/w calls that print passwords, tokens, or PII. Use ProGuard/R8 rules to strip logging in release builds: -assumenosideeffects class android.util.Log { public static *** d(...); }" ;;
        "sql_injection")
            echo "Use parameterized queries exclusively: db.query(table, cols, \"id=?\", new String[]{id}, ...) Never concatenate user input into SQL strings. For ContentProviders, validate and sanitize the selection parameter." ;;
        "zip_slip")
            echo "Validate each ZipEntry name before extraction: if (entry.getName().contains(\"..\")) throw new SecurityException(). Use a canonical path check: if (!destFile.getCanonicalPath().startsWith(destDir.getCanonicalPath())) throw..." ;;
        "mutable_pending_intent")
            echo "Use FLAG_IMMUTABLE when creating PendingIntents (required for API 31+): PendingIntent.getActivity(ctx, 0, intent, PendingIntent.FLAG_IMMUTABLE). Only use FLAG_MUTABLE if you explicitly need the intent to be modified." ;;
        "firebase_public")
            echo "Secure your Firebase Realtime Database rules: { \"rules\": { \".read\": \"auth != null\", \".write\": \"auth != null\" } }. Deploy rules via Firebase CLI: firebase deploy --only database. Audit rules at console.firebase.google.com." ;;
        "aws_key")
            echo "Rotate the exposed AWS key immediately via IAM console. Never hardcode credentials in source. Use IAM roles for EC2/Lambda, environment variables for servers, or AWS Secrets Manager. Add git-secrets to prevent future commits." ;;
        "google_api_key")
            echo "Restrict the API key in Google Cloud Console: add HTTP referrer restrictions or Android app restrictions (package name + SHA-1). Rotate the key and store it server-side, fetching it at runtime via an authenticated endpoint." ;;
        "unsafe_deserialization")
            echo "Avoid Java ObjectInputStream deserialization of untrusted data. Use safer alternatives: JSON (Gson/Moshi), Protobuf, or Parcelable. If deserialization is required, implement a SerialFilter (Java 9+) to whitelist allowed classes." ;;
        "backup_sensitive")
            echo "Define a dataExtractionRules.xml (API 31+) or fullBackupContent.xml (API 30-) to explicitly exclude sensitive paths: <exclude domain=\"database\" path=\"secrets.db\"/><exclude domain=\"sharedpref\" path=\"tokens.xml\"/>" ;;
        "aidl_no_permission")
            echo "Add caller verification in all AIDL stub implementations: int uid = Binder.getCallingUid(); if (ctx.checkPermission(MY_PERMISSION, -1, uid) != PERMISSION_GRANTED) throw new SecurityException(\"Unauthorized\");" ;;
        *)
            echo "Review the finding in context and apply the principle of least privilege. Consult OWASP Mobile Security Testing Guide (MSTG) and Android Security Best Practices at developer.android.com/topic/security/best-practices." ;;
    esac
}

check_tools() {
    section "TOOL AVAILABILITY CHECK"
    declare -A TOOLS=(
        ["apktool"]="apktool"
        ["jadx"]="jadx"
        ["adb"]="adb"
        ["java"]="java"
        ["python3"]="python3"
        ["strings"]="strings"
        ["grep"]="grep"
        ["aapt"]="aapt"
        ["keytool"]="keytool"
        ["readelf"]="readelf"
        ["nm"]="nm"
        ["objdump"]="objdump"
        ["file"]="file"
        ["unzip"]="unzip"
        ["curl"]="curl"
        ["timeout"]="timeout"
        ["apkleaks"]="apkleaks"
        ["semgrep"]="semgrep"
        ["trufflehog"]="trufflehog"
        ["apkid"]="apkid"
        ["node"]="node"
        ["md5sum"]="md5sum"
        ["jq"]="jq"
    )
    printf "\n%-42s %s\n" "TOOL" "STATUS"
    printf "%-42s %s\n" "" ""
    for name in "${!TOOLS[@]}"; do
        cmd="${TOOLS[$name]}"
        if command -v "$cmd" &>/dev/null; then
            printf "%-42s ${GREEN} FOUND${RESET}\n" "$name"
        else
            printf "%-42s ${RED} MISSING${RESET}\n" "$name"
            MISSING_TOOLS+=("$name")
        fi
    done

    # FlowDroid JAR (not a system command  check file path)
    local FD_JAR="${HOME}/.android_audit/flowdroid/soot-infoflow-cmd.jar"
    if [ -f "$FD_JAR" ]; then
        printf "%-42s ${GREEN} FOUND${RESET}\n" "FlowDroid JAR"
    else
        printf "%-42s ${YELLOW} AUTO-DOWNLOAD${RESET}\n" "FlowDroid JAR"
    fi

    # Optional fallback decompiler tooling
    if command -v d2j-dex2jar >/dev/null 2>&1 || command -v dex2jar >/dev/null 2>&1; then
        printf "%-42s ${GREEN} FOUND${RESET}\n" "dex2jar (fallback decompiler)"
    else
        printf "%-42s ${YELLOW} OPTIONAL${RESET}\n" "dex2jar (install package: dex2jar)"
    fi
    local CFR_FALLBACK_JAR="${CFR_JAR:-${HOME}/.android_audit/tools/cfr.jar}"
    if [ -f "$CFR_FALLBACK_JAR" ]; then
        printf "%-42s ${GREEN} FOUND${RESET}\n" "CFR JAR (fallback decompiler)"
    else
        printf "%-42s ${YELLOW} OPTIONAL${RESET}\n" "CFR JAR (set CFR_JAR)"
    fi
    echo ""
    if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
        warn "Missing tools. Install with:"
        echo -e "  ${BOLD}sudo apt update && sudo apt install -y apktool adb default-jdk binutils unzip curl file jq nodejs npm${RESET}"
        echo -e "  ${BOLD}pip3 install apkleaks semgrep apkid${RESET}"
        echo -e "  ${BOLD}curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin${RESET}"
        echo -e "  ${BOLD}wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.5.0.zip && unzip jadx-1.5.0.zip -d ~/jadx && sudo ln -sf ~/jadx/bin/jadx /usr/local/bin/jadx${RESET}"
    else
        success "All tools present!"
    fi
}

tool_ok() { command -v "$1" &>/dev/null; }

# Returns a note about API-level exploitability context
api_context() {
    # api_context <min_threshold> <description_of_risk>
    local threshold="$1" risk="$2"
    local min_sdk=0
    [ -f "${WORK_DIR}/min_sdk.txt" ] && min_sdk=$(cat "${WORK_DIR}/min_sdk.txt")
    if [[ "$min_sdk" =~ ^[0-9]+$ ]] && [ "$min_sdk" -ge "$threshold" ] 2>/dev/null; then
        echo " [API-context: mitigated on API${threshold}  but app supports API${min_sdk}+, so ${risk}]"
    else
        echo " [API-context: exploitable on all supported API levels including minSdk=${min_sdk}]"
    fi
}

# 
# EXTRACTION  with cache/resume support
# 
extract_apk() {
    local apk="$1"
    section "APK EXTRACTION"

    mkdir -p "${WORK_DIR}" "${WORK_DIR}/parallel"
    cp "$apk" "${WORK_DIR}/target.apk"

    # Compute APK hash for cache key
    local apk_hash
    apk_hash=$(md5sum "$apk" | cut -c1-16)
    local cache_dir="${CACHE_BASE}/${apk_hash}"

    # Validate cache: must have decoded AndroidManifest.xml AND at least some Java files
    cache_valid() {
        local cd="$1"
        [ -d "$cd/apktool_out" ] || return 1
        [ -d "$cd/jadx_out" ]    || return 1
        # Manifest must exist at root level (not in original/ subdir) and be decoded XML
        local mf="$cd/apktool_out/AndroidManifest.xml"
        [ -f "$mf" ] || return 1
        head -c 10 "$mf" | grep -q '<?xml\|<mani' || return 1
        # jadx_out must have at least one Java file (not an empty dir from a failed run)
        find "$cd/jadx_out" -name "*.java" -quit 2>/dev/null | grep -q . || return 1
        return 0
    }

    if [ "$RESUME_MODE" = true ] && cache_valid "$cache_dir"; then
        success "Resuming from valid cache: $cache_dir"
        ln -sf "${cache_dir}/apktool_out" "${WORK_DIR}/apktool_out"
        ln -sf "${cache_dir}/jadx_out"    "${WORK_DIR}/jadx_out"
        ln -sf "${cache_dir}/raw"         "${WORK_DIR}/raw"
        return
    elif [ -d "$cache_dir" ] && ! cache_valid "$cache_dir"; then
        warn "Stale/invalid cache found at $cache_dir  removing and re-decompiling"
        rm -rf "$cache_dir"
    fi

    mkdir -p "${WORK_DIR}/apktool_out" "${WORK_DIR}/jadx_out" "${WORK_DIR}/raw"

    # Raw unzip (fast, always do it)
    info "Unzipping APK..."
    unzip -q "${WORK_DIR}/target.apk" -d "${WORK_DIR}/raw" 2>/dev/null || true

    # Resolve jadx binary  check PATH, then common install locations
    local jadx_bin="jadx"
    if ! command -v jadx &>/dev/null; then
        for p in "${HOME}/jadx/bin/jadx" \
                  "/opt/jadx/bin/jadx" \
                  "/usr/local/bin/jadx" \
                  "/usr/share/jadx/bin/jadx"; do
            if [ -x "$p" ]; then jadx_bin="$p"; break; fi
        done
        if [ "$jadx_bin" = "jadx" ]; then
            warn "jadx not found in PATH or common locations  decompilation will be skipped"
            warn "Install: wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.5.0.zip && unzip jadx-1.5.0.zip -d ~/jadx && sudo ln -sf ~/jadx/bin/jadx /usr/local/bin/jadx"
        fi
    fi

    # Optional fallback decompiler: dex2jar + CFR
    # Used only when JADX yields zero Java files.
    fallback_decompile_dex2jar_cfr() {
        local apk_path="$1"
        local out_dir="$2"
        local fallback_log="${WORK_DIR}/parallel/fallback_decompiler.log"
        local cfr_jar="${CFR_JAR:-${HOME}/.android_audit/tools/cfr.jar}"
        local dex2jar_bin=""

        if command -v d2j-dex2jar >/dev/null 2>&1; then
            dex2jar_bin="d2j-dex2jar"
        elif command -v dex2jar >/dev/null 2>&1; then
            dex2jar_bin="dex2jar"
        else
            echo "fallback:skip:no_dex2jar" > "$fallback_log"
            return 1
        fi

        if [ ! -f "$cfr_jar" ]; then
            echo "fallback:skip:no_cfr_jar:$cfr_jar" > "$fallback_log"
            return 1
        fi

        mkdir -p "${out_dir}/sources_fallback"
        local jar_out="${WORK_DIR}/fallback_classes.jar"

        {
            echo "fallback:start:dex2jar+cfr"
            timeout 240 "$dex2jar_bin" "$apk_path" -o "$jar_out" -f
            local d2j_rc=$?
            echo "fallback:dex2jar_rc:${d2j_rc}"
            if [ "$d2j_rc" -ne 0 ] || [ ! -s "$jar_out" ]; then
                echo "fallback:fail:dex2jar"
                return 1
            fi

            timeout 300 java -jar "$cfr_jar" "$jar_out" --outputdir "${out_dir}/sources_fallback"
            local cfr_rc=$?
            echo "fallback:cfr_rc:${cfr_rc}"
            [ "$cfr_rc" -eq 0 ] && echo "fallback:ok" || echo "fallback:fail:cfr"
        } > "$fallback_log" 2>&1

        local fb_count
        fb_count=$(find "${out_dir}/sources_fallback" -name "*.java" 2>/dev/null | wc -l)
        [ "$fb_count" -gt 0 ] || return 1
        return 0
    }
    # apktool + jadx in parallel with timeout guards
    info "Starting apktool + jadx in parallel..."

    ( timeout 180 apktool d -f -o "${WORK_DIR}/apktool_out" "${WORK_DIR}/target.apk" \
        --no-src 2>/dev/null \
        && echo "apktool:ok" || echo "apktool:fail" ) > "${WORK_DIR}/parallel/apktool.log" 2>&1 &
    BG_PIDS+=($!) ; BG_NAMES+=("apktool")

    ( timeout 300 "$jadx_bin" --output-dir "${WORK_DIR}/jadx_out" \
        --show-bad-code --no-res \
        "${WORK_DIR}/target.apk" 2>/dev/null \
        && echo "jadx:ok" || echo "jadx:fail" ) > "${WORK_DIR}/parallel/jadx.log" 2>&1 &
    BG_PIDS+=($!) ; BG_NAMES+=("jadx")

    wait_parallel "apktool + jadx decompilation"
    # Evaluate decompilation quality
    local java_count
    java_count=$(find "${WORK_DIR}/jadx_out" -name "*.java" 2>/dev/null | wc -l)
    local jadx_err_count=0
    if [ -f "${WORK_DIR}/parallel/jadx.log" ]; then
        jadx_err_count=$(grep -oE 'count:[[:space:]]*[0-9]+' "${WORK_DIR}/parallel/jadx.log" 2>/dev/null | tail -1 | grep -oE '[0-9]+' || echo 0)
    fi

    if grep -q "jadx:fail" "${WORK_DIR}/parallel/jadx.log" 2>/dev/null; then
        if [ "$java_count" -gt 0 ]; then
            warn "jadx reported errors ($jadx_err_count) but produced $java_count Java files  continuing with PARTIAL source coverage"
            echo "PARTIAL" > "${WORK_DIR}/decomp_status.txt"
            echo "$java_count" > "${WORK_DIR}/decomp_java_count.txt"
            echo "$jadx_err_count" > "${WORK_DIR}/decomp_jadx_errors.txt"
        else
            warn "jadx decompilation failed with no Java output  attempting fallback (dex2jar + CFR)"
            if fallback_decompile_dex2jar_cfr "${WORK_DIR}/target.apk" "${WORK_DIR}/jadx_out"; then
                local fb_java_count
                fb_java_count=$(find "${WORK_DIR}/jadx_out/sources_fallback" -name "*.java" 2>/dev/null | wc -l)
                warn "Fallback decompilation succeeded with $fb_java_count Java files (coverage may still be partial)"
                echo "PARTIAL_FALLBACK" > "${WORK_DIR}/decomp_status.txt"
                echo "$fb_java_count" > "${WORK_DIR}/decomp_java_count.txt"
                echo "$jadx_err_count" > "${WORK_DIR}/decomp_jadx_errors.txt"
                java_count=$fb_java_count
            else
                warn "Fallback decompiler unavailable/failed. Install d2j-dex2jar and CFR jar for best coverage."
                echo "FAILED" > "${WORK_DIR}/decomp_status.txt"
                echo "0" > "${WORK_DIR}/decomp_java_count.txt"
                echo "$jadx_err_count" > "${WORK_DIR}/decomp_jadx_errors.txt"
            fi
        fi
    else
        echo "OK" > "${WORK_DIR}/decomp_status.txt"
        echo "$java_count" > "${WORK_DIR}/decomp_java_count.txt"
        echo "$jadx_err_count" > "${WORK_DIR}/decomp_jadx_errors.txt"
        info "jadx completed successfully with $java_count Java files"
    fi

    grep -q "apktool:fail" "${WORK_DIR}/parallel/apktool.log" 2>/dev/null && \
        warn "apktool decompilation failed  manifest analysis will be limited"

    # Only cache if we got usable output (java files + decoded manifest)
    local manifest_ok=false
    [ -f "${WORK_DIR}/apktool_out/AndroidManifest.xml" ] && \
        head -c 10 "${WORK_DIR}/apktool_out/AndroidManifest.xml" | grep -q '<?xml\|<mani' && \
        manifest_ok=true

    if [ "$java_count" -gt 0 ] && [ "$manifest_ok" = true ]; then
        if [ ! -d "$cache_dir" ]; then
            mkdir -p "${CACHE_BASE}"
            cp -r "${WORK_DIR}/apktool_out" "${WORK_DIR}/jadx_out" "${WORK_DIR}/raw" "${cache_dir}/" 2>/dev/null || true
            info "Cached decompile to: $cache_dir ($java_count Java files)"
        fi
    else
        warn "Decompilation output incomplete (java: $java_count, manifest: $manifest_ok)  not caching"
        [ "$java_count" -eq 0 ] && warn "No Java files recovered. Check JADX/CFR fallback prerequisites."
    fi

    success "Extraction complete"
}

# Wait for all background jobs
wait_parallel() {
    local label="${1:-background jobs}"
    info "Waiting for: $label"
    local failed=0
    for i in "${!BG_PIDS[@]}"; do
        pid="${BG_PIDS[$i]}"
        name="${BG_NAMES[$i]}"
        if wait "$pid" 2>/dev/null; then
            success "$name complete"
        else
            warn "$name exited non-zero (may be partial output)"
            failed=$((failed+1))
        fi
    done
    BG_PIDS=()
    BG_NAMES=()
}

# 
# MODULE: METADATA
# 
mod_metadata() {
    section "METADATA & SIGNATURE"
    local apk="${WORK_DIR}/target.apk"

    # Decompilation quality context (populated by extract_apk)
    local decomp_status="UNKNOWN" decomp_java="0" decomp_errs="0"
    [ -f "${WORK_DIR}/decomp_status.txt" ] && decomp_status=$(cat "${WORK_DIR}/decomp_status.txt")
    [ -f "${WORK_DIR}/decomp_java_count.txt" ] && decomp_java=$(cat "${WORK_DIR}/decomp_java_count.txt")
    [ -f "${WORK_DIR}/decomp_jadx_errors.txt" ] && decomp_errs=$(cat "${WORK_DIR}/decomp_jadx_errors.txt")

    case "$decomp_status" in
        OK)
            info "Decompiler status: OK ($decomp_java Java files)" ;;
        PARTIAL|PARTIAL_FALLBACK)
            warn "Decompiler status: $decomp_status ($decomp_java Java files, JADX errors: $decomp_errs)"
            add_finding "INFO" "Decompiler" "Partial Java Decompilation" \
                "JADX reported parse/decode errors but usable Java source was recovered. Static findings are valid but some code paths may be missing." \
                "status=$decomp_status java_files=$decomp_java jadx_errors=$decomp_errs" "CONFIRMED" "general" ;;
        FAILED)
            warn "Decompiler status: FAILED (no Java sources recovered)"
            add_finding "MEDIUM" "Decompiler" "Java Decompilation Failed" \
                "No Java source was recovered from JADX or fallback decompiler. Source-based modules will have significantly reduced coverage." \
                "status=$decomp_status java_files=$decomp_java jadx_errors=$decomp_errs" "CONFIRMED" "general" ;;
        *)
            warn "Decompiler status unavailable; proceeding with best effort" ;;
    esac

    # Certificate
    if tool_ok keytool && tool_ok unzip; then
        local cert_file
        cert_file=$(unzip -l "$apk" 2>/dev/null | grep -oE 'META-INF/.*\.(RSA|DSA|EC)' | head -1 || true)
        if [ -n "$cert_file" ]; then
            local cert_info
            cert_info=$(unzip -p "$apk" "$cert_file" 2>/dev/null | keytool -printcert 2>/dev/null || echo "")
            if echo "$cert_info" | grep -qi "android debug\|androiddebugkey"; then
                add_finding "CRITICAL" "Metadata" "Debug Certificate in Production APK" \
                    "The APK is signed with the Android debug keystore. Debug-signed APKs expose the app to cloning and tampering attacks as the debug key is publicly known." \
                    "$cert_info" "CONFIRMED" "debugCert"
            fi
            if echo "$cert_info" | grep -qE "1024"; then
                add_finding "HIGH" "Metadata" "Weak Signing Key (1024-bit)" \
                    "The signing certificate uses a 1024-bit key, considered cryptographically weak by modern standards (NIST deprecated 1024-bit RSA in 2013)." \
                    "$(echo "$cert_info" | grep -i 'key\|algorithm')" "CONFIRMED" "weakKey"
            fi
        fi
    fi

    # aapt metadata
    if tool_ok aapt; then
        local aapt_out
        aapt_out=$(timeout 30 aapt dump badging "${WORK_DIR}/target.apk" 2>/dev/null || echo "")
        local pkg min_sdk tgt_sdk
        pkg=$(echo "$aapt_out"     | grep -oP "package: name='\K[^']+" | head -1 || echo "unknown")
        min_sdk=$(echo "$aapt_out" | grep -oP "minSdkVersion:'\K[^']+" | head -1 || echo "0")
        tgt_sdk=$(echo "$aapt_out" | grep -oP "targetSdkVersion:'\K[^']+" | head -1 || echo "0")
        echo "$pkg" > "${WORK_DIR}/pkg_name.txt"
        echo "$min_sdk" > "${WORK_DIR}/min_sdk.txt"
        echo "$tgt_sdk" > "${WORK_DIR}/target_sdk.txt"
        MIN_SDK="$min_sdk"
        info "Package: $pkg | minSdk: $min_sdk | targetSdk: $tgt_sdk"
        if [[ "$min_sdk" =~ ^[0-9]+$ ]] && [ "$min_sdk" -lt 21 ]; then
            add_finding "MEDIUM" "Metadata" "Very Low minSdkVersion ($min_sdk)" \
                "Supporting API $min_sdk exposes users on ancient Android versions with many unpatched vulnerabilities. Consider raising minSdkVersion to at least 24 (Android 7)." \
                "minSdkVersion: $min_sdk" "CONFIRMED" "general"
        fi
        if [[ "$tgt_sdk" =~ ^[0-9]+$ ]] && [ "$tgt_sdk" -lt 28 ]; then
            add_finding "MEDIUM" "Metadata" "Low targetSdkVersion ($tgt_sdk)" \
                "targetSdkVersion below 28 disables modern Android security features: network security config enforcement, file URI restrictions, FLAG_SECURE defaults." \
                "targetSdkVersion: $tgt_sdk" "CONFIRMED" "general"
        fi
    fi
}

# 
# MODULE: MANIFEST
# 
mod_manifest() {
    section "ANDROIDMANIFEST.XML"
    local manifest
    manifest=$(find "${WORK_DIR}/apktool_out" -maxdepth 1 -name "AndroidManifest.xml" 2>/dev/null | head -1 || true)
    # Never use raw/AndroidManifest.xml  it's binary (not apktool-decoded)
    if [ -z "$manifest" ] || [ ! -f "$manifest" ]; then
        warn "AndroidManifest.xml not found in apktool output  skipping manifest analysis"
        warn "Ensure apktool completed: apktool d -f -o out target.apk"
        return
    fi
    # Verify it's decoded XML, not binary
    if ! head -c 20 "$manifest" | grep -q '<?xml\|<manifest'; then
        warn "Manifest appears to be binary (apktool decode failed?)  skipping"
        return
    fi

    grep -q 'android:debuggable="true"' "$manifest" 2>/dev/null && \
        add_finding "CRITICAL" "Manifest" "Application Debuggable" \
            "android:debuggable=\"true\" allows ADB debugger attachment, memory extraction, SSL pinning bypass via Frida, and arbitrary code execution in app context." \
            "$(grep 'debuggable' "$manifest")" "CONFIRMED" "debuggable"

    grep -q 'android:allowBackup="true"' "$manifest" 2>/dev/null && \
        add_finding "HIGH" "Manifest" "Backup Enabled (allowBackup=true)" \
            "Any user with ADB access can extract all app data (DBs, SharedPrefs, files) via 'adb backup'. Sensitive tokens, session data, and credentials may be exfiltrated." \
            "$(grep 'allowBackup' "$manifest")" "CONFIRMED" "allowBackup"

    grep -q 'android:usesCleartextTraffic="true"' "$manifest" 2>/dev/null && \
        add_finding "HIGH" "Manifest" "Cleartext Traffic Permitted (usesCleartextTraffic)" \
            "The app allows unencrypted HTTP traffic. All data sent over HTTP is visible to network attackers and can be trivially intercepted on shared/public networks." \
            "$(grep 'usesCleartextTraffic' "$manifest")" "CONFIRMED" "cleartext"

    if ! grep -q 'android:networkSecurityConfig' "$manifest" 2>/dev/null; then
        add_finding "MEDIUM" "Manifest" "No Network Security Configuration" \
            "No networkSecurityConfig defined. Certificate pinning is absent and user-installed CAs are trusted by default on API < 24, enabling trivial MITM on test/rooted devices." \
            "Missing android:networkSecurityConfig in <application>" "CONFIRMED" "no_pinning"
    fi

    # Exported components  parse with python for accuracy
    python3 - "$manifest" "${WORK_DIR}/exported_components.txt" << 'PYEOF' 2>/dev/null || true
import sys, xml.etree.ElementTree as ET
manifest_path = sys.argv[1]
out_path = sys.argv[2]
NS = 'http://schemas.android.com/apk/res/android'
try:
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    results = []
    for tag in ['activity','service','receiver','provider']:
        for elem in root.iter(tag):
            name = elem.get(f'{{{NS}}}name','?')
            exported = elem.get(f'{{{NS}}}exported','')
            has_filter = elem.find('intent-filter') is not None
            perm = elem.get(f'{{{NS}}}permission','')
            grant_uri = elem.get(f'{{{NS}}}grantUriPermissions','')
            is_exported = exported == 'true' or (has_filter and exported == '')
            results.append(f"{tag}|{name}|{exported}|{has_filter}|{perm}|{grant_uri}|{is_exported}")
    with open(out_path,'w') as f:
        f.write('\n'.join(results))
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
PYEOF

    if [ -f "${WORK_DIR}/exported_components.txt" ]; then
        while IFS='|' read -r tag name exported has_filter perm grant_uri is_exported; do
            [ "$is_exported" != "True" ] && continue
            case "$tag" in
                activity)
                    local rem_key="exported_activity"
                    local sev="MEDIUM"
                    local extra_note=""
                    [ -z "$perm" ] && extra_note=" No permission protection." && sev="HIGH"
                    add_finding "$sev" "Exported Components" "Exported Activity: $name" \
                        "This Activity is accessible by any app or ADB.${extra_note} May allow unauthorized UI access, data exfiltration, or privilege escalation via intent extras." \
                        "Activity: $name | permission: ${perm:-NONE}" "CONFIRMED" "$rem_key"
                    ;;
                service)
                    local sev="MEDIUM"
                    [ -z "$perm" ] && sev="HIGH"
                    add_finding "$sev" "Exported Components" "Exported Service: $name" \
                        "Exported Service accessible without permission restriction. Malicious apps may bind to it, send untrusted intents, and trigger sensitive operations." \
                        "Service: $name | permission: ${perm:-NONE}" "CONFIRMED" "exported_service"
                    ;;
                receiver)
                    local sev="MEDIUM"
                    [ -z "$perm" ] && sev="HIGH"
                    add_finding "$sev" "Exported Components" "Exported BroadcastReceiver: $name" \
                        "BroadcastReceiver receives broadcasts from any app. Without permission protection, any app can send crafted intents to trigger its logic." \
                        "Receiver: $name | permission: ${perm:-NONE}" "CONFIRMED" "exported_receiver"
                    ;;
                provider)
                    local sev="HIGH"
                    local extra=""
                    [ "$grant_uri" = "true" ] && extra=" grantUriPermissions=true adds further risk."
                    add_finding "$sev" "Exported Components" "Exported ContentProvider: $name" \
                        "Exported ContentProvider with no read/write permission may allow any app to query, modify, or delete sensitive data.${extra}" \
                        "Provider: $name | permission: ${perm:-NONE} | grantUri: $grant_uri" "CONFIRMED" "exported_provider"
                    ;;
            esac
        done < "${WORK_DIR}/exported_components.txt"
    fi

    # Implicit exports (has intent-filter, no explicit exported attr)
    local implicit
    implicit=$(python3 - "$manifest" << 'PYEOF' 2>/dev/null || echo "0"
import sys, xml.etree.ElementTree as ET
NS = 'http://schemas.android.com/apk/res/android'
try:
    tree = ET.parse(sys.argv[1]); root = tree.getroot()
    n = sum(1 for t in ['activity','service','receiver'] for e in root.iter(t)
            if e.find('intent-filter') is not None and e.get(f'{{{NS}}}exported') is None)
    print(n)
except: print(0)
PYEOF
)
    [ "$implicit" -gt 0 ] 2>/dev/null && \
        add_finding "MEDIUM" "Manifest" "Implicitly Exported Components ($implicit)" \
            "Components with <intent-filter> but no explicit android:exported are implicitly exported on API < 31. Any app can invoke them, potentially bypassing access controls.$(api_context 31 'still relevant for users on older OS')" \
            "$implicit component(s) missing explicit exported attribute" "CONFIRMED" "implicit_export"

    # Deep links
    local schemes
    schemes=$(grep -oP 'android:scheme="\K[^"]+' "$manifest" 2>/dev/null | sort -u || true)
    [ -n "$schemes" ] && while IFS= read -r s; do
        add_finding "INFO" "Deep Links" "Custom URI Scheme Registered: $s://" \
            "Deep links may bypass authentication checks, pass unsanitized data to WebViews, allow open redirects, or expose internal app screens directly." \
            "Scheme: $s://" "CONFIRMED" "general"
    done <<< "$schemes"

    # Task hijacking
    grep -q 'android:taskAffinity' "$manifest" 2>/dev/null && \
    grep -q 'android:allowTaskReparenting="true"' "$manifest" 2>/dev/null && \
        add_finding "HIGH" "Manifest" "Task Hijacking Risk (taskAffinity + allowTaskReparenting)" \
            "Combining taskAffinity with allowTaskReparenting=true enables task hijacking. A malicious app can steal activities from the back stack and capture sensitive UI." \
            "$(grep -E 'taskAffinity|allowTaskReparenting' "$manifest")" "LIKELY" "general"

    # Dangerous permissions
    for p in READ_SMS RECEIVE_SMS SEND_SMS READ_CALL_LOG PROCESS_OUTGOING_CALLS \
              REQUEST_INSTALL_PACKAGES BIND_ACCESSIBILITY_SERVICE BIND_DEVICE_ADMIN \
              SYSTEM_ALERT_WINDOW CHANGE_COMPONENT_ENABLED_STATE MASTER_CLEAR REBOOT; do
        grep -q "$p" "$manifest" 2>/dev/null && \
            add_finding "INFO" "Permissions" "Dangerous Permission: $p" \
                "The app requests $p. Verify it's necessary. $p is particularly high-risk and could be abused for overlay attacks, device control, or sensitive data access." \
                "$(grep "$p" "$manifest" | head -2)" "CONFIRMED" "general"
    done
}

# 
# MODULE: SMALI ANALYSIS (obfuscation-resistant)
# 
mod_smali() {
    section "SMALI-LEVEL ANALYSIS"
    local smali_dir="${WORK_DIR}/apktool_out"
    [ ! -d "$smali_dir" ] && { warn "No smali output"; return; }

    declare -A SMALI_PATTERNS=(
        ["AES ECB Mode in Smali"]='const-string.*"AES/ECB'
        ["Crypto DES in Smali"]='const-string.*"DES[^e]'
        ["Log.d Sensitive in Smali"]='invoke-static.*Landroid/util/Log;->d'
        ["World Readable File Smali"]='const/4.*0x1\|openFileOutput.*0x1'
        ["exec() Shell Command"]='invoke-virtual.*Ljava/lang/Runtime;->exec'
        ["Reflection invoke Smali"]='invoke-virtual.*Ljava/lang/reflect/Method;->invoke'
        ["Unsafe deserialization Smali"]='Ljava/io/ObjectInputStream;->readObject'
        ["Dynamic code loading"]='Ldalvik/system/DexClassLoader;-><init>\|Ldalvik/system/PathClassLoader;-><init>'
        ["Native method invocation"]='invoke-static.*Ljava/lang/System;->loadLibrary'
        ["ContentResolver rawQuery"]='Landroid/database/sqlite/SQLiteDatabase;->rawQuery'
        ["HTTP URL Smali"]='const-string.*"http://'
        ["Intent with setComponent"]='invoke-virtual.*Landroid/content/Intent;->setComponent'
        ["PendingIntent Mutable"]='invoke-static.*Landroid/app/PendingIntent;->get.*0x0\b'
        ["addJavascriptInterface Smali"]='invoke-virtual.*Landroid/webkit/WebView;->addJavascriptInterface'
    )

    for check in "${!SMALI_PATTERNS[@]}"; do
        local pat="${SMALI_PATTERNS[$check]}"
        local found
        found=$(grep -rl --include="*.smali" -P "$pat" "$smali_dir" 2>/dev/null | head -3 || true)
        if [ -n "$found" ]; then
            local evidence
            evidence=$(grep -rh --include="*.smali" -P "$pat" "$smali_dir" 2>/dev/null | head -3 | sed 's/^[[:space:]]*//' | tr '\n' ' ' || true)
            add_finding "HIGH" "Smali Analysis" "Smali: $check" \
                "Detected in Smali bytecode (obfuscation-resistant): '$check'. This finding persists even if Java class names are obfuscated by ProGuard/R8." \
                "$evidence" "CONFIRMED" "general"
            warn "Smali hit: $check"
        fi
    done

    # Dynamic code loading  high confidence finding
    if grep -rl --include="*.smali" "DexClassLoader\|PathClassLoader\|InMemoryDexClassLoader" "$smali_dir" 2>/dev/null | grep -q .; then
        add_finding "HIGH" "Smali Analysis" "Dynamic Code Loading Detected" \
            "The app loads additional DEX code at runtime using DexClassLoader or similar. This may be used to load malicious plugins, bypass static analysis, or update code outside the Play Store." \
            "$(grep -rh --include="*.smali" 'DexClassLoader\|PathClassLoader' "$smali_dir" 2>/dev/null | head -3 | tr '\n' ' ')" "CONFIRMED" "general"
    fi

    # Shell command exec
    if grep -rl --include="*.smali" "Runtime;->exec" "$smali_dir" 2>/dev/null | grep -q .; then
        add_finding "HIGH" "Smali Analysis" "Runtime.exec() Shell Command Execution" \
            "The app calls Runtime.exec() to execute shell commands. If user-controlled input reaches this call, it results in OS command injection (RCE on the device)." \
            "$(grep -rh --include="*.smali" 'Runtime;->exec' "$smali_dir" 2>/dev/null | head -3 | tr '\n' ' ')" "LIKELY" "general"
    fi
}

# 
# MODULE: AIDL INTERFACE SCANNING
# 
mod_aidl() {
    section "AIDL INTERFACE ANALYSIS"
    local src="${WORK_DIR}/jadx_out"
    [ ! -d "$src" ] && { warn "No jadx output"; return; }

    # Find AIDL stub implementations (Stub.java classes generated from AIDL)
    local stubs
    stubs=$(find "$src" -name "*.java" 2>/dev/null | xargs grep -l "extends.*\.Stub\b\|implements.*IInterface\b" 2>/dev/null | head -20 || true)

    if [ -z "$stubs" ]; then
        info "No AIDL stub implementations found"
        return
    fi

    info "Found AIDL stubs, checking for permission guards..."
    while IFS= read -r stub_file; do
        local fname
        fname=$(basename "$stub_file" .java)
        # Check if the stub has getCallingUid/getCallingPid/checkCallingPermission
        if ! grep -qP 'getCallingUid|getCallingPid|checkCallingPermission|enforceCallingPermission' "$stub_file" 2>/dev/null; then
            local methods
            methods=$(grep -oP 'public\s+\w[\w<>, ]*\s+\w+\s*\(' "$stub_file" 2>/dev/null | head -5 | tr '\n' ' ' || true)
            add_finding "HIGH" "AIDL / IPC" "AIDL Stub Missing Caller Permission Check: $fname" \
                "The AIDL stub implementation '$fname' does not call getCallingUid(), checkCallingPermission(), or enforceCallingPermission(). Any app that binds to this service can invoke all IPC methods without authorization." \
                "File: $stub_file | Methods: $methods" "LIKELY" "aidl_no_permission"
            warn "AIDL no permission check: $fname"
        fi

        # Check for sensitive operations without permission
        if grep -qP 'getPassword|getToken|getSecret|deleteUser|adminAction' "$stub_file" 2>/dev/null; then
            if ! grep -qP 'checkCallingPermission|enforceCallingPermission' "$stub_file" 2>/dev/null; then
                add_finding "CRITICAL" "AIDL / IPC" "AIDL Sensitive Method Unprotected: $fname" \
                    "Sensitive-sounding methods in '$fname' AIDL stub are callable by any binding app without permission checks. This may expose privileged operations to malicious apps." \
                    "$(grep -P 'getPassword|getToken|getSecret|deleteUser|adminAction' "$stub_file" | head -3 | tr '\n' ' ')" "LIKELY" "aidl_no_permission"
            fi
        fi
    done <<< "$stubs"
}

# 
# MODULE: CONTENTPROVIDER SQL INJECTION TRACER
# 
mod_contentprovider() {
    section "CONTENTPROVIDER SQL INJECTION TRACER"
    local src="${WORK_DIR}/jadx_out"
    [ ! -d "$src" ] && { warn "No jadx output"; return; }

    # Find ContentProvider subclasses
    local providers
    providers=$(find "$src" -name "*.java" 2>/dev/null | xargs grep -l "extends ContentProvider\b" 2>/dev/null | head -20 || true)
    [ -z "$providers" ] && { info "No ContentProvider subclasses found"; return; }

    while IFS= read -r pfile; do
        local pname
        pname=$(basename "$pfile" .java)
        info "Tracing ContentProvider: $pname"

        # Check query() method for unsanitized selection parameter
        local query_body
        query_body=$(
            python3 - "$pfile" 2>/dev/null << 'PYEOF'
import sys, re
try:
    src = open(sys.argv[1]).read()
    # Find query method body
    m = re.search(r'public\s+Cursor\s+query\s*\([^)]+\)\s*\{(.{0,2000})', src, re.DOTALL)
    if m:
        print(m.group(1)[:500])
except: pass
PYEOF
        )

        if [ -n "$query_body" ]; then
            # Check for raw selection passed to rawQuery or direct string concat
            if echo "$query_body" | grep -qP 'rawQuery|execSQL|selection\s*\+|"\s*\+\s*selection'; then
                add_finding "CRITICAL" "ContentProvider" "SQL Injection in ContentProvider.query(): $pname" \
                    "The query() method passes the 'selection' parameter (caller-controlled) directly into a rawQuery() or string concatenation. Any app with read access to this ContentProvider can execute arbitrary SQL." \
                    "Provider: $pname | $(echo "$query_body" | grep -P 'rawQuery|selection.*\+' | head -2 | tr '\n' ' ')" "CONFIRMED" "sql_injection"
                fail "CRITICAL SQL injection in provider: $pname"
            fi

            # Parameterized check  is selection validated?
            if ! echo "$query_body" | grep -qP 'selectionArgs|replaceAll|sanitize|validate|Pattern|Matcher'; then
                add_finding "MEDIUM" "ContentProvider" "ContentProvider query() May Lack Input Validation: $pname" \
                    "The query() method does not appear to validate or sanitize the selection parameter. Depending on how it's used, this may allow SQL injection or logic bypass." \
                    "Provider: $pname  no selectionArgs or sanitization found in query()" "POSSIBLE" "sql_injection"
            fi
        fi

        # Check openFile() for path traversal
        if grep -qP 'openFile\s*\(' "$pfile" 2>/dev/null; then
            local of_body
            of_body=$(grep -A 20 'openFile' "$pfile" 2>/dev/null | head -20 | tr '\n' ' ' || true)
            if echo "$of_body" | grep -qP 'uri\.getPath|uri\.getLastPathSegment|new File.*uri'; then
                if ! echo "$of_body" | grep -qP 'getCanonicalPath|startsWith|normalize'; then
                    add_finding "HIGH" "ContentProvider" "Path Traversal in ContentProvider.openFile(): $pname" \
                        "openFile() uses URI path components to construct a File path without canonical path validation. An attacker can use '../' sequences in the URI to read arbitrary files in the app's data directory." \
                        "Provider: $pname | $of_body" "LIKELY" "general"
                fi
            fi
        fi
    done <<< "$providers"
}

# 
# MODULE: BACKUP RULES ANALYSIS
# 
mod_backup() {
    section "BACKUP RULES ANALYSIS"
    local apktool_dir="${WORK_DIR}/apktool_out"
    local manifest
    manifest=$(find "$apktool_dir" -maxdepth 1 -name "AndroidManifest.xml" 2>/dev/null | head -1 || true)

    # Check if backup rules exist at all
    local backup_xml
    backup_xml=$(find "$apktool_dir" -name "full_backup_content.xml" -o \
                                     -name "backup_rules.xml" \
                                     -o -name "data_extraction_rules.xml" \
                                     -o -name "*backup*.xml" 2>/dev/null | head -1 || true)

    if [ -z "$backup_xml" ]; then
        add_finding "MEDIUM" "Backup Security" "No Backup Exclusion Rules Defined" \
            "No fullBackupContent or dataExtractionRules XML found. All app data (databases, SharedPreferences, files) will be included in ADB backups and cloud auto-backups unless android:allowBackup=\"false\" is set." \
            "No backup XML found in resources" "LIKELY" "backup_sensitive"
        return
    fi

    info "Found backup rules: $backup_xml"
    cat "$backup_xml"

    # Check what's NOT excluded  look for common sensitive paths
    local sensitive_paths=("tokens" "secrets" "password" "auth" "session" "key" "priv" "cert" "wallet" "credential")
    for p in "${sensitive_paths[@]}"; do
        if ! grep -qi "$p" "$backup_xml" 2>/dev/null; then
            # Check if files with this name exist
            local matching_files
            matching_files=$(find "${WORK_DIR}/raw" -name "*${p}*" 2>/dev/null | head -3 || true)
            if [ -n "$matching_files" ]; then
                add_finding "MEDIUM" "Backup Security" "Potentially Sensitive Path Not Excluded from Backup: *$p*" \
                    "Files matching '*$p*' exist in the APK assets/resources but are not mentioned in the backup exclusion rules. These may be backed up and accessible via ADB to anyone with USB access." \
                    "Files: $matching_files" "POSSIBLE" "backup_sensitive"
            fi
        fi
    done

    # Check for include-all (no exclude rules = backup everything)
    local exclude_count
    exclude_count=$(grep -c '<exclude' "$backup_xml" 2>/dev/null || echo 0)
    if [ "$exclude_count" -eq 0 ]; then
        add_finding "HIGH" "Backup Security" "Backup Rules File Has No Exclusions" \
            "A backup rules XML exists but contains no <exclude> directives. All application data will be included in backups." \
            "$(cat "$backup_xml" 2>/dev/null | head -20)" "CONFIRMED" "backup_sensitive"
    fi
}

# 
# MODULE: SECRETS (parallel with apkleaks + trufflehog)
# 
mod_secrets() {
    section "SECRETS & CREDENTIALS"
    local src="${WORK_DIR}/jadx_out"
    local apktool="${WORK_DIR}/apktool_out"
    local raw="${WORK_DIR}/raw"
    local shard="${SHARD_DIR}/shard_$$.ndjson"

    info "Running multi-pattern secret scanner (single-pass)..."

    # Single-pass scan across all source directories
    for dir in "$src" "$apktool" "$raw"; do
        [ ! -d "$dir" ] && continue
        scan_source "$dir" "$shard" \
            'AKIA[0-9A-Z]{16}|Secrets|HIGH|aws_key' \
            '(?i)aws.{0,15}secret.{0,10}[=:].{0,50}[A-Za-z0-9/+]{40}|Secrets: AWS Secret Key|HIGH|aws_key' \
            'AIza[0-9A-Za-z_-]{35}|Secrets: Google API Key|HIGH|google_api_key' \
            'sk_live_[0-9a-zA-Z]{24}|Secrets: Stripe Secret Key|CRITICAL|general' \
            'pk_live_[0-9a-zA-Z]{24}|Secrets: Stripe Publishable Key|HIGH|general' \
            'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|Secrets: Hardcoded JWT Token|HIGH|general' \
            '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----|Secrets: Private Key in Source|CRITICAL|general' \
            'https?://[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@|Secrets: Basic Auth URL with Credentials|HIGH|general' \
            'ghp_[0-9a-zA-Z]{36}|Secrets: GitHub Personal Access Token|CRITICAL|general' \
            'xox[baprs]-[0-9a-zA-Z]{10,48}|Secrets: Slack Token|HIGH|general' \
            'SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}|Secrets: SendGrid API Key|HIGH|general' \
            '(?i)(password|passwd|pwd)\s*[=:]\s*"[^"]{4,}|Secrets: Hardcoded Password String|HIGH|general' \
            '(?i)(secret|api_key|api[-_]key|client_secret)\s*[=:]\s*"[^"]{6,}|Secrets: Hardcoded Secret/API Key|HIGH|general' \
            '(?i)(access_token|auth_token|bearer)\s*[=:]\s*"[^"]{10,}|Secrets: Hardcoded Auth Token|HIGH|general' \
            'SecretKeySpec\s*\(\s*"[^"]{8,}|Secrets: Hardcoded Encryption Key in SecretKeySpec|CRITICAL|general' \
            'type.*service_account.*project_id|Secrets: GCP Service Account JSON|CRITICAL|google_api_key' \
            '[0-9]{9}:[a-zA-Z0-9_-]{35}|Secrets: Telegram Bot Token|HIGH|general'
    done

    # apkleaks (background)  pipe "n" to suppress interactive jadx download prompt
    if tool_ok apkleaks; then
        ( echo "n" | timeout 120 apkleaks -f "${WORK_DIR}/target.apk" \
            -o "${WORK_DIR}/apkleaks_out.txt" 2>/dev/null || true
          echo "n" | timeout 120 apkleaks -f "${WORK_DIR}/target.apk" \
            --json -o "${WORK_DIR}/apkleaks_out.json" 2>/dev/null || true ) &
        BG_PIDS+=($!) ; BG_NAMES+=("apkleaks")
    fi

    # trufflehog (background)
    if tool_ok trufflehog && [ -d "$src" ]; then
        ( timeout 120 trufflehog filesystem "$src" \
            --no-verification --json 2>/dev/null \
            | head -100 > "${WORK_DIR}/trufflehog_out.txt" || true ) &
        BG_PIDS+=($!) ; BG_NAMES+=("trufflehog")
    fi

    wait_parallel "secrets scanners"

    # Process apkleaks output  try JSON first, fall back to text
    local apkleaks_shard="${SHARD_DIR}/shard_$$.ndjson"
    if [ -s "${WORK_DIR}/apkleaks_out.json" ]; then
        python3 - "${WORK_DIR}/apkleaks_out.json" "$apkleaks_shard" << 'PYEOF'
import sys, json
leak_file = sys.argv[1]
shard     = sys.argv[2]
try:
    data = json.load(open(leak_file))
    findings = []
    for rule, matches in data.items():
        if not matches: continue
        ev = '\n'.join(str(m) for m in matches[:10])
        findings.append(json.dumps({
            'severity':'HIGH','category':'Secrets',
            'title': f'apkleaks: {rule} ({len(matches)} match{"es" if len(matches)>1 else ""})',
            'description': f'apkleaks matched pattern "{rule}" with {len(matches)} occurrence(s).',
            'evidence': ev[:500], 'confidence':'LIKELY', 'cvss_score':7.5,
            'remediation':'Remove hardcoded credentials. Store secrets server-side or use Android Keystore.'
        }))
    if findings:
        open(shard,'a').write('\n'.join(findings)+'\n')
        print(f"apkleaks JSON: {len(findings)} pattern matches")
except Exception as e:
    print(f"apkleaks JSON parse error: {e}")
PYEOF
    elif [ -s "${WORK_DIR}/apkleaks_out.txt" ]; then
        local leaks
        leaks=$(grep -v '^$\|\[+\]\|\[INFO\]\|\[!\]\|Done with nothing\|find jadx\|download jadx\|Y/n\|Aborted' \
                "${WORK_DIR}/apkleaks_out.txt" 2>/dev/null | head -30 | tr '\n' '|')
        if [ -n "$leaks" ]; then
            add_finding "HIGH" "Secrets" "apkleaks Findings (text mode)" \
                "apkleaks detected potential secrets. Review each match carefully." \
                "${leaks:0:600}" "LIKELY" "general"
        fi
    fi

    # Process trufflehog output
    if [ -s "${WORK_DIR}/trufflehog_out.txt" ]; then
        local th_count
        th_count=$(wc -l < "${WORK_DIR}/trufflehog_out.txt" || echo 0)
        add_finding "CRITICAL" "Secrets" "trufflehog: $th_count High-Confidence Secret(s) Found" \
            "trufflehog detected secrets with high confidence. These are very likely real credentials and should be rotated immediately." \
            "$(head -3 "${WORK_DIR}/trufflehog_out.txt")" "CONFIRMED" "aws_key"
    fi
}

# 
# MODULE: CRYPTOGRAPHY
# 
mod_crypto() {
    section "CRYPTOGRAPHY ANALYSIS"
    local src="${WORK_DIR}/jadx_out"
    [ ! -d "$src" ] && { warn "No jadx source"; return; }
    local shard="${SHARD_DIR}/shard_$$.ndjson"

    scan_source "$src" "$shard" \
        'AES/ECB|Cryptography: Insecure AES/ECB Mode|HIGH|aes_ecb' \
        'Cipher\.getInstance\s*\(\s*"DES[^e]|Cryptography: DES Cipher (Broken)|HIGH|des_cipher' \
        'DESede|TripleDES|Cryptography: 3DES Cipher (Weak)|HIGH|des_cipher' \
        'MessageDigest\.getInstance\s*\(\s*"MD5"|Cryptography: MD5 Hash (Collision-Vulnerable)|HIGH|md5_sha1' \
        'MessageDigest\.getInstance\s*\(\s*"SHA-?1"|Cryptography: SHA-1 Hash (Collision-Vulnerable)|HIGH|md5_sha1' \
        'new IvParameterSpec\s*\(\s*new byte\[\]\{|IvParameterSpec\s*\(\s*"[^"]+"\)|Cryptography: Static/Hardcoded IV|HIGH|static_iv' \
        'SecretKeySpec\s*\(\s*"[^"]+"\s*\.getBytes|Cryptography: Hardcoded Key in SecretKeySpec|CRITICAL|general' \
        'RSA/ECB/PKCS1Padding|Cryptography: RSA PKCS1 Padding (Vulnerable to Bleichenbacher)|HIGH|general' \
        'RSA/None/NoPadding|Cryptography: RSA No Padding (Textbook RSA, trivially breakable)|CRITICAL|general' \
        'Math\.random\s*\(\)|Cryptography: Math.random() Used for Security (not CSPRNG)|HIGH|general' \
        'SecureRandom.*\.setSeed\s*\(\s*[0-9]|Cryptography: SecureRandom with Constant Seed|HIGH|general' \
        'SSLContext\.getInstance\s*\(\s*"SSL"\)|Cryptography: SSLv3 Forced (Insecure Protocol)|CRITICAL|trust_all_certs' \
        'ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier|Cryptography: AllowAll HostnameVerifier (MITM)|CRITICAL|trust_all_certs' \
        'TrustManager.*X509Certificate|checkServerTrusted[^)]{0,300}\{\s*\}|Cryptography: Empty/Permissive TrustManager|CRITICAL|trust_all_certs'
}

# 
# MODULE: WEBVIEW
# 
mod_webview() {
    section "WEBVIEW ANALYSIS"
    local src="${WORK_DIR}/jadx_out"
    [ ! -d "$src" ] && { warn "No jadx source"; return; }
    local shard="${SHARD_DIR}/shard_$$.ndjson"

    scan_source "$src" "$shard" \
        'setJavaScriptEnabled\s*\(\s*true\s*\)|WebView: JavaScript Enabled|HIGH|js_enabled' \
        'addJavascriptInterface\s*\(|WebView: JavaScript Interface (RCE Risk)|CRITICAL|js_interface' \
        'setAllowFileAccess\s*\(\s*true\s*\)|WebView: File Access Enabled|HIGH|general' \
        'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)|WebView: Universal File Access (UXSS)|CRITICAL|file_access_universal' \
        'setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)|WebView: File Access From File URLs|HIGH|file_access_universal' \
        'handler\.proceed\s*\(\)|WebView: SSL Error Ignored (handler.proceed)|CRITICAL|ssl_error_proceed' \
        'loadUrl\s*\(\s*"http://|WebView: Loads Plaintext HTTP URL|HIGH|cleartext' \
        'loadUrl\s*\(.*getStringExtra|loadUrl\s*\(.*getIntent|WebView: Loads Intent-Supplied URL (Open Redirect)|CRITICAL|js_enabled' \
        'evaluateJavascript\s*\(.*get(Extra|String|Intent)|WebView: evaluateJavascript with Intent Data|CRITICAL|js_interface' \
        'setWebContentsDebuggingEnabled\s*\(\s*true\s*\)|WebView: Remote Debugging Enabled|HIGH|general' \
        'setSavePassword\s*\(\s*true\s*\)|WebView: Password Saving Enabled|MEDIUM|general'
}

# 
# MODULE: DATA STORAGE
# 
mod_storage() {
    section "INSECURE DATA STORAGE"
    local src="${WORK_DIR}/jadx_out"
    [ ! -d "$src" ] && { warn "No jadx source"; return; }
    local shard="${SHARD_DIR}/shard_$$.ndjson"

    scan_source "$src" "$shard" \
        'MODE_WORLD_READABLE|Data Storage: World-Readable File Mode|HIGH|world_readable' \
        'MODE_WORLD_WRITEABLE|Data Storage: World-Writeable File Mode|HIGH|world_readable' \
        'getExternalStorageDirectory\s*\(\)|getExternalFilesDir\s*\(|Data Storage: Write to External Storage|HIGH|external_storage' \
        'Log\.[dviwe]\s*\(.*(?i)(password|token|secret|key|auth|credential)|Data Storage: Sensitive Data in Logs|HIGH|log_sensitive' \
        '(?i)(password|token|secret|pin)\s*[=:,\(]\s*sharedPreferences|sharedPreferences.*(?i)(password|token|secret|pin)|Data Storage: Sensitive Data in SharedPreferences|HIGH|general' \
        'ClipboardManager.*(?i)(password|secret|token|key)|Data Storage: Sensitive Data Copied to Clipboard|HIGH|general' \
        '(?i)(password|passwd)\s*=\s*"[^"]{4,}|Data Storage: Hardcoded Password|CRITICAL|general' \
        'SQLiteDatabase.*openOrCreate|openDatabase\s*\(|Data Storage: SQLite Database (check encryption)|INFO|general' \
        'getWritableDatabase\s*\(\)|getReadableDatabase\s*\(\)|Data Storage: SQLiteOpenHelper Usage (check for SQL injection)|INFO|general' \
        'ObjectOutputStream|Serializable|Data Storage: Java Serialization (check for deserialization issues)|MEDIUM|general'
}

# 
# MODULE: INTENTS
# 
mod_intents() {
    section "INTENT & IPC VULNERABILITIES"
    local src="${WORK_DIR}/jadx_out"
    [ ! -d "$src" ] && { warn "No jadx source"; return; }
    local shard="${SHARD_DIR}/shard_$$.ndjson"

    scan_source "$src" "$shard" \
        'PendingIntent\.get(?:Activity|Service|Broadcast)\b(?!.*FLAG_IMMUTABLE)(?!.*FLAG_UPDATE_CURRENT\|.*FLAG_IMMUTABLE)|Intent/IPC: Mutable PendingIntent (FLAG_IMMUTABLE missing)|HIGH|mutable_pending_intent' \
        'sendStickyBroadcast\s*\(|Intent/IPC: Sticky Broadcast (deprecated, readable by all apps)|MEDIUM|general' \
        'rawQuery\s*\(.*getStringExtra|getStringExtra.*rawQuery|Intent/IPC: SQL Injection via Intent Extra|CRITICAL|sql_injection' \
        'new File\s*\(.*getStringExtra|getStringExtra.*new File|Intent/IPC: Path Traversal via Intent Extra|CRITICAL|general' \
        'loadUrl\s*\(.*getStringExtra|getStringExtra.*loadUrl|Intent/IPC: WebView Open Redirect via Intent|CRITICAL|js_enabled' \
        'Runtime\.getRuntime\s*\(\)\.exec\s*\(.*getStringExtra|Intent/IPC: OS Command Injection via Intent Extra|CRITICAL|general' \
        '(?i)fragment.*getStringExtra|getSupportFragmentManager.*getStringExtra|Intent/IPC: Fragment Injection via Intent Extra|CRITICAL|general' \
        'startActivity.*getIntent|onNewIntent.*startActivity|Intent/IPC: Intent Forwarding (check extras validation)|MEDIUM|general' \
        'getSerializableExtra\s*\(|getParcelableExtra\s*\(|Intent/IPC: Deserialization via Intent (check class allowlist)|HIGH|general'
}

# 
# MODULE: NETWORK SECURITY CONFIG
# 
mod_netconfig() {
    section "NETWORK SECURITY CONFIG"
    local nsc
    nsc=$(find "${WORK_DIR}/apktool_out" -name "network_security_config.xml" 2>/dev/null | head -1 || true)

    if [ -z "$nsc" ]; then
        add_finding "MEDIUM" "Network Security" "No network_security_config.xml" \
            "App lacks a network security configuration. No certificate pinning, and user-installed CAs are trusted on pre-Android 7 devices." \
            "File not found" "CONFIRMED" "no_pinning"
        return
    fi

    grep -q 'cleartextTrafficPermitted="true"' "$nsc" 2>/dev/null && \
        add_finding "HIGH" "Network Security" "NSC Allows Cleartext Traffic" \
            "network_security_config.xml explicitly permits HTTP cleartext traffic. This exposes transmitted data to passive eavesdropping." \
            "$(grep 'cleartextTrafficPermitted' "$nsc")" "CONFIRMED" "cleartext" || true

    grep -q '<certificates src="user"' "$nsc" 2>/dev/null && \
        add_finding "HIGH" "Network Security" "User CA Certificates Trusted in NSC" \
            "The app trusts user-installed CA certificates. An attacker can install a custom root CA on the test device to intercept all TLS traffic without triggering SSL errors." \
            "$(grep 'certificates src' "$nsc")" "CONFIRMED" "no_pinning" || true

    if ! grep -q '<pin-set' "$nsc" 2>/dev/null; then
        add_finding "MEDIUM" "Network Security" "No Certificate Pinning in NSC" \
            "No <pin-set> defined. Certificate pinning would prevent MITM attacks even when a rogue CA is trusted." \
            "No <pin-set> element found" "CONFIRMED" "no_pinning"
    fi

    grep -q '<debug-overrides' "$nsc" 2>/dev/null && \
        add_finding "INFO" "Network Security" "debug-overrides Present in NSC" \
            "<debug-overrides> weakens TLS validation in debug mode. Ensure this is not active in release builds." \
            "$(grep -A5 'debug-overrides' "$nsc")" "LIKELY" "general" || true

    # Source-level TrustManager check
    if [ -d "${WORK_DIR}/jadx_out" ]; then
        grep -rlP --text 'checkServerTrusted' "${WORK_DIR}/jadx_out" 2>/dev/null | while read -r f; do
            if grep -qP 'checkServerTrusted.*\{[\s\n]*\}' "$f" 2>/dev/null; then
                add_finding "CRITICAL" "Network Security" "Empty checkServerTrusted()  Trust All Certs" \
                    "A custom TrustManager with an empty checkServerTrusted() blindly trusts ALL TLS certificates, completely bypassing SSL validation and enabling trivial MITM on any network." \
                    "File: $f" "CONFIRMED" "trust_all_certs"
            fi
        done
    fi
    return 0
}

# 
# MODULE: NATIVE LIBRARIES
# 
mod_native() {
    section "NATIVE LIBRARY ANALYSIS"
    local lib_dir="${WORK_DIR}/raw/lib"
    [ ! -d "$lib_dir" ] && { info "No native libraries in APK"; return; }

    find "$lib_dir" -name "*.so" | while read -r so; do
        local lib
        lib=$(basename "$so")
        info "Analyzing: $lib"

        if tool_ok strings; then
            local str_out
            str_out=$(strings "$so" 2>/dev/null || true)

            # Dangerous C functions
            for fn in strcpy strcat sprintf gets vsprintf strtok scanf system; do
                if echo "$str_out" | grep -qw "$fn" 2>/dev/null; then
                    add_finding "MEDIUM" "Native Libs" "Dangerous C Function in $lib: $fn()" \
                        "$fn() in native code is susceptible to buffer overflow/injection if input is unbounded. Review all call sites carefully." \
                        "Symbol: $fn in $lib" "LIKELY" "general"
                fi
            done

            # system()  elevated risk
            if echo "$str_out" | grep -qw "system" 2>/dev/null; then
                add_finding "HIGH" "Native Libs" "system() Call in $lib" \
                    "system() executes shell commands. If user input flows into this call, it results in OS command injection (RCE on the device)." \
                    "system() symbol in $lib" "LIKELY" "general"
            fi

            # Hardcoded secrets in binary
            if echo "$str_out" | grep -qiP '(password|secret|api.?key|private.?key)' 2>/dev/null; then
                local secrets
                secrets=$(echo "$str_out" | grep -iP '(password|secret|api.?key|private.?key)' | head -5 | tr '\n' ' ')
                add_finding "HIGH" "Native Libs" "Potential Secrets in Binary: $lib" \
                    "Strings resembling credentials found embedded in native library binary." \
                    "$secrets" "LIKELY" "general"
            fi

            # Hardcoded HTTP URLs
            local http_urls
            http_urls=$(echo "$str_out" | grep -oP 'http://[a-zA-Z0-9._/-]+' | head -5 | tr '\n' ' ' || true)
            [ -n "$http_urls" ] && add_finding "MEDIUM" "Native Libs" "HTTP URLs in Native Library: $lib" \
                "Plaintext HTTP URLs found in native binary. Traffic to these endpoints is unencrypted." \
                "$http_urls" "CONFIRMED" "cleartext"
        fi

        # ELF security mitigations
        if tool_ok readelf; then
            local elf
            elf=$(readelf -d "$so" 2>/dev/null || true)
            ! echo "$elf" | grep -q "GNU_RELRO" && \
                add_finding "MEDIUM" "Native Libs" "No RELRO in $lib" \
                    "Missing RELRO (Relocation Read-Only) makes GOT overwrite attacks easier in memory corruption exploits." \
                    "No GNU_RELRO in $lib" "CONFIRMED" "general"
            ! echo "$elf" | grep -q "BIND_NOW" && \
                add_finding "LOW" "Native Libs" "Lazy Binding (No BIND_NOW) in $lib" \
                    "Lazy symbol binding prevents full RELRO. Resolve all symbols at load time with BIND_NOW for stronger memory safety." \
                    "No BIND_NOW in $lib" "CONFIRMED" "general"
        fi

        # Debug symbols check
        if tool_ok nm; then
            local sym_count
            sym_count=$(nm -D "$so" 2>/dev/null | wc -l || echo 0)
            [ "$sym_count" -gt 100 ] && \
                add_finding "LOW" "Native Libs" "Debug Symbols Not Stripped in $lib ($sym_count symbols)" \
                    "Unstripped debug symbols significantly aid reverse engineering. Strip symbols from release builds with strip --strip-unneeded." \
                    "Symbol count: $sym_count in $lib" "CONFIRMED" "general"
        fi
    done
}

# 
# MODULE: FIREBASE & CLOUD
# 
mod_firebase() {
    section "FIREBASE & CLOUD MISCONFIG"
    local gs
    gs=$(find "${WORK_DIR}" -name "google-services.json" 2>/dev/null | head -1 || true)

    if [ -n "$gs" ]; then
        local fb_url api_key project_id storage_bucket
        fb_url=$(grep -oP '"firebase_url"\s*:\s*"\K[^"]+' "$gs" 2>/dev/null || true)
        api_key=$(grep -oP '"current_key"\s*:\s*"\K[^"]+' "$gs" 2>/dev/null | head -1 || true)
        project_id=$(grep -oP '"project_id"\s*:\s*"\K[^"]+' "$gs" 2>/dev/null | head -1 || true)
        storage_bucket=$(grep -oP '"storage_bucket"\s*:\s*"\K[^"]+' "$gs" 2>/dev/null | head -1 || true)

        add_finding "INFO" "Firebase" "Firebase Config Extracted" \
            "google-services.json found. Project: $project_id, API Key: $api_key, DB: $fb_url, Storage: $storage_bucket. Validate rules and key restrictions." \
            "Project: $project_id | Key: $api_key" "CONFIRMED" "general"

        # Save for live checks
        echo "$fb_url"        > "${WORK_DIR}/firebase_url.txt"      2>/dev/null || true
        echo "$api_key"       > "${WORK_DIR}/firebase_apikey.txt"   2>/dev/null || true
        echo "$project_id"    > "${WORK_DIR}/firebase_project.txt"  2>/dev/null || true
        echo "$storage_bucket"> "${WORK_DIR}/firebase_storage.txt"  2>/dev/null || true
    else
        # Grep source for firebase URLs
        local fb_urls
        fb_urls=$(grep -rP --text --include="*.java" --include="*.kt" --include="*.xml" --include="*.json" \
            'https://[a-z0-9-]+\.firebaseio\.com' "${WORK_DIR}/" 2>/dev/null | \
            grep -oP 'https://[a-z0-9-]+\.firebaseio\.com' | sort -u | head -3 || true)
        if [ -n "$fb_urls" ]; then
            while IFS= read -r url; do
                add_finding "MEDIUM" "Firebase" "Hardcoded Firebase DB URL: $url" \
                    "Firebase URL found in source. Test $url/.json to check if public read is enabled." \
                    "URL: $url" "CONFIRMED" "firebase_public"
                echo "$url" >> "${WORK_DIR}/firebase_url.txt"
            done <<< "$fb_urls"
        fi
    fi
}

# 
# MODULE: MISCELLANEOUS
# 
mod_misc() {
    section "MISCELLANEOUS CHECKS"
    local src="${WORK_DIR}/jadx_out"
    [ ! -d "$src" ] && { warn "No jadx source"; return; }
    local shard="${SHARD_DIR}/shard_$$.ndjson"

    scan_source "$src" "$shard" \
        'rawQuery\s*\([^)]*\+|execSQL\s*\([^)]*\+|Misc: SQL Injection (rawQuery/execSQL concat)|CRITICAL|sql_injection' \
        'ZipEntry.*getName\s*\(\).*new File|new File.*ZipEntry.*getName|Misc: Zip Slip Path Traversal|HIGH|zip_slip' \
        'ObjectInputStream\b|readObject\s*\(\)|Misc: Unsafe Java Deserialization|HIGH|unsafe_deserialization' \
        'new Random\s*\(\).*token|token.*new Random\s*\(\)|Random\s*\(\).*password|Misc: java.util.Random for Security Token (not CSPRNG)|HIGH|general' \
        'filterTouchesWhenObscured\s*=\s*false|Misc: Tapjacking Not Prevented (filterTouchesWhenObscured=false)|MEDIUM|general' \
        'openFile.*\.\./|Misc: ContentProvider Path Traversal|HIGH|general' \
        '(?i)(test|dev|debug).{0,10}(password|pass|secret).{0,5}[=:].{0,30}|Misc: Hardcoded Test/Dev Credentials|HIGH|general' \
        'evaluateJavascript\s*\(.*getStringExtra|evaluateJavascript\s*\(.*getIntent\(\)|Misc: JS Execution with Intent User Input|CRITICAL|js_interface' \
        'Runtime\.getRuntime\s*\(\)\.exec\s*\(|Misc: Runtime.exec() OS Command Execution|HIGH|general' \
        'ProcessBuilder\s*\(.*getStringExtra|ProcessBuilder\s*\(.*getIntent|Misc: ProcessBuilder with Intent Data (Command Injection)|CRITICAL|general' \
        'Class\.forName\s*\(.*getStringExtra|Misc: Dynamic Class Loading from Intent (Class Injection)|CRITICAL|general' \
        '(?i)http://(?!schemas\.android|www\.w3|localhost|127\.0\.0\.1)[a-z0-9._/-]{8,}|Misc: Hardcoded HTTP (non-localhost) URL|MEDIUM|cleartext' \
        'StrictMode\.(setThreadPolicy|setVmPolicy)|Misc: StrictMode Used (may indicate debug/dev build)|INFO|general' \
        'android\.util\.Log\.[dv]\s*\(|BuildConfig\.DEBUG|Misc: Verbose Logging / Debug Code|INFO|general'
}

# 
# MODULE: LIVE NETWORK CHECKS
# 
mod_live_checks() {
    section "LIVE NETWORK CHECKS"

    if [ "$DO_LIVE_CHECKS" != "true" ]; then
        info "Live checks disabled. Pass --live to enable."
        return
    fi

    #  Firebase Realtime DB 
    if [ -f "${WORK_DIR}/firebase_url.txt" ]; then
        while IFS= read -r fb_url; do
            [ -z "$fb_url" ] && continue
            info "Testing Firebase DB: $fb_url/.json"

            local resp_bundle http_code resp
            resp_bundle=$(timeout 10 curl -sk --max-time 8 -w "\nHTTP_STATUS:%{http_code}" "${fb_url}/.json" 2>/dev/null || true)
            http_code=$(echo "$resp_bundle" | sed -n 's/^HTTP_STATUS://p' | tail -1)
            resp=$(echo "$resp_bundle" | sed '/^HTTP_STATUS:/d')

            [ -z "$resp" ] && continue

            # Explicitly treat known non-vulnerable states as informational only.
            if echo "$resp" | grep -qi '"error"'; then
                if echo "$resp" | grep -qi 'disabled by a database owner'; then
                    info "Firebase DB is disabled by owner: $fb_url"
                elif echo "$resp" | grep -qi 'permission denied\|auth'; then
                    info "Firebase DB requires authentication: $fb_url"
                else
                    warn "Firebase DB returned error (not confirmed public): $fb_url"
                fi
                continue
            fi

            # Public read is confirmed only when unauthenticated request returns actual JSON data.
            if [ "${http_code:-200}" = "200" ] && [ "$resp" != "null" ] && [ ${#resp} -gt 1 ]; then
                add_finding "CRITICAL" "Live: Firebase" "Firebase Realtime DB Publicly Readable: $fb_url" \
                    "The Firebase Realtime Database returns data without authentication. Any attacker can read (and potentially write) all data. This is a critical data exposure." \
                    "URL: ${fb_url}/.json | HTTP: ${http_code:-200} | Response: ${resp:0:200}" "CONFIRMED" "firebase_public"
                fail "CRITICAL: Firebase DB public read! $fb_url"
            fi
        done < "${WORK_DIR}/firebase_url.txt"
    fi

    #  Firebase Storage Bucket 
    if [ -f "${WORK_DIR}/firebase_storage.txt" ]; then
        local bucket
        bucket=$(cat "${WORK_DIR}/firebase_storage.txt" | head -1)
        if [ -n "$bucket" ]; then
            info "Testing Firebase Storage: $bucket"
            local store_resp
            store_resp=$(timeout 10 curl -sk --max-time 8 \
                "https://firebasestorage.googleapis.com/v0/b/${bucket}/o" 2>/dev/null || true)
            if echo "$store_resp" | grep -q '"name"'; then
                add_finding "HIGH" "Live: Firebase" "Firebase Storage Bucket Publicly Listable: $bucket" \
                    "Firebase Storage bucket files are publicly listable without authentication. Sensitive files, images, or documents may be enumerable and downloadable." \
                    "Bucket: $bucket | Response: ${store_resp:0:300}" "CONFIRMED" "firebase_public"
            fi
        fi
    fi

    #  Google API Key Scope Test 
    if [ -f "${WORK_DIR}/firebase_apikey.txt" ]; then
        local api_key
        api_key=$(cat "${WORK_DIR}/firebase_apikey.txt" | head -1)
        if [ -n "$api_key" ] && [[ "$api_key" == AIza* ]]; then
            info "Testing Google API key scope: $api_key"

            # Test Maps API (often unrestricted)
            local maps_resp
            maps_resp=$(timeout 10 curl -sk --max-time 8 \
                "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=${api_key}" 2>/dev/null || true)
            if echo "$maps_resp" | grep -qv '"OVER_DAILY_LIMIT"\|"API_KEY_INVALID"\|"REQUEST_DENIED"'; then
                add_finding "HIGH" "Live: API Keys" "Google API Key Has Maps Geocoding Access: ${api_key:0:20}..." \
                    "The hardcoded Google API key allows Maps Geocoding API requests. If unrestricted, attackers can use this key for quota abuse, incurring financial cost to the app owner." \
                    "Key: ${api_key:0:20}... | API: Maps Geocoding" "CONFIRMED" "google_api_key"
            fi

            # Test Firebase REST auth
            local fb_project
            [ -f "${WORK_DIR}/firebase_project.txt" ] && fb_project=$(cat "${WORK_DIR}/firebase_project.txt")
            if [ -n "${fb_project:-}" ]; then
                local fb_auth_resp
                fb_auth_resp=$(timeout 10 curl -sk --max-time 8 -X POST \
                    "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${api_key}" \
                    -H 'Content-Type: application/json' \
                    -d '{"returnSecureToken":true}' 2>/dev/null || true)
                if echo "$fb_auth_resp" | grep -q '"idToken"'; then
                    add_finding "CRITICAL" "Live: API Keys" "Firebase Anonymous Auth Enabled (Account Takeover Risk)" \
                        "The Firebase API key allows anonymous account creation without any credentials. Combined with insecure DB rules, this may allow full database access to any attacker." \
                        "Key: ${api_key:0:20}... | Response contains idToken" "CONFIRMED" "firebase_public"
                fi
            fi
        fi
    fi

    #  Endpoint Reachability & Header Check 
    info "Extracting and testing hardcoded endpoints..."
    local endpoints=()
    for src_dir in "${WORK_DIR}/jadx_out" "${WORK_DIR}/apktool_out"; do
        [ ! -d "$src_dir" ] && continue
        while IFS= read -r url; do
            endpoints+=("$url")
        done < <(grep -rhoP 'https?://[a-zA-Z0-9._/-]{10,100}' "$src_dir" \
                 --include="*.java" --include="*.kt" --include="*.xml" --include="*.json" 2>/dev/null | \
                 grep -v 'schemas.android.com\|w3.org\|example.com\|localhost\|127\.0\|10\.0\.0\|192\.168' | \
                 sort -u | head -20 || true)
    done

    local tested=0
    for url in "${endpoints[@]}"; do
        [ $tested -ge 10 ] && break
        tested=$((tested+1))
        local headers
        headers=$(timeout 8 curl -skI --max-time 6 "$url" 2>/dev/null | head -10 || true)
        if [ -n "$headers" ]; then
            local status
            status=$(echo "$headers" | grep -oP 'HTTP/\d\.\d \K\d+' | head -1 || echo "?")
            # Check for missing security headers
            if ! echo "$headers" | grep -qi 'Strict-Transport-Security'; then
                add_finding "LOW" "Live: Endpoints" "Missing HSTS Header: $url" \
                    "The endpoint $url does not return a Strict-Transport-Security header, making it easier to downgrade HTTPS connections to HTTP via MITM." \
                    "URL: $url | HTTP $status | No HSTS" "CONFIRMED" "general"
            fi
            if echo "$headers" | grep -qi 'Server:'; then
                local server_header
                server_header=$(echo "$headers" | grep -i 'Server:' | head -1)
                add_finding "INFO" "Live: Endpoints" "Server Version Disclosure: $url" \
                    "The server discloses its software and version via the Server: header, aiding fingerprinting and targeted attacks." \
                    "URL: $url | $server_header" "CONFIRMED" "general"
            fi
        fi
    done

    success "Live network checks complete"
}

# 
# MODULE: APKID  PACKER / PROTECTOR DETECTION
# 
mod_apkid() {
    section "APKID  PACKER & PROTECTOR DETECTION"

    if ! tool_ok apkid; then
        warn "apkid not installed  skipping packer detection (pip3 install apkid)"
        add_finding "INFO" "APKiD" "APKiD Not Installed  Packer Detection Skipped" \
            "APKiD was not found. Without packer detection, the script cannot alert you when an APK is protected by Jiagu, 360, Bangcle, DexProtect, or similar. In those cases all other modules produce garbage or silent false-clean results." \
            "Install: pip3 install apkid" "CONFIRMED" "general"
        return
    fi

    info "Running APKiD against ${WORK_DIR}/target.apk ..."
    local apkid_out
    apkid_out=$(timeout 60 apkid --json "${WORK_DIR}/target.apk" 2>/dev/null || echo '{}')

    # Parse JSON output
    python3 - "$apkid_out" << 'PYEOF'
import sys, json

try:
    data = json.loads(sys.argv[1])
except:
    print("APKiD JSON parse failed")
    sys.exit(0)

results = data.get('files', [])
for r in results:
    tags = r.get('tags', [])
    fname = r.get('filename', '')
    for tag in tags:
        print(f"FILE: {fname} | TAG: {tag}")
PYEOF

    # Key findings from apkid tags
    declare -A PACKER_SIGS=(
        ["jiagu"]="Qihoo 360 Jiagu packer detected"
        ["bangcle"]="Bangcle/SecShell packer detected"
        ["dexprotect"]="DexProtect packer detected"
        ["ijiami"]="Ijiami packer detected"
        ["naga"]="Naga packer detected"
        ["liapp"]="LIAPP packer detected"
        ["apkprotect"]="APKProtect packer detected"
        ["dexguard"]="DexGuard commercial obfuscator detected"
        ["proguard"]="ProGuard obfuscator detected (informational)"
        ["anti_vm"]="Anti-VM / emulator detection found"
        ["anti_debug"]="Anti-debug protection found"
        ["multi_dex"]="Multi-DEX APK (complex structure)"
        ["flutter"]="Flutter framework detected"
        ["react_native"]="React Native framework detected"
        ["cordova"]="Apache Cordova framework detected"
        ["xamarin"]="Xamarin framework detected"
    )

    local packed=false
    for sig in "${!PACKER_SIGS[@]}"; do
        if echo "$apkid_out" | grep -qi "$sig" 2>/dev/null; then
            local msg="${PACKER_SIGS[$sig]}"
            local sev="HIGH"
            [[ "$sig" == "proguard" || "$sig" == "multi_dex" ]] && sev="INFO"
            [[ "$sig" == "flutter" || "$sig" == "react_native" || "$sig" == "cordova" ]] && sev="INFO"
            [[ "$sig" == "anti_vm" || "$sig" == "anti_debug" ]] && sev="MEDIUM"

            add_finding "$sev" "APKiD" "APKiD: $msg" \
                "$msg. If this is a commercial packer (Jiagu, Bangcle, DexProtect), jadx/apktool decompilation output is likely incomplete or misleading. Static analysis results should be treated as partial  dynamic analysis required for full coverage." \
                "apkid signature: $sig" "CONFIRMED" "general"

            [[ "$sev" == "HIGH" ]] && packed=true
            warn "APKiD: $msg"

            # Set framework flags for downstream modules
            case "$sig" in
                flutter)     echo "flutter"      >> "${WORK_DIR}/frameworks.txt" ;;
                react_native) echo "react_native" >> "${WORK_DIR}/frameworks.txt" ;;
                cordova)     echo "cordova"      >> "${WORK_DIR}/frameworks.txt" ;;
            esac
        fi
    done

    if [ "$packed" = true ]; then
        add_finding "CRITICAL" "APKiD" "APK Is Protected By Commercial Packer  Static Analysis Is Unreliable" \
            "A commercial packer was detected. All static analysis findings from this tool may be INCOMPLETE or INCORRECT because the real DEX code is loaded dynamically at runtime and was not available for analysis. You MUST complement this with dynamic analysis (Frida, objection, MobSF dynamic) to get reliable results." \
            "$(echo "$apkid_out" | head -5)" "CONFIRMED" "general"
        fail "CRITICAL: APK is packed  static results are partial only!"
    fi

    success "APKiD analysis complete"
}

# 
# MODULE: SEMGREP  OWASP MOBILE TOP 10 RULESET
# 
mod_semgrep() {
    section "SEMGREP  OWASP MOBILE TOP 10"

    if ! tool_ok semgrep; then
        warn "semgrep not installed  skipping (pip3 install semgrep)"
        return
    fi

    local src="${WORK_DIR}/jadx_out"
    if [ ! -d "$src" ]; then
        warn "No jadx source for semgrep"
        return
    fi

    info "Running semgrep with OWASP Mobile + Android rulesets..."
    local sg_out="${WORK_DIR}/semgrep_output.json"

    # Run semgrep with multiple relevant rulesets
    timeout 300 semgrep \
        --config "p/owasp-top-ten" \
        --config "p/android" \
        --config "p/secrets" \
        --json \
        --quiet \
        --no-git-ignore \
        "$src" > "$sg_out" 2>/dev/null || true

    if [ ! -s "$sg_out" ]; then
        warn "semgrep produced no output (may need login: semgrep login)"
        # Try auto config as fallback
        timeout 180 semgrep \
            --config auto \
            --json --quiet \
            "$src" > "$sg_out" 2>/dev/null || true
    fi

    if [ -s "$sg_out" ]; then
        python3 - "$sg_out" << 'PYEOF'
import sys, json

try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except Exception as e:
    print(f"semgrep parse error: {e}")
    sys.exit(0)

results = data.get('results', [])
print(f"semgrep found {len(results)} results")

# Group by severity
for r in results[:50]:  # cap at 50 to avoid noise
    sev   = r.get('extra', {}).get('severity', 'WARNING').upper()
    msg   = r.get('extra', {}).get('message', '')
    rule  = r.get('check_id', '')
    path  = r.get('path', '')
    line  = r.get('start', {}).get('line', 0)
    code  = r.get('extra', {}).get('lines', '')
    print(f"[{sev}] {rule} @ {path}:{line}")
    print(f"  {msg[:120]}")
PYEOF

        # Parse and add top semgrep findings
        python3 - "$sg_out" "${SHARD_DIR}/shard_semgrep.ndjson" << 'PYEOF'
import sys, json

sev_map = {'ERROR':'HIGH','WARNING':'MEDIUM','INFO':'LOW','INVENTORY':'INFO'}

try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except:
    sys.exit(0)

results = data.get('results', [])
seen = set()
output_lines = []

for r in results[:60]:
    rule  = r.get('check_id', 'unknown')
    msg   = r.get('extra', {}).get('message', 'No description')
    sev_raw = r.get('extra', {}).get('severity', 'WARNING').upper()
    sev   = sev_map.get(sev_raw, 'MEDIUM')
    path  = r.get('path', '')
    line  = r.get('start', {}).get('line', 0)
    code  = (r.get('extra', {}).get('lines', '') or '')[:300]
    fix   = (r.get('extra', {}).get('fix', '') or 'See semgrep rule documentation for remediation.')[:300]

    key = rule + '|' + path[:60]
    if key in seen:
        continue
    seen.add(key)

    entry = {
        'severity': sev,
        'category': f'Semgrep / {rule.split(".")[-2] if "." in rule else "OWASP"}',
        'title': f'Semgrep: {rule.split(".")[-1] if "." in rule else rule}',
        'description': msg,
        'evidence': f'File: {path}:{line}\n{code}',
        'confidence': 'LIKELY',
        'cvss_score': {'HIGH':7.0,'MEDIUM':5.0,'LOW':3.0,'INFO':1.0}.get(sev,5.0),
        'remediation': fix if fix else 'Review the semgrep rule documentation and apply the recommended fix pattern.'
    }
    output_lines.append(json.dumps(entry))

with open(sys.argv[2], 'w') as f:
    f.write('\n'.join(output_lines))

print(f"Wrote {len(output_lines)} semgrep findings to shard")
PYEOF
        success "semgrep analysis complete"
    else
        warn "semgrep produced no JSON output"
    fi
}

# 
# MODULE: REACT NATIVE  Bundle Analysis
# 
mod_react_native() {
    section "REACT NATIVE BUNDLE ANALYSIS"

    local bundle_paths=(
        "${WORK_DIR}/raw/assets/index.android.bundle"
        "${WORK_DIR}/raw/assets/index.bundle"
        "${WORK_DIR}/raw/assets/main.bundle"
        "${WORK_DIR}/raw/assets/app.bundle"
    )

    local bundle=""
    for p in "${bundle_paths[@]}"; do
        [ -f "$p" ] && bundle="$p" && break
    done

    if [ -z "$bundle" ]; then
        # Also check apktool output
        bundle=$(find "${WORK_DIR}/apktool_out/assets" -name "*.bundle" 2>/dev/null | head -1 || true)
    fi

    if [ -z "$bundle" ]; then
        info "No React Native bundle found  not a React Native app (or bundle is inline)"
        return
    fi

    info "React Native bundle found: $bundle ($(wc -c < "$bundle" | tr -d ' ') bytes)"

    add_finding "INFO" "React Native" "React Native App Detected" \
        "This app uses React Native. The JavaScript bundle contains all business logic and may include hardcoded secrets, API endpoints, sensitive logic, and security controls that are trivially readable without any decompilation." \
        "Bundle: $bundle" "CONFIRMED" "general"

    #  Deobfuscate / prettify if node is available
    local js_src="$bundle"
    if tool_ok node; then
        info "Prettifying React Native bundle with node..."
        local pretty="${WORK_DIR}/rn_bundle_pretty.js"
        node - "$bundle" "$pretty" << 'JSEOF' 2>/dev/null || true
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
// Basic prettification: insert newlines at statement boundaries
const pretty = src
    .replace(/;(?!\n)/g, ';\n')
    .replace(/\{(?!\n)/g, '{\n')
    .replace(/\}(?!\n)/g, '}\n');
fs.writeFileSync(process.argv[3], pretty);
console.log('Bundle prettified');
JSEOF
        [ -f "$pretty" ] && js_src="$pretty"
    fi

    #  Secret patterns in JS bundle
    declare -A RN_PATTERNS=(
        ["Hardcoded API Key"]='(?i)(api[_-]?key|apikey)\s*[:=]\s*["\x27][A-Za-z0-9_\-]{16,}'
        ["Hardcoded Secret"]='(?i)(secret|password|passwd|token)\s*[:=]\s*["\x27][^"\x27]{8,}'
        ["AWS Key in Bundle"]='AKIA[0-9A-Z]{16}'
        ["Firebase Config in Bundle"]='AIza[0-9A-Za-z_-]{35}'
        ["JWT in Bundle"]='eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+'
        ["Private Key in Bundle"]='-----BEGIN (RSA |EC )?PRIVATE KEY-----'
        ["Internal IP in Bundle"]='["'"'"'](10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)'
        ["HTTP Endpoint in Bundle"]='fetch\s*\(\s*["\x27]http://'
        ["Disabled SSL Pinning"]='(?i)(ssl|certificate|pinning)\s*[:=]\s*(false|disabled|skip|bypass)'
        ["Eval Usage (Code Injection)"]='eval\s*\('
        ["Console.log with Sensitive Data"]='console\.log\s*\(.*(?i)(password|token|secret|key|auth)'
        ["AsyncStorage Sensitive Data"]='AsyncStorage\.(setItem|getItem)\s*\(.*(?i)(password|token|secret|key)'
        ["Insecure fetch (no HTTPS check)"]='fetch\s*\(\s*["\x27]http://'
        ["React Native Debugger Enabled"]='__DEV__|NativeDevSettings|setIsDebuggingRemotely'
        ["Hardcoded Internal URL"]='(?i)(staging|internal|dev|test)\.(api|backend|server)\.'
    )

    for name in "${!RN_PATTERNS[@]}"; do
        local pat="${RN_PATTERNS[$name]}"
        local hits
        hits=$(grep --text -oP "$pat" "$js_src" 2>/dev/null | head -3 | tr '\n' ' ' || true)
        if [ -n "$hits" ]; then
            local sev="HIGH"
            [[ "$name" == *"Internal IP"* || "$name" == *"Debugger"* ]] && sev="MEDIUM"
            [[ "$name" == *"AWS"* || "$name" == *"Private Key"* || "$name" == *"SSL Pinning"* ]] && sev="CRITICAL"
            add_finding "$sev" "React Native" "RN Bundle: $name" \
                "Detected '$name' in React Native JS bundle. The bundle is shipped with the APK and is trivially readable by any user  there is no obfuscation protecting this data." \
                "${hits:0:400}" "CONFIRMED" "general"
            warn "RN: $name"
        fi
    done

    #  List all domains/endpoints in bundle
    info "Extracting API endpoints from RN bundle..."
    local endpoints
    endpoints=$(grep --text -oP 'https?://[a-zA-Z0-9._\-/]{10,100}' "$js_src" 2>/dev/null | \
                grep -v 'example.com\|schemas\|localhost\|w3.org' | sort -u | head -30 || true)
    if [ -n "$endpoints" ]; then
        local count
        count=$(echo "$endpoints" | wc -l)
        add_finding "INFO" "React Native" "API Endpoints in RN Bundle ($count found)" \
            "All API endpoints are visible in the React Native bundle. Review for internal/staging endpoints, unauthenticated paths, or paths that reveal internal architecture." \
            "$endpoints" "CONFIRMED" "general"
    fi

    #  Hermes bytecode detection
    if file "$bundle" 2>/dev/null | grep -qi "hermes\|bytecode\|binary"; then
        add_finding "MEDIUM" "React Native" "Hermes Bytecode Bundle Detected" \
            "The React Native bundle is compiled to Hermes bytecode (.hbc), not plain JavaScript. This adds a layer of obfuscation but does NOT prevent reverse engineering  hbc disassemblers (hermes-dec, metro-bundler) can recover the source." \
            "Bundle file type: $(file "$bundle" 2>/dev/null)" "CONFIRMED" "general"
        warn "Hermes bytecode detected"
    fi

    success "React Native analysis complete"
}

# 
# MODULE: FLUTTER  Dart Snapshot Analysis
# 
mod_flutter() {
    section "FLUTTER / DART SNAPSHOT ANALYSIS"

    local flutter_so
    flutter_so=$(find "${WORK_DIR}/raw/lib" -name "libflutter.so" 2>/dev/null | head -1 || true)
    local app_so
    app_so=$(find "${WORK_DIR}/raw/lib" -name "libapp.so" 2>/dev/null | head -1 || true)
    local dart_snapshot
    dart_snapshot=$(find "${WORK_DIR}/raw" -name "*.dill" -o -name "kernel_blob.bin" -o \
                        -name "isolate_snapshot_data" -o -name "vm_snapshot_data" 2>/dev/null | head -1 || true)

    if [ -z "$flutter_so" ] && [ -z "$dart_snapshot" ]; then
        info "No Flutter artifacts found  not a Flutter app"
        return
    fi

    info "Flutter app detected"
    add_finding "INFO" "Flutter" "Flutter App Detected" \
        "This app is built with Flutter. Business logic lives in Dart compiled to native ARM code (libapp.so) or as kernel snapshots. Static analysis of Java/Kotlin source is not applicable  use blutter, vm_service, or Frida for dynamic analysis." \
        "libflutter.so: ${flutter_so:-not found} | libapp.so: ${app_so:-not found}" "CONFIRMED" "general"

    #  strings analysis of libapp.so (highest value target)
    if [ -n "$app_so" ] && tool_ok strings; then
        info "Extracting strings from libapp.so..."
        local app_strings
        app_strings=$(strings --text "$app_so" 2>/dev/null || true)

        # Secrets in Dart snapshot
        declare -A DART_PATTERNS=(
            ["AWS Key in libapp.so"]='AKIA[0-9A-Z]{16}'
            ["Google API Key in libapp.so"]='AIza[0-9A-Za-z_-]{35}'
            ["JWT in libapp.so"]='eyJ[A-Za-z0-9_-]{20,}'
            ["Private Key in libapp.so"]='BEGIN.{0,10}PRIVATE KEY'
            ["Hardcoded Secret in libapp.so"]='(?i)(secret|password|api.?key)\s*[:=]\s*[^\s]{8,}'
            ["Firebase URL in libapp.so"]='https://[a-z0-9-]+\.firebaseio\.com'
            ["Internal Endpoint in libapp.so"]='https?://(?:staging|internal|dev|api)\.[a-zA-Z0-9.]+'
            ["HTTP (not HTTPS) Endpoint"]='http://[a-zA-Z0-9._/-]{10,}'
        )

        for name in "${!DART_PATTERNS[@]}"; do
            local hits
            hits=$(echo "$app_strings" | grep --text -oP "${DART_PATTERNS[$name]}" 2>/dev/null | head -3 | tr '\n' ' ' || true)
            if [ -n "$hits" ]; then
                local sev="HIGH"
                [[ "$name" == *"AWS"* || "$name" == *"Private Key"* ]] && sev="CRITICAL"
                add_finding "$sev" "Flutter" "Flutter/Dart: $name" \
                    "Found in libapp.so Dart native snapshot. Even though Dart is compiled to native code, strings are often preserved in the binary and trivially extractable." \
                    "${hits:0:400}" "CONFIRMED" "general"
                warn "Flutter: $name"
            fi
        done

        # Check for debug/profile mode artifacts
        if echo "$app_strings" | grep -q "dart:developer\|observatory\|vm-service\|dart.vm.service" 2>/dev/null; then
            add_finding "HIGH" "Flutter" "Flutter Debug/Profile Mode Artifacts in libapp.so" \
                "The Dart VM service (observatory) strings are present in libapp.so. This may indicate a debug or profile build shipped to production, allowing remote debugging and code injection via the Dart VM service protocol." \
                "dart:developer / vm-service strings found in libapp.so" "LIKELY" "general"
        fi

        # SSL certificate verification
        if echo "$app_strings" | grep -qi "badCertificateCallback\|onBadCertificate\|VERIFY_NONE\|certificateCheck.*false" 2>/dev/null; then
            add_finding "CRITICAL" "Flutter" "SSL Certificate Verification Disabled in Flutter App" \
                "Strings suggesting SSL verification bypass (badCertificateCallback returning true, onBadCertificate) found in Dart snapshot. Flutter apps with this pattern accept ALL TLS certificates, enabling trivial MITM attacks." \
                "$(echo "$app_strings" | grep -i 'badCertificate\|VERIFY_NONE' | head -3 | tr '\n' ' ')" "LIKELY" "trust_all_certs"
        fi

        # Endpoints from libapp.so
        local flutter_endpoints
        flutter_endpoints=$(echo "$app_strings" | grep --text -oP 'https?://[a-zA-Z0-9._\-/]{10,80}' | \
                            grep -v 'example.com\|schemas\|localhost\|pub.dev\|dart.dev\|flutter.dev' | \
                            sort -u | head -20 || true)
        if [ -n "$flutter_endpoints" ]; then
            local ecount
            ecount=$(echo "$flutter_endpoints" | wc -l)
            add_finding "INFO" "Flutter" "API Endpoints Extracted from Dart Snapshot ($ecount found)" \
                "Hardcoded API endpoints found in libapp.so. Review for internal/staging URLs, unauthenticated paths, or architecture disclosure." \
                "$flutter_endpoints" "CONFIRMED" "general"
        fi
    fi

    #  Check for debug flag in libflutter.so
    if [ -n "$flutter_so" ] && tool_ok strings; then
        if strings --text "$flutter_so" 2>/dev/null | grep -q "kDebugMode\|--enable-checked-mode\|profile_period"; then
            add_finding "MEDIUM" "Flutter" "Flutter Debug/Profile Flags in libflutter.so" \
                "Debug or profile mode flags found in libflutter.so. Ensure this is a release build compiled with flutter build apk --release." \
                "kDebugMode / profile flags in libflutter.so" "LIKELY" "general"
        fi
    fi

    success "Flutter analysis complete"
}

# 
# MODULE: CORDOVA / IONIC  WebView-based App Analysis
# 
mod_cordova() {
    section "CORDOVA / IONIC / CAPACITOR ANALYSIS"

    local www_dir
    www_dir=$(find "${WORK_DIR}/raw/assets" -type d -name "www" 2>/dev/null | head -1 || true)
    local capacitor_dir
    capacitor_dir=$(find "${WORK_DIR}/raw/assets" -type d -name "public" 2>/dev/null | head -1 || true)

    local webroot="${www_dir:-$capacitor_dir}"

    if [ -z "$webroot" ]; then
        info "No Cordova/Capacitor www or public directory found"
        return
    fi

    info "Cordova/Ionic/Capacitor app detected: $webroot"

    # Detect framework flavour
    local framework="Cordova"
    [ -f "${webroot}/capacitor.config.json" ] || \
    find "$webroot" -name "capacitor*.js" 2>/dev/null | grep -q . && framework="Capacitor"
    find "$webroot" -name "ionic*.js" 2>/dev/null | grep -q . && framework="Ionic/$framework"

    add_finding "INFO" "Cordova" "$framework App Detected" \
        "This app is built with $framework. All business logic lives in JavaScript/HTML/CSS in assets/www (or assets/public) and is trivially readable. No decompilation needed." \
        "Web root: $webroot" "CONFIRMED" "general"

    #  Cordova config.xml
    local config_xml
    config_xml=$(find "${WORK_DIR}/raw" -name "config.xml" 2>/dev/null | head -1 || true)
    if [ -n "$config_xml" ]; then
        # Allow-navigation / allow-intent (open redirect / XSS)
        if grep -q 'allow-navigation href="\*"' "$config_xml" 2>/dev/null; then
            add_finding "HIGH" "Cordova" "Cordova allow-navigation Wildcard (*)" \
                "config.xml contains <allow-navigation href='*'> allowing the WebView to navigate to ANY URL. This can be exploited via XSS or deep link injection to redirect to attacker-controlled pages that have full native bridge access." \
                "$(grep 'allow-navigation' "$config_xml")" "CONFIRMED" "js_enabled"
        fi
        if grep -q 'allow-intent href="\*"' "$config_xml" 2>/dev/null; then
            add_finding "MEDIUM" "Cordova" "Cordova allow-intent Wildcard (*)" \
                "config.xml allows all external intents. Combined with XSS, an attacker could open arbitrary URLs in the system browser or launch external apps." \
                "$(grep 'allow-intent' "$config_xml")" "CONFIRMED" "general"
        fi
        # access origin wildcard
        if grep -q 'access origin="\*"' "$config_xml" 2>/dev/null; then
            add_finding "HIGH" "Cordova" "Cordova Network Access Wildcard (*)" \
                "config.xml <access origin='*'> allows the app to make XHR requests to any domain, bypassing same-origin policy. This enables data exfiltration via XSS to any attacker-controlled server." \
                "$(grep 'access origin' "$config_xml")" "CONFIRMED" "general"
        fi
        # Outdated Cordova version
        local cordova_ver
        cordova_ver=$(grep -oP 'cordova-android version="\K[^"]+' "$config_xml" 2>/dev/null || true)
        if [ -n "$cordova_ver" ]; then
            info "Cordova Android version: $cordova_ver"
            add_finding "INFO" "Cordova" "Cordova Version: $cordova_ver  Verify for CVEs" \
                "Identified Cordova Android version $cordova_ver. Verify this version against known CVEs (e.g. CVE-2020-11017 for Cordova < 9.0). Outdated Cordova versions may have XSS-to-RCE bridge vulnerabilities." \
                "cordova-android: $cordova_ver" "CONFIRMED" "general"
        fi
    fi

    #  Scan JS/HTML source in www
    info "Scanning Cordova www directory..."
    declare -A WWW_PATTERNS=(
        ["Hardcoded API Key in JS"]='(?i)(api[_-]?key|apikey)\s*[:=]\s*["\x27][A-Za-z0-9_\-]{16,}'
        ["Hardcoded Secret in JS"]='(?i)(secret|password|token)\s*[:=]\s*["\x27][^"\x27]{8,}'
        ["eval() in JS (Code Injection)"]='(?<![a-zA-Z])eval\s*\('
        ["document.write (XSS risk)"]='document\.write\s*\('
        ["innerHTML assignment (XSS)"]='\.innerHTML\s*='
        ["Disabled SSL in XHR"]='(?i)rejectUnauthorized\s*:\s*false'
        ["HTTP Endpoint in JS"]='fetch\s*\(\s*["\x27]http://|XMLHttpRequest.*open.*["\x27]http://'
        ["localStorage Sensitive Data"]='localStorage\.setItem\s*\(.*(?i)(password|token|secret|key)'
        ["sessionStorage Sensitive Data"]='sessionStorage\.setItem\s*\(.*(?i)(password|token|secret|key)'
        ["cordova.exec with User Input"]='cordova\.exec\s*\(.*\+[^;]{0,80}'
        ["AWS Key in www"]='AKIA[0-9A-Z]{16}'
        ["Google API Key in www"]='AIza[0-9A-Za-z_-]{35}'
        ["JWT in www"]='eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}'
        ["Outdated jQuery XSS vectors"]='jquery[/-]1\.[0-9]\.'
        ["Angular bypassSecurityTrust"]='bypassSecurityTrust(Html|Script|ResourceUrl|Style|Url)'
    )

    for name in "${!WWW_PATTERNS[@]}"; do
        local pat="${WWW_PATTERNS[$name]}"
        local hits
        hits=$(grep --text -rhoP "$pat" "$webroot" \
               --include="*.js" --include="*.html" --include="*.ts" --include="*.json" \
               2>/dev/null | head -3 | tr '\n' ' ' || true)
        if [ -n "$hits" ]; then
            local sev="HIGH"
            [[ "$name" == *"AWS"* || "$name" == *"Disabled SSL"* ]] && sev="CRITICAL"
            [[ "$name" == *"eval"* || "$name" == *"innerHTML"* ]] && sev="MEDIUM"
            add_finding "$sev" "Cordova" "Cordova/JS: $name" \
                "Detected '$name' in Cordova web assets. JavaScript is completely readable without any reverse engineering  this is a clear text disclosure." \
                "${hits:0:400}" "CONFIRMED" "general"
            warn "Cordova: $name"
        fi
    done

    #  List all unique API endpoints
    local js_endpoints
    js_endpoints=$(grep --text -rhoP 'https?://[a-zA-Z0-9._\-/]{10,80}' "$webroot" \
                   --include="*.js" --include="*.html" --include="*.json" 2>/dev/null | \
                   grep -v 'example.com\|schemas\|localhost\|w3.org\|cdn\.' | \
                   sort -u | head -25 || true)
    if [ -n "$js_endpoints" ]; then
        local ecount
        ecount=$(echo "$js_endpoints" | wc -l)
        add_finding "INFO" "Cordova" "API Endpoints in Cordova Web Assets ($ecount found)" \
            "All API endpoints are in plain JS  fully readable. Review for internal URLs, unauthenticated paths, staging environments." \
            "$js_endpoints" "CONFIRMED" "general"
    fi

    #  Plugin audit
    local plugins
    plugins=$(find "${WORK_DIR}/raw" -name "cordova_plugins.js" 2>/dev/null | head -1 || true)
    if [ -n "$plugins" ]; then
        info "Auditing Cordova plugins..."
        local dangerous_plugins=("cordova-plugin-file" "cordova-plugin-contacts"
                                  "cordova-plugin-camera" "cordova-plugin-media"
                                  "cordova-plugin-inappbrowser" "phonegap-plugin-contentsync"
                                  "cordova-plugin-whitelist" "cordova-sqlite-storage")
        for dp in "${dangerous_plugins[@]}"; do
            if grep -q "$dp" "$plugins" 2>/dev/null; then
                add_finding "MEDIUM" "Cordova" "Sensitive Cordova Plugin: $dp" \
                    "Plugin '$dp' is installed. If exploited via XSS in the WebView, this plugin could give an attacker access to files, contacts, camera, or media storage. Verify that plugin access is properly restricted." \
                    "Plugin: $dp in cordova_plugins.js" "LIKELY" "js_interface"
            fi
        done
    fi

    success "Cordova/Ionic analysis complete"
}

# 
# MODULE: MOBSF REST API INTEGRATION
# 
mod_mobsf() {
    section "MOBSF REST API INTEGRATION"

    if [ -z "$MOBSF_APIKEY" ]; then
        info "MobSF integration disabled. Set MOBSF_APIKEY env var to enable."
        info "  export MOBSF_APIKEY=<your-key>  (found in MobSF Settings)"
        info "  export MOBSF_URL=http://localhost:8000  (default)"
        return
    fi

    # Test MobSF connectivity
    local ping
    ping=$(timeout 5 curl -sk "${MOBSF_URL}/api/v1/version" \
           -H "Authorization: ${MOBSF_APIKEY}" 2>/dev/null || echo "")
    if ! echo "$ping" | grep -q "version"; then
        warn "MobSF not reachable at ${MOBSF_URL}  skipping"
        warn "Start MobSF with: docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf"
        return
    fi

    info "MobSF reachable. Uploading APK..."

    # Upload
    local upload_resp
    upload_resp=$(timeout 60 curl -sk "${MOBSF_URL}/api/v1/upload" \
        -H "Authorization: ${MOBSF_APIKEY}" \
        -F "file=@${WORK_DIR}/target.apk" 2>/dev/null || echo "")
    local hash
    hash=$(echo "$upload_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('hash',''))" 2>/dev/null || echo "")

    if [ -z "$hash" ]; then
        warn "MobSF upload failed: $upload_resp"
        return
    fi

    info "MobSF hash: $hash  triggering scan..."
    timeout 120 curl -sk "${MOBSF_URL}/api/v1/scan" \
        -H "Authorization: ${MOBSF_APIKEY}" \
        -d "scan_type=apk&file_name=target.apk&hash=${hash}" > /dev/null 2>&1 || true

    sleep 5

    # Fetch JSON report
    info "Fetching MobSF report..."
    local mobsf_report="${WORK_DIR}/mobsf_report.json"
    timeout 30 curl -sk "${MOBSF_URL}/api/v1/report_json" \
        -H "Authorization: ${MOBSF_APIKEY}" \
        -d "hash=${hash}" > "$mobsf_report" 2>/dev/null || true

    if [ ! -s "$mobsf_report" ]; then
        warn "MobSF report empty"
        return
    fi

    # Parse and add MobSF findings to our report
    python3 - "$mobsf_report" "${SHARD_DIR}/shard_mobsf.ndjson" << 'PYEOF'
import sys, json

sev_map = {'high':'HIGH','warning':'HIGH','medium':'MEDIUM',
           'info':'INFO','secure':'INFO','hotspot':'MEDIUM'}

try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except Exception as e:
    print(f"MobSF parse error: {e}")
    sys.exit(0)

output = []
seen = set()

# Manifest analysis findings
for item in data.get('manifest_analysis', {}).get('manifest_findings', []):
    title = item.get('title', '')
    sev_raw = item.get('severity','info').lower()
    sev = sev_map.get(sev_raw, 'MEDIUM')
    desc = item.get('description','')
    if title not in seen:
        seen.add(title)
        output.append(json.dumps({
            'severity': sev, 'category': 'MobSF / Manifest',
            'title': f'MobSF: {title}', 'description': desc,
            'evidence': 'Source: MobSF manifest analysis',
            'confidence': 'CONFIRMED',
            'cvss_score': {'HIGH':7.5,'MEDIUM':5.0,'LOW':3.0,'INFO':1.0}.get(sev,5.0),
            'remediation': 'See MobSF report for detailed remediation guidance.'
        }))

# Code analysis findings
for item in data.get('code_analysis', {}).get('findings', {}).values():
    title = item.get('metadata',{}).get('cwe','') + ' ' + item.get('metadata',{}).get('masvs','')
    sev_raw = item.get('metadata',{}).get('severity','info').lower()
    sev = sev_map.get(sev_raw, 'MEDIUM')
    desc = item.get('metadata',{}).get('description','')
    files = str(list(item.get('files',{}).keys())[:3])
    key = title[:60]
    if key not in seen and title.strip():
        seen.add(key)
        output.append(json.dumps({
            'severity': sev, 'category': 'MobSF / Code Analysis',
            'title': f'MobSF: {title.strip()}', 'description': desc,
            'evidence': f'Files: {files}',
            'confidence': 'LIKELY',
            'cvss_score': {'HIGH':7.0,'MEDIUM':5.0,'LOW':3.0,'INFO':1.0}.get(sev,5.0),
            'remediation': 'Refer to MobSF code analysis report and OWASP MASVS for remediation.'
        }))

with open(sys.argv[2], 'w') as f:
    f.write('\n'.join(output))

print(f"MobSF contributed {len(output)} additional findings")
PYEOF

    success "MobSF integration complete  report augmented"
    info "MobSF full report: ${MOBSF_URL}/static_analyzer/?name=target.apk&checksum=${hash}&type=apk"
}

# 
# MODULE: FLOWDROID  INTER-PROCEDURAL TAINT ANALYSIS
# 
#
#  FlowDroid performs a full inter-procedural, context-sensitive, flow-sensitive
#  taint analysis of Android DEX bytecode. Unlike our regex checks (which only
#  see single-line patterns), FlowDroid builds a complete call graph and traces
#  data from SOURCES (getIntent, getSharedPreferences, getQueryParameter, etc.)
#  to SINKS (rawQuery, exec, openFile, Log.d, sendBroadcast, etc.) across any
#  number of intermediate method calls.
#
#  Requirements (auto-handled by this module):
#    - Java 8 or 11  (NOT Java 17+  FlowDroid uses old Soot internals)
#    - FlowDroid JAR  (auto-downloaded to ~/.android_audit/flowdroid/)
#    - android.jar platform stub  (auto-downloaded  API 29 by default)
#    - ~4 GB heap    (configurable via FLOWDROID_HEAP env var)
#    - 520 minutes on a typical app  (skippable: --skip modules:flowdroid)
#
#  Override defaults:
#    export FLOWDROID_HEAP=6g          # increase for large/complex APKs
#    export FLOWDROID_TIMEOUT=1200     # seconds (default 900)
#    export FLOWDROID_PLATFORM_API=33  # Android platform API level for stubs
# 
mod_flowdroid() {
    section "FLOWDROID  INTER-PROCEDURAL TAINT ANALYSIS"

    local FD_HOME="${HOME}/.android_audit/flowdroid"
    local FD_JAR="${FD_HOME}/soot-infoflow-cmd.jar"
    local FD_SOURCES="${FD_HOME}/SourcesAndSinks.txt"
    local FD_PLATFORMS="${FD_HOME}/platforms"
    local FD_HEAP="${FLOWDROID_HEAP:-4g}"
    local FD_TIMEOUT="${FLOWDROID_TIMEOUT:-900}"
    local FD_API="${FLOWDROID_PLATFORM_API:-29}"
    local FD_RESULTS="${WORK_DIR}/flowdroid_results.xml"
    local FD_LOG="${WORK_DIR}/flowdroid.log"

    mkdir -p "$FD_HOME" "$FD_PLATFORMS"

    #  Java version check 
    if ! tool_ok java; then
        warn "Java not found  FlowDroid requires Java 8 or 11"
        add_finding "INFO" "FlowDroid" "FlowDroid Skipped  Java Not Found" \
            "FlowDroid taint analysis requires Java 8 or 11. Install with: sudo apt install openjdk-11-jdk" \
            "java not in PATH" "CONFIRMED" "general"
        return
    fi

    local java_ver
    java_ver=$(java -version 2>&1 | grep -oP '(?<=version ")[0-9]+' | head -1 || echo "0")
    # Handle Java 8 reporting as "1.8"
    [[ "$java_ver" == "1" ]] && java_ver=$(java -version 2>&1 | grep -oP '1\.\K[0-9]+' | head -1 || echo "8")

    if [ "$java_ver" -gt 11 ] 2>/dev/null; then
        warn "Java $java_ver detected  FlowDroid requires Java 8 or 11"
        warn "Install Java 11: sudo apt install openjdk-11-jdk"
        warn "Switch: sudo update-alternatives --config java"

        # Try to find a compatible Java in common locations
        local compat_java=""
        for jpath in /usr/lib/jvm/java-11-openjdk-amd64/bin/java \
                     /usr/lib/jvm/java-8-openjdk-amd64/bin/java \
                     /usr/local/lib/jvm/java-11/bin/java; do
            if [ -x "$jpath" ]; then
                compat_java="$jpath"
                info "Found compatible Java: $compat_java"
                break
            fi
        done

        if [ -z "$compat_java" ]; then
            add_finding "MEDIUM" "FlowDroid" "FlowDroid Skipped  No Compatible Java (need 8 or 11, found $java_ver)" \
                "FlowDroid uses Soot internals incompatible with Java 17+. Install Java 11: sudo apt install openjdk-11-jdk && sudo update-alternatives --config java" \
                "Detected Java version: $java_ver" "CONFIRMED" "general"
            return
        fi
        JAVA_CMD="$compat_java"
    else
        JAVA_CMD="java"
        info "Java $java_ver detected  compatible with FlowDroid"
    fi

    #  Download FlowDroid JAR if missing 
    if [ ! -f "$FD_JAR" ]; then
        info "FlowDroid JAR not found  downloading..."
        local FD_URL="https://github.com/secure-software-engineering/FlowDroid/releases/download/v2.13/soot-infoflow-cmd-jar-with-dependencies.jar"
        local FD_URL_FALLBACK="https://github.com/secure-software-engineering/FlowDroid/releases/download/v2.12/soot-infoflow-cmd-jar-with-dependencies.jar"

        if timeout 120 curl -fsSL "$FD_URL" -o "${FD_JAR}.tmp" 2>/dev/null; then
            mv "${FD_JAR}.tmp" "$FD_JAR"
            success "FlowDroid v2.13 downloaded"
        elif timeout 120 curl -fsSL "$FD_URL_FALLBACK" -o "${FD_JAR}.tmp" 2>/dev/null; then
            mv "${FD_JAR}.tmp" "$FD_JAR"
            success "FlowDroid v2.12 downloaded (fallback)"
        else
            warn "Could not download FlowDroid  network may be restricted"
            info "Manual install: download soot-infoflow-cmd-jar-with-dependencies.jar"
            info "from https://github.com/secure-software-engineering/FlowDroid/releases"
            info "and place it at: $FD_JAR"
            add_finding "INFO" "FlowDroid" "FlowDroid JAR Download Failed  Taint Analysis Skipped" \
                "Could not download FlowDroid automatically. Download manually from GitHub releases and place at $FD_JAR" \
                "URL: $FD_URL" "CONFIRMED" "general"
            return
        fi
    fi

    #  Download Android platform stubs if missing 
    local platform_jar="${FD_PLATFORMS}/android-${FD_API}/android.jar"
    if [ ! -f "$platform_jar" ]; then
        info "Downloading Android API ${FD_API} platform stub (android.jar)..."
        mkdir -p "${FD_PLATFORMS}/android-${FD_API}"

        # Try to get from locally installed Android SDK first
        local sdk_jar=""
        for sdk_root in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" \
                        "${HOME}/Android/Sdk" "/opt/android-sdk" \
                        "/usr/lib/android-sdk"; do
            [ -z "$sdk_root" ] && continue
            local candidate="${sdk_root}/platforms/android-${FD_API}/android.jar"
            if [ -f "$candidate" ]; then
                sdk_jar="$candidate"
                break
            fi
        done

        if [ -n "$sdk_jar" ]; then
            cp "$sdk_jar" "$platform_jar"
            success "Copied android.jar from local SDK: $sdk_jar"
        else
            # Download from a reliable mirror
            info "Android SDK not found locally  downloading android.jar stub..."
            local JAR_URL="https://github.com/Sable/android-platforms/raw/master/android-${FD_API}/android.jar"
            if timeout 120 curl -fsSL "$JAR_URL" -o "$platform_jar" 2>/dev/null; then
                success "Downloaded android-${FD_API}/android.jar"
            else
                warn "Could not download android.jar for API ${FD_API}"
                warn "Set ANDROID_HOME to your SDK path, or run:"
                warn "  sdkmanager 'platforms;android-${FD_API}'"
                add_finding "INFO" "FlowDroid" "FlowDroid Platform Stub Download Failed" \
                    "android.jar for API $FD_API could not be downloaded. Set ANDROID_HOME to your Android SDK root or run: sdkmanager 'platforms;android-${FD_API}'" \
                    "Platform jar needed at: $platform_jar" "CONFIRMED" "general"
                return
            fi
        fi
    fi

    #  Write curated Sources & Sinks list 
    # Comprehensive Android-specific source/sink list covering OWASP Mobile Top 10
    cat > "$FD_SOURCES" << 'SOURCESINKS'
[Sources]
<android.content.Intent: android.os.Bundle getExtras()> -> _RETURN_
<android.content.Intent: java.lang.String getStringExtra(java.lang.String)> -> _RETURN_
<android.content.Intent: int getIntExtra(java.lang.String,int)> -> _RETURN_
<android.content.Intent: android.net.Uri getData()> -> _RETURN_
<android.content.Intent: java.lang.String getAction()> -> _RETURN_
<android.content.Intent: java.lang.String getDataString()> -> _RETURN_
<android.content.ContentResolver: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)> -> _RETURN_
<android.content.SharedPreferences: java.lang.String getString(java.lang.String,java.lang.String)> -> _RETURN_
<android.content.SharedPreferences: int getInt(java.lang.String,int)> -> _RETURN_
<android.database.Cursor: java.lang.String getString(int)> -> _RETURN_
<android.database.Cursor: int getInt(int)> -> _RETURN_
<android.net.Uri: java.lang.String getQueryParameter(java.lang.String)> -> _RETURN_
<android.net.Uri: java.lang.String getPath()> -> _RETURN_
<android.net.Uri: java.lang.String getLastPathSegment()> -> _RETURN_
<android.net.Uri: java.lang.String getFragment()> -> _RETURN_
<android.net.Uri: java.lang.String getHost()> -> _RETURN_
<java.io.BufferedReader: java.lang.String readLine()> -> _RETURN_
<java.util.Scanner: java.lang.String next()> -> _RETURN_
<java.util.Scanner: java.lang.String nextLine()> -> _RETURN_
<android.content.ClipboardManager: android.content.ClipData getPrimaryClip()> -> _RETURN_
<android.telephony.TelephonyManager: java.lang.String getDeviceId()> -> _RETURN_
<android.telephony.TelephonyManager: java.lang.String getSubscriberId()> -> _RETURN_
<android.location.Location: double getLatitude()> -> _RETURN_
<android.location.Location: double getLongitude()> -> _RETURN_
<android.accounts.AccountManager: android.accounts.Account[] getAccounts()> -> _RETURN_
<android.content.res.AssetManager: java.io.InputStream open(java.lang.String)> -> _RETURN_
<java.lang.System: java.lang.String getenv(java.lang.String)> -> _RETURN_
<java.lang.System: java.util.Properties getProperties()> -> _RETURN_

[Sinks]
<android.database.sqlite.SQLiteDatabase: android.database.Cursor rawQuery(java.lang.String,java.lang.String[])> -> 0
<android.database.sqlite.SQLiteDatabase: void execSQL(java.lang.String)> -> 0
<android.database.sqlite.SQLiteDatabase: long insert(java.lang.String,java.lang.String,android.content.ContentValues)> -> _RETURN_
<android.util.Log: int d(java.lang.String,java.lang.String)> -> 0|1
<android.util.Log: int v(java.lang.String,java.lang.String)> -> 0|1
<android.util.Log: int i(java.lang.String,java.lang.String)> -> 0|1
<android.util.Log: int w(java.lang.String,java.lang.String)> -> 0|1
<android.util.Log: int e(java.lang.String,java.lang.String)> -> 0|1
<java.io.FileOutputStream: void write(byte[])> -> 0
<java.io.FileWriter: void write(java.lang.String)> -> 0
<java.io.PrintStream: void println(java.lang.String)> -> 0
<java.lang.Runtime: java.lang.Process exec(java.lang.String)> -> 0
<java.lang.Runtime: java.lang.Process exec(java.lang.String[])> -> 0
<android.webkit.WebView: void loadUrl(java.lang.String)> -> 0
<android.webkit.WebView: void loadData(java.lang.String,java.lang.String,java.lang.String)> -> 0
<android.webkit.WebView: void evaluateJavascript(java.lang.String,android.webkit.ValueCallback)> -> 0
<android.content.Intent: void putExtra(java.lang.String,java.lang.String)> -> 1
<android.content.Context: void sendBroadcast(android.content.Intent)> -> 0
<java.net.URL: java.net.URLConnection openConnection()> -> _RETURN_
<okhttp3.Request$Builder: okhttp3.Request$Builder url(java.lang.String)> -> 0
<java.io.ObjectOutputStream: void writeObject(java.lang.Object)> -> 0
<android.content.SharedPreferences$Editor: android.content.SharedPreferences$Editor putString(java.lang.String,java.lang.String)> -> 1
<android.content.ContentResolver: int update(android.net.Uri,android.content.ContentValues,java.lang.String,java.lang.String[])> -> 2
<android.content.ContentResolver: android.net.Uri insert(android.net.Uri,android.content.ContentValues)> -> _RETURN_
<android.telephony.SmsManager: void sendTextMessage(java.lang.String,java.lang.String,java.lang.String,android.app.PendingIntent,android.app.PendingIntent)> -> 2
SOURCESINKS

    #  Run FlowDroid 
    info "Running FlowDroid taint analysis (this takes 520 minutes)..."
    info "Heap: ${FD_HEAP} | Timeout: ${FD_TIMEOUT}s | Platform API: ${FD_API}"
    info "Source/sink list: $FD_SOURCES"
    info "Skip with: --skip modules:flowdroid"

    local start_time=$SECONDS

    timeout "$FD_TIMEOUT" "$JAVA_CMD" \
        "-Xmx${FD_HEAP}" \
        -jar "$FD_JAR" \
        --apkfile   "${WORK_DIR}/target.apk" \
        --platformsdir "$FD_PLATFORMS" \
        --sourcesandsinks "$FD_SOURCES" \
        --outputfile "$FD_RESULTS" \
        --callbacksource \
        --implicit \
        --aliasflowins \
        --aplength 5 \
        --accesspath 3 \
        > "$FD_LOG" 2>&1

    local fd_exit=$?
    local elapsed=$(( SECONDS - start_time ))

    if [ $fd_exit -eq 124 ]; then
        warn "FlowDroid timed out after ${FD_TIMEOUT}s  partial results may exist"
        warn "Increase timeout: export FLOWDROID_TIMEOUT=1800"
        add_finding "MEDIUM" "FlowDroid" "FlowDroid Analysis Timed Out (${FD_TIMEOUT}s)" \
            "FlowDroid exceeded the timeout limit. The APK may be very large or complex. Results are partial. Increase timeout with: export FLOWDROID_TIMEOUT=1800" \
            "Elapsed: ${elapsed}s | Timeout: ${FD_TIMEOUT}s" "CONFIRMED" "general"
    elif [ $fd_exit -ne 0 ] && [ ! -s "$FD_RESULTS" ]; then
        warn "FlowDroid exited with code $fd_exit"
        local fd_err
        fd_err=$(tail -20 "$FD_LOG" 2>/dev/null | tr '\n' ' ')
        add_finding "INFO" "FlowDroid" "FlowDroid Analysis Failed (exit $fd_exit)" \
            "FlowDroid did not complete successfully. Common causes: incompatible Java version, insufficient heap memory, or a packed/corrupt APK. Check $FD_LOG for details." \
            "Exit: $fd_exit | Last log: $fd_err" "CONFIRMED" "general"
        return
    fi

    info "FlowDroid completed in ${elapsed}s"

    #  Parse FlowDroid XML results 
    if [ ! -s "$FD_RESULTS" ]; then
        info "FlowDroid found no taint flows (clean result or analysis failed)"
        return
    fi

    python3 - "$FD_RESULTS" "${SHARD_DIR}/shard_flowdroid.ndjson" << 'PYEOF'
import sys, json, xml.etree.ElementTree as ET

results_path = sys.argv[1]
shard_path   = sys.argv[2]

try:
    tree = ET.parse(results_path)
    root = tree.getroot()
except ET.ParseError as e:
    print(f"FlowDroid XML parse error: {e}")
    sys.exit(0)

output = []

#  Sink-category to severity + remediation key mapping 
SINK_SEVERITY = {
    'rawQuery':           ('CRITICAL', 'sql_injection',       'SQL Injection via Taint Flow'),
    'execSQL':            ('CRITICAL', 'sql_injection',       'SQL Injection via Taint Flow'),
    'exec(':              ('CRITICAL', 'general',             'OS Command Injection via Taint Flow'),
    'loadUrl':            ('CRITICAL', 'js_enabled',          'WebView URL Injection via Taint Flow'),
    'evaluateJavascript': ('CRITICAL', 'js_interface',        'WebView JS Injection via Taint Flow'),
    'Log.':               ('HIGH',     'log_sensitive',       'Sensitive Data Logged via Taint Flow'),
    'sendBroadcast':      ('HIGH',     'exported_receiver',   'Sensitive Data in Broadcast via Taint Flow'),
    'putExtra':           ('HIGH',     'mutable_pending_intent','Sensitive Data Leak via Intent Extra'),
    'FileOutputStream':   ('HIGH',     'external_storage',   'Sensitive Data Written to File via Taint Flow'),
    'FileWriter':         ('HIGH',     'external_storage',   'Sensitive Data Written to File via Taint Flow'),
    'SharedPreferences':  ('MEDIUM',   'backup_sensitive',   'Sensitive Data in SharedPrefs via Taint Flow'),
    'sendTextMessage':    ('HIGH',     'general',             'Sensitive Data in SMS via Taint Flow'),
    'openConnection':     ('HIGH',     'cleartext',           'Sensitive Data in Network Request via Taint Flow'),
    'url(':               ('HIGH',     'cleartext',           'Sensitive Data in Network Request via Taint Flow'),
    'println':            ('MEDIUM',   'log_sensitive',       'Sensitive Data Printed via Taint Flow'),
}

DEFAULT_SEV   = ('MEDIUM', 'general', 'Taint Flow: Source to Sink')

def classify_sink(sink_method: str):
    for key, val in SINK_SEVERITY.items():
        if key.lower() in sink_method.lower():
            return val
    return DEFAULT_SEV

def format_path(path_elem):
    """Format a FlowDroid taint path into human-readable evidence."""
    steps = []
    for node in path_elem.findall('.//PathElement'):
        stmt      = node.get('Statement', '')
        method    = node.get('Method', '')
        classname = node.get('Class', '').split('.')[-1]
        line      = node.get('LineNumber', '?')
        if stmt or method:
            steps.append(f"  [{classname}.java:{line}] {stmt or method}")
    return '\n'.join(steps[:12]) if steps else 'Path details not available'

# Find all DataFlowResult / Result elements
# FlowDroid XML schema varies by version  handle both
results = root.findall('.//Result') or root.findall('.//DataFlowResult')

print(f"FlowDroid found {len(results)} taint flows")

for result in results:
    # Source
    source_elem  = result.find('.//Source') or result.find('Source')
    sink_elem    = result.find('.//Sink')   or result.find('Sink')
    path_elem    = result.find('.//Path')   or result.find('Path')

    if source_elem is None or sink_elem is None:
        continue

    source_stmt   = source_elem.get('Statement', source_elem.get('method', 'unknown source'))
    source_method = source_elem.get('Method',    '')
    source_class  = source_elem.get('Class',     '').split('.')[-1]
    source_line   = source_elem.get('LineNumber', '?')

    sink_stmt     = sink_elem.get('Statement',   sink_elem.get('method', 'unknown sink'))
    sink_method   = sink_elem.get('Method',      '')
    sink_class    = sink_elem.get('Class',       '').split('.')[-1]
    sink_line     = sink_elem.get('LineNumber',  '?')

    sev, rem_key, label = classify_sink(sink_stmt + sink_method)

    # Build call-chain evidence
    path_str = format_path(path_elem) if path_elem is not None else ''

    evidence = (
        f"SOURCE: {source_stmt}\n"
        f"  in {source_class}.java:{source_line} [{source_method}]\n\n"
        f"SINK:   {sink_stmt}\n"
        f"  in {sink_class}.java:{sink_line} [{sink_method}]\n\n"
        f"TAINT PATH:\n{path_str}"
    )

    title = (
        f"FlowDroid: {label} "
        f"({source_class}:{source_line}  {sink_class}:{sink_line})"
    )

    desc = (
        f"FlowDroid detected a confirmed inter-procedural taint flow from "
        f"'{source_stmt.strip()}' (in {source_class}) to "
        f"'{sink_stmt.strip()}' (in {sink_class}). "
        f"This is a multi-hop data flow that regex-only analysis cannot detect  "
        f"the tainted value travels through the call graph before reaching the dangerous sink. "
        f"Severity: {sev}."
    )

    cvss = {'CRITICAL':9.5,'HIGH':7.5,'MEDIUM':5.5,'LOW':3.0}.get(sev, 5.0)

    rem_map = {
        'sql_injection':    'Use parameterized queries: db.query(table, cols, "col=?", new String[]{val}, ...). Never pass tainted data into rawQuery() or execSQL() directly.',
        'log_sensitive':    'Remove Log.d/v/i/e/w calls that receive tainted (user/intent) data. Strip logging in release: -assumenosideeffects class android.util.Log { public static *** d(...); }',
        'js_enabled':       'Validate and sanitize any URL passed to WebView.loadUrl(). Never pass intent extras or URI params directly to loadUrl() without checking the scheme and host.',
        'js_interface':     'Never pass tainted data to evaluateJavascript(). Validate all content before injecting into WebView JS context.',
        'external_storage': 'Do not write tainted data to files without sanitization. Store sensitive data in encrypted internal storage only.',
        'cleartext':        'Do not include tainted data in network requests without encryption and proper parameterization. Use HTTPS and validate server identity.',
        'general':          'Sanitize or validate data from intent extras, URI parameters, and user input before using it in sensitive operations.',
    }

    entry = {
        'severity':    sev,
        'category':    'FlowDroid / Taint Analysis',
        'title':       title,
        'description': desc,
        'evidence':    evidence,
        'confidence':  'CONFIRMED',
        'cvss_score':  cvss,
        'remediation': rem_map.get(rem_key, rem_map['general'])
    }
    output.append(json.dumps(entry))

with open(shard_path, 'w') as f:
    f.write('\n'.join(output))

print(f"FlowDroid: {len(output)} taint flows written to shard")
PYEOF

    local flow_count
    flow_count=$(wc -l < "${SHARD_DIR}/shard_flowdroid.ndjson" 2>/dev/null || echo 0)
    if [ "$flow_count" -gt 0 ]; then
        success "FlowDroid found $flow_count inter-procedural taint flows in ${elapsed}s"
        warn "These are multi-hop flows invisible to regex analysis  prioritise review"
    else
        success "FlowDroid: no taint flows detected in ${elapsed}s"
    fi
}

# 
# MODULE: ICC / IccTA  CROSS-COMPONENT INTENT CHAIN TAINT ANALYSIS
# 
#
#  Models Android Inter-Component Communication (ICC) as a graph:
#    exported_component  startActivity/startService/sendBroadcast  target_component
#
#  Detects privilege escalation chains that single-component FlowDroid misses:
#    Exported Activity A (no permission)  passes Intent extras  Service B
#     Service B queries ContentProvider C  C returns sensitive data to A
#
#  Also detects:
#    - Confused deputy attacks (unprivileged  privileged component via Intent)
#    - Pending Intent theft (mutable PI passed through exported component)
#    - Broadcast-to-Activity launchers (can bypass task stack security)
#    - Deep link  sensitive Activity chains
# 
mod_iccta() {
    section "ICC / CROSS-COMPONENT INTENT CHAIN ANALYSIS"

    local src="${WORK_DIR}/jadx_out"
    local manifest
    manifest=$(find "${WORK_DIR}/apktool_out" -maxdepth 1 -name "AndroidManifest.xml" 2>/dev/null | head -1 || true)

    # Never fall back to raw/AndroidManifest.xml  it's binary (not decoded XML)
    if [ -z "$manifest" ] || [ ! -f "$manifest" ]; then
        warn "ICC analysis requires apktool-decoded AndroidManifest.xml  skipping"
        warn "Ensure apktool completed successfully"
        return
    fi

    # Quick sanity check: decoded manifest should start with XML
    if ! head -c 6 "$manifest" | grep -q '<?xml\|<mani'; then
        warn "Manifest at $manifest appears binary (apktool decode may have failed)  skipping ICC"
        return
    fi

    info "Building component graph from manifest + source..."

    #  Step 1: Extract all exported components from manifest 
    python3 - "$manifest" "${WORK_DIR}/icc_exported.json" << 'PYEOF'
import sys, json, xml.etree.ElementTree as ET

NS = 'http://schemas.android.com/apk/res/android'
manifest_path = sys.argv[1]
out_path = sys.argv[2]

try:
    root = ET.parse(manifest_path).getroot()
except Exception as e:
    print(f"Manifest parse error: {e}")
    sys.exit(1)

exported = []
for tag in ['activity', 'service', 'receiver', 'provider']:
    for elem in root.iter(tag):
        name       = elem.get(f'{{{NS}}}name', '')
        exp_attr   = elem.get(f'{{{NS}}}exported', '')
        has_filter = elem.find('intent-filter') is not None
        permission = elem.get(f'{{{NS}}}permission', '')
        is_exported = exp_attr == 'true' or (has_filter and exp_attr == '')
        actions = [a.get(f'{{{NS}}}name','') for a in elem.findall('.//action')]
        schemes = [d.get(f'{{{NS}}}scheme','') for d in elem.findall('.//data') if d.get(f'{{{NS}}}scheme')]
        if is_exported:
            exported.append({
                'type': tag, 'name': name, 'permission': permission,
                'has_filter': has_filter, 'actions': actions,
                'schemes': schemes, 'protected': bool(permission)
            })

with open(out_path, 'w') as f:
    json.dump(exported, f, indent=2)
print(f"Found {len(exported)} exported components")
PYEOF

    if [ ! -s "${WORK_DIR}/icc_exported.json" ]; then
        warn "No exported components found for ICC analysis"
        return
    fi

    #  Step 2: Build ICC call graph from source 
    # For each exported component, find what it sends Intents to
    python3 - "$src" "${WORK_DIR}/icc_exported.json" "${WORK_DIR}/icc_graph.json" << 'PYEOF'
import sys, os, json, re, glob

src_root     = sys.argv[1]
exported_path= sys.argv[2]
graph_path   = sys.argv[3]

with open(exported_path) as f:
    exported = json.load(f)

exported_names = {c['name'].split('.')[-1]: c for c in exported}

# Patterns that launch/communicate with other components
ICC_PATTERNS = {
    'startActivity':         r'startActivity\s*\(\s*(\w+)',
    'startService':          r'startService\s*\(\s*(\w+)',
    'bindService':           r'bindService\s*\(\s*(\w+)',
    'sendBroadcast':         r'sendBroadcast\s*\(\s*(\w+)',
    'sendOrderedBroadcast':  r'sendOrderedBroadcast\s*\(\s*(\w+)',
    'startActivityForResult':r'startActivityForResult\s*\(\s*(\w+)',
    'getContentResolver':    r'getContentResolver\s*\(\)',
    'setComponent':          r'setComponent\s*\(.*?new\s+ComponentName\s*\([^)]+,\s*["\']([^"\']+)["\']',
    'setClass':              r'setClass\s*\([^,]+,\s*(\w+)\.class',
    'PendingIntent.get':     r'PendingIntent\.get\w+\s*\([^,]+,\s*\d+,\s*(\w+)',
    'explicit_intent':       r'new\s+Intent\s*\([^,]+,\s*(\w+)\.class',
    'implicit_intent':       r'new\s+Intent\s*\(\s*["\']([^"\']+)["\']',
}

graph = []  # list of {from, to_pattern, icc_type, file, line, evidence}
java_files = glob.glob(os.path.join(src_root, '**', '*.java'), recursive=True)
java_files += glob.glob(os.path.join(src_root, '**', '*.kt'), recursive=True)

# Exclude test files
java_files = [f for f in java_files if 'test' not in f.lower() and 'androidtest' not in f.lower()]

for jfile in java_files:
    class_name = os.path.basename(jfile).replace('.java','').replace('.kt','')
    try:
        lines = open(jfile, errors='replace').readlines()
    except:
        continue
    for lineno, line in enumerate(lines, 1):
        for icc_type, pat in ICC_PATTERNS.items():
            m = re.search(pat, line)
            if m:
                target = m.group(1) if m.lastindex else ''
                graph.append({
                    'from_class':  class_name,
                    'from_file':   jfile,
                    'from_line':   lineno,
                    'icc_type':    icc_type,
                    'target':      target,
                    'evidence':    line.strip()[:200],
                    'from_exported': class_name in exported_names,
                    'from_protected': exported_names.get(class_name, {}).get('protected', True)
                })

with open(graph_path, 'w') as f:
    json.dump(graph, f, indent=2)
print(f"Built ICC graph: {len(graph)} edges across {len(java_files)} source files")
PYEOF

    #  Step 3: Analyse graph for dangerous chains 
    python3 - \
        "${WORK_DIR}/icc_exported.json" \
        "${WORK_DIR}/icc_graph.json" \
        "${SHARD_DIR}/shard_iccta.ndjson" << 'PYEOF'
import sys, json

exported_path= sys.argv[1]
graph_path   = sys.argv[2]
shard_path   = sys.argv[3]

with open(exported_path) as f:
    exported = json.load(f)
with open(graph_path) as f:
    graph = json.load(f)

exported_names   = {c['name'].split('.')[-1]: c for c in exported}
exported_classes = set(exported_names.keys())
output = []

def finding(sev, title, desc, evidence, confidence='LIKELY', rem=''):
    cvss = {'CRITICAL':9.5,'HIGH':7.5,'MEDIUM':5.5,'LOW':3.0}.get(sev,5.0)
    return json.dumps({
        'severity': sev, 'category': 'ICC / Cross-Component',
        'title': title, 'description': desc,
        'evidence': evidence, 'confidence': confidence,
        'cvss_score': cvss,
        'remediation': rem or 'Validate all Intent extras at component entry points. Enforce permission checks on all exported components that receive data from untrusted callers.'
    })

#  Check 1: Unprotected exported component launches protected one 
for edge in graph:
    src_class = edge['from_class']
    if not edge['from_exported'] or edge['from_protected']:
        continue  # source must be exported AND unprotected
    target = edge['target']
    if target in exported_names:
        target_comp = exported_names[target]
        if target_comp['protected']:
            ev = (f"Chain: {src_class} (exported, no permission) "
                  f" {edge['icc_type']}()  {target} (protected)\n"
                  f"At: {edge['from_file']}:{edge['from_line']}\n"
                  f"Code: {edge['evidence']}")
            output.append(finding(
                'HIGH',
                f'ICC Confused Deputy: {src_class}  {target}',
                f'Unprotected exported component {src_class} launches protected component {target} '
                f'via {edge["icc_type"]}(). An attacker can invoke {src_class} freely and use it '
                f'as a proxy to reach {target}, bypassing the permission requirement  this is a '
                f'classic confused deputy attack.',
                ev, 'LIKELY',
                f'Add android:permission to {src_class} or remove the {edge["icc_type"]}() call to '
                f'{target} from exported component logic. Validate caller identity with '
                f'Binder.getCallingUid() if cross-app communication is required.'
            ))

#  Check 2: Exported component passes Intent extras to another component 
for edge in graph:
    if not edge['from_exported']:
        continue
    if edge['icc_type'] in ('startActivity','startService','sendBroadcast','startActivityForResult'):
        # Source is exported and sends an Intent  potential data laundering
        src = edge['from_class']
        src_comp = exported_names.get(src, {})
        protected = src_comp.get('protected', True)
        if not protected:
            ev = (f"Exported (unprotected): {src}\n"
                  f" {edge['icc_type']}() at {edge['from_file']}:{edge['from_line']}\n"
                  f"Code: {edge['evidence']}")
            output.append(finding(
                'MEDIUM',
                f'ICC Data Laundering: {src} passes Intent via {edge["icc_type"]}()',
                f'Exported unprotected component {src} sends an Intent to another component. '
                f'If user-controlled data from the inbound Intent is forwarded without validation, '
                f'an attacker can inject arbitrary extras that reach the target component.',
                ev, 'POSSIBLE',
                f'Validate and sanitize all Intent extras received by {src} before forwarding '
                f'them in any outbound startActivity/startService/sendBroadcast call.'
            ))

#  Check 3: ContentResolver access from exported component 
for edge in graph:
    if edge['icc_type'] == 'getContentResolver' and edge['from_exported']:
        src = edge['from_class']
        src_comp = exported_names.get(src, {})
        if not src_comp.get('protected', True):
            ev = (f"Exported (unprotected): {src}\n"
                  f" getContentResolver() at {edge['from_file']}:{edge['from_line']}\n"
                  f"Code: {edge['evidence']}")
            output.append(finding(
                'HIGH',
                f'ICC ContentResolver Access from Unprotected Exported Component: {src}',
                f'Exported component {src} (no permission protection) accesses a ContentProvider '
                f'via getContentResolver(). If the ContentProvider requires a READ permission, '
                f'{src} acts as a confused deputy allowing any app to read protected data by '
                f'invoking {src} and capturing what it reads.',
                ev, 'LIKELY',
                f'Add android:permission to {src}, or ensure it does not expose ContentResolver '
                f'query results back to the caller.'
            ))

#  Check 4: Deep link / scheme  sensitive activity chains 
for comp in exported:
    if comp['type'] == 'activity' and comp['schemes'] and not comp['protected']:
        schemes = ', '.join(comp['schemes'])
        name    = comp['name'].split('.')[-1]
        # Check if this activity also does startActivity/startService (chain)
        chains = [e for e in graph if e['from_class'] == name
                  and e['icc_type'] in ('startActivity','startService','sendBroadcast')]
        if chains:
            chain_ev = '\n'.join(f"   {c['icc_type']}() at line {c['from_line']}: {c['evidence']}" for c in chains[:3])
            output.append(finding(
                'HIGH',
                f'ICC Deep Link Chain: {name} ({schemes})  Component Launch',
                f'Activity {name} is reachable via deep link scheme(s) [{schemes}] with no '
                f'permission protection, AND launches other components internally. An attacker '
                f'crafting a malicious URI can trigger this full chain from outside the app  '
                f'including any components the activity launches.',
                f"Activity: {name}\nSchemes: {schemes}\nChained ICC calls:\n{chain_ev}",
                'LIKELY',
                f'Validate deep link URIs strictly in {name} before acting on them. '
                f'Add android:permission or restrict the activity\'s intent-filter to reduce exposure.'
            ))

#  Check 5: PendingIntent through exported component 
for edge in graph:
    if edge['icc_type'] == 'PendingIntent.get' and edge['from_exported']:
        src = edge['from_class']
        if not exported_names.get(src, {}).get('protected', True):
            output.append(finding(
                'HIGH',
                f'ICC PendingIntent Theft Risk: {src}',
                f'Exported unprotected component {src} creates a PendingIntent. If this PI is '
                f'passed back to the caller or stored in a world-readable location, any app can '
                f'steal it and send the wrapped Intent with the app\'s identity and permissions.',
                f"Component: {src}\n{edge['evidence']} at {edge['from_file']}:{edge['from_line']}",
                'POSSIBLE',
                'Use FLAG_IMMUTABLE on all PendingIntents. Never return PendingIntents to '
                'untrusted callers from exported components. Consider whether the exported '
                'component truly needs to create PendingIntents.'
            ))

with open(shard_path, 'w') as f:
    f.write('\n'.join(output))
print(f"ICC analysis: {len(output)} cross-component findings")
PYEOF

    local icc_count
    icc_count=$(wc -l < "${SHARD_DIR}/shard_iccta.ndjson" 2>/dev/null || echo 0)
    success "ICC analysis complete  $icc_count cross-component chain findings"
}

# 
# MODULE: OBFUSCATED STRING DEOBFUSCATION (Static DEX Emulation)
# 
#
#  Many apps encrypt or encode secrets at compile time and decrypt at runtime:
#    String key = xorDecrypt(new byte[]{0x41,0x13,...}, 0x42);  // "AIzaSy..."
#    String url = new String(Base64.decode("aHR0cHM6Ly8...", BASE64));
#
#  This module detects and statically executes common obfuscation patterns
#  without running the APK, then feeds the recovered strings back into
#  the same secret patterns used by mod_secrets().
# 
mod_stringdeob() {
    section "OBFUSCATED STRING DEOBFUSCATION"
    # Always create shard so merge_shards doesn't count a missing file as success
    touch "${SHARD_DIR}/shard_stringdeob.ndjson" 2>/dev/null || true

    local src="${WORK_DIR}/jadx_out"
    local smali_dir="${WORK_DIR}/apktool_out"

    if [ ! -d "$src" ] && [ ! -d "$smali_dir" ]; then
        warn "No source or smali for string deobfuscation"
        return
    fi

    info "Scanning for obfuscated/encoded string patterns..."

    python3 - "$src" "$smali_dir" "${SHARD_DIR}/shard_stringdeob.ndjson" << 'PYEOF'
import sys, os, re, json, base64, glob, binascii

src_root   = sys.argv[1]
smali_root = sys.argv[2]
shard_path = sys.argv[3]

output  = []
secrets = []  # recovered plaintext strings to re-scan

def secret_finding(title, plaintext, context, confidence='CONFIRMED'):
    cvss = 9.0 if any(k in plaintext for k in ['AKIA','AIza','sk_live','ghp_','eyJ']) else 7.0
    sev  = 'CRITICAL' if cvss >= 9.0 else 'HIGH'
    return json.dumps({
        'severity': sev,
        'category': 'String Deobfuscation',
        'title': title,
        'description': (
            f'A string that was obfuscated/encoded at compile time has been statically '
            f'recovered. Recovered value: "{plaintext[:120]}". '
            f'This value was invisible to all regex-based secret scanners.'
        ),
        'evidence': f'Recovered: {plaintext[:300]}\nContext: {context[:300]}',
        'confidence': confidence,
        'cvss_score': cvss,
        'remediation': (
            'Do not rely on compile-time encoding as a security control  strings like XOR, '
            'base64, and Caesar cipher are trivially reversible. Store secrets server-side and '
            'fetch at runtime via authenticated endpoints, or use Android Keystore for keys that '
            'must be on-device.'
        )
    })

#  Pattern 1: Base64 encoded strings 
B64_PAT = re.compile(
    r'Base64\.decode\s*\(\s*["\']([A-Za-z0-9+/]{16,}={0,2})["\']',
    re.DOTALL
)
B64_INLINE = re.compile(r'["\']([A-Za-z0-9+/]{24,}={0,2})["\']')

def try_base64(s):
    try:
        dec = base64.b64decode(s + '==').decode('utf-8', errors='strict')
        if dec.isprintable() and len(dec) > 6:
            return dec
    except:
        pass
    return None

#  Pattern 2: XOR byte-array decryption 
XOR_PAT = re.compile(
    r'new\s+byte\s*\[\s*\]\s*\{([0-9,\s\-xXa-fA-F]+)\}.*?[\^&]\s*(\d+|0[xX][0-9a-fA-F]+)',
    re.DOTALL
)
XOR_SIMPLE = re.compile(
    r'//.*?XOR|xorDec|decrypt.*?key\s*=\s*(\d+)',
    re.IGNORECASE
)

def try_xor(bytes_str, key_str):
    try:
        key = int(key_str, 0)
        parts = [p.strip() for p in bytes_str.split(',') if p.strip()]
        raw = []
        for p in parts[:256]:
            raw.append(int(p, 0) & 0xff)
        result = bytes([b ^ key for b in raw]).decode('utf-8', errors='replace')
        if result.isprintable() and len(result) > 4:
            return result
    except:
        pass
    return None

#  Pattern 3: Hex-encoded strings 
HEX_PAT = re.compile(r'["\']([0-9a-fA-F]{32,})["\']')

def try_hex(s):
    try:
        dec = bytes.fromhex(s).decode('utf-8', errors='strict')
        if dec.isprintable() and len(dec) > 6 and not dec.isdigit():
            return dec
    except:
        pass
    return None

#  Pattern 4: Reversed strings 
REV_PAT = re.compile(
    r'new\s+StringBuilder\s*\(\s*["\']([^"\']{8,})["\'\s]*\)\s*\.reverse\(\)',
)

#  Pattern 5: String split & join reassembly 
SPLIT_PAT = re.compile(
    r'(?:String\.join|\.join)\s*\(\s*["\']["\']?\s*,\s*((?:["\'][^"\']+["\'],?\s*){3,})\)',
)

#  Pattern 6: Char array construction (int[]  String) 
CHAR_ARR = re.compile(
    r'new\s+char\s*\[\s*\]\s*\{([\d,\s]+)\}'
)

def try_char_array(s):
    try:
        ints = [int(x.strip()) for x in s.split(',') if x.strip().isdigit()]
        result = ''.join(chr(i) for i in ints if 32 <= i <= 126)
        if len(result) > 5:
            return result
    except:
        pass
    return None

#  Pattern 7: Caesar cipher (ROT-N) 
CAESAR_PAT = re.compile(
    r'charAt\s*\(\w+\)\s*[+-]\s*(\d+)\s*\)',
)

#  Scan Java/Kotlin source 
java_files = []
if os.path.isdir(src_root):
    java_files  = glob.glob(os.path.join(src_root, '**', '*.java'), recursive=True)
    java_files += glob.glob(os.path.join(src_root, '**', '*.kt'),   recursive=True)
    java_files  = [f for f in java_files if 'test' not in f.lower()]

seen = set()
SECRET_RE = re.compile(
    r'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24}|'
    r'ghp_[0-9a-zA-Z]{36}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}|'
    r'-----BEGIN.{0,10}PRIVATE KEY'
)
SECRET_RE_I = re.compile(
    r'(password|secret|api.?key|token)\s*[:=]\s*.{8,40}',
    re.IGNORECASE
)

def secret_match(s):
    return secret_match(s) or SECRET_RE_I.search(s)

for jfile in java_files[:500]:  # cap for performance
    try:
        content = open(jfile, errors='replace').read()
    except:
        continue

    ctx = f"File: {os.path.basename(jfile)}"

    # Base64 decode
    for m in B64_PAT.finditer(content):
        dec = try_base64(m.group(1))
        if dec and dec not in seen:
            seen.add(dec)
            if secret_match(dec) or len(dec) > 8:
                secrets.append(dec)
                output.append(secret_finding(
                    f'Deobfuscated Base64 String in {os.path.basename(jfile)}',
                    dec, f'{ctx}\nEncoded: {m.group(1)[:60]}'
                ))

    # Inline base64 candidates (longer strings outside explicit decode calls)
    for m in B64_INLINE.finditer(content):
        cand = m.group(1)
        if len(cand) < 32:
            continue
        dec = try_base64(cand)
        if dec and dec not in seen and secret_match(dec):
            seen.add(dec)
            secrets.append(dec)
            output.append(secret_finding(
                f'Inline Base64 Secret Recovered in {os.path.basename(jfile)}',
                dec, f'{ctx}\nEncoded: {cand[:60]}', 'LIKELY'
            ))

    # XOR byte arrays
    for m in XOR_PAT.finditer(content):
        result = try_xor(m.group(1), m.group(2))
        if result and result not in seen:
            seen.add(result)
            secrets.append(result)
            output.append(secret_finding(
                f'XOR-Decrypted String in {os.path.basename(jfile)}',
                result, f'{ctx}\nXOR key: {m.group(2)}\nBytes: {m.group(1)[:80]}'
            ))

    # Hex strings
    for m in HEX_PAT.finditer(content):
        cand = m.group(1)
        if len(cand) < 32 or len(cand) % 2 != 0:
            continue
        dec = try_hex(cand)
        if dec and dec not in seen and (secret_match(dec) or len(dec) > 12):
            seen.add(dec)
            secrets.append(dec)
            output.append(secret_finding(
                f'Hex-Encoded String Decoded in {os.path.basename(jfile)}',
                dec, f'{ctx}\nHex: {cand[:60]}'
            ))

    # Reversed strings
    for m in REV_PAT.finditer(content):
        rev = m.group(1)[::-1]
        if rev not in seen and len(rev) > 8:
            seen.add(rev)
            secrets.append(rev)
            if secret_match(rev):
                output.append(secret_finding(
                    f'Reversed String Recovered in {os.path.basename(jfile)}',
                    rev, f'{ctx}\nOriginal (reversed): {m.group(1)}'
                ))

    # Char array  string
    for m in CHAR_ARR.finditer(content):
        result = try_char_array(m.group(1))
        if result and result not in seen and len(result) > 8:
            seen.add(result)
            secrets.append(result)
            if secret_match(result):
                output.append(secret_finding(
                    f'Char-Array String Reconstructed in {os.path.basename(jfile)}',
                    result, f'{ctx}\nChars: {m.group(1)[:80]}'
                ))

    # Split/join reassembly
    for m in SPLIT_PAT.finditer(content):
        parts_raw = re.findall(r'["\']([^"\']+)["\']', m.group(1))
        joined = ''.join(parts_raw)
        if joined not in seen and len(joined) > 8 and secret_match(joined):
            seen.add(joined)
            secrets.append(joined)
            output.append(secret_finding(
                f'Split-Joined String Reassembled in {os.path.basename(jfile)}',
                joined, f'{ctx}\nParts: {parts_raw[:5]}'
            ))

#  Scan smali for XOR and byte-push patterns 
if os.path.isdir(smali_root):
    SMALI_CONST = re.compile(r'const/\d+\s+\w+,\s+(0x[0-9a-fA-F]+|-?\d+)')
    smali_files = glob.glob(os.path.join(smali_root, '**', '*.smali'), recursive=True)

    for sfile in smali_files[:300]:
        try:
            lines = open(sfile, errors='replace').readlines()
        except:
            continue
        # Look for sequences of const pushes followed by xor-int
        consts = []
        for i, line in enumerate(lines):
            cm = SMALI_CONST.search(line)
            if cm:
                try:
                    consts.append(int(cm.group(1), 0))
                except:
                    pass
            elif 'xor-int' in line and len(consts) >= 8:
                # Attempt XOR with last const as key, previous as data
                if len(consts) >= 2:
                    key  = consts[-1] & 0xff
                    data = [c & 0xff for c in consts[:-1]]
                    result = bytes([b ^ key for b in data])
                    try:
                        s = result.decode('utf-8', errors='strict')
                        if s.isprintable() and len(s) > 6 and s not in seen:
                            seen.add(s)
                            if secret_match(s):
                                secrets.append(s)
                                output.append(secret_finding(
                                    f'Smali XOR-Decrypted String in {os.path.basename(sfile)}',
                                    s,
                                    f'File: {os.path.basename(sfile)} line {i+1}\nXOR key: 0x{key:02x}',
                                    'LIKELY'
                                ))
                    except:
                        pass
                consts = []
            elif 'invoke-' in line or 'return' in line:
                consts = []

#  Summary finding 
if secrets:
    all_secrets = '\n'.join(f'   {s[:80]}' for s in secrets[:20])
    output.append(json.dumps({
        'severity': 'INFO',
        'category': 'String Deobfuscation',
        'title': f'String Deobfuscation Summary: {len(secrets)} Strings Recovered',
        'description': (
            f'{len(secrets)} strings were recovered from compile-time obfuscation. '
            f'These strings were completely invisible to all regex-based scanners. '
            f'Full values are in individual findings above.'
        ),
        'evidence': f'Recovered strings:\n{all_secrets}',
        'confidence': 'CONFIRMED',
        'cvss_score': 5.0,
        'remediation': 'Store secrets server-side. Compile-time encoding is not a security control.'
    }))
elif not output:
    print("No obfuscated strings recovered  either none present or patterns not matched")

with open(shard_path, 'w') as f:
    f.write('\n'.join(output))
print(f"String deobfuscation: {len(secrets)} strings recovered, {len(output)} findings")
PYEOF

    local deob_count
    deob_count=$(wc -l < "${SHARD_DIR}/shard_stringdeob.ndjson" 2>/dev/null || echo 0)
    success "String deobfuscation complete  $deob_count findings"
}

# 
# MODULE: THIRD-PARTY LIBRARY CVE MATCHING (OSV.dev + NVD)
# 
#
#  Extracts all third-party library names + versions from:
#    - build.gradle / build.gradle.kts (implementation "group:artifact:version")
#    - pom.xml (Maven coordinates)
#    - META-INF/MANIFEST.MF (Bundle-Version, Implementation-Version)
#    - .jar filenames inside the APK (e.g. okhttp-3.12.0.jar)
#    - MANIFEST files in AAR/JAR entries
#    - strings output from DEX (version strings)
#
#  Queries OSV.dev API (https://api.osv.dev/v1/query) for each dependency.
#  Fallback: NVD NIST API for any not found in OSV.
# 
mod_libcve() {
    section "THIRD-PARTY LIBRARY CVE MATCHING"

    if ! tool_ok curl; then
        warn "curl required for CVE matching  skipping"
        return
    fi
    if ! tool_ok python3; then
        warn "python3 required for CVE matching  skipping"
        return
    fi

    info "Extracting library dependencies..."

    python3 - \
        "${WORK_DIR}/raw" \
        "${WORK_DIR}/apktool_out" \
        "${WORK_DIR}/jadx_out" \
        "${WORK_DIR}/target.apk" \
        "${WORK_DIR}/deps.json" << 'PYEOF'
import sys, os, re, json, zipfile, glob

raw_dir    = sys.argv[1]
apktool    = sys.argv[2]
jadx       = sys.argv[3]
apk_path   = sys.argv[4]
out_path   = sys.argv[5]

deps = {}  # {group:artifact: version}

def add_dep(group, artifact, version, source):
    if not version or version in ('${', 'RELEASE', 'SNAPSHOT', 'latest'):
        return
    key = f"{group}:{artifact}"
    if key not in deps:
        deps[key] = {'group': group, 'artifact': artifact,
                     'version': version, 'source': source}

#  1. Gradle files inside APK assets or extracted 
GRADLE_DEP = re.compile(
    r'''(?:implementation|api|compile|runtimeOnly|androidTestImplementation)\s+
        ['"]([\w.\-]+):([\w.\-]+):([\d.\-\w]+)['"]''',
    re.VERBOSE
)
for root, dirs, files in os.walk(raw_dir):
    for fname in files:
        if fname.endswith(('.gradle', '.gradle.kts', 'build.gradle')):
            try:
                content = open(os.path.join(root, fname), errors='replace').read()
                for m in GRADLE_DEP.finditer(content):
                    add_dep(m.group(1), m.group(2), m.group(3), fname)
            except: pass

# Search jadx output for gradle-style strings
if os.path.isdir(jadx):
    for jfile in glob.glob(os.path.join(jadx, '**', '*.java'), recursive=True)[:200]:
        try:
            content = open(jfile, errors='replace').read()
            for m in GRADLE_DEP.finditer(content):
                add_dep(m.group(1), m.group(2), m.group(3), os.path.basename(jfile))
        except: pass

#  2. META-INF MANIFEST.MF entries inside APK 
try:
    with zipfile.ZipFile(apk_path) as zf:
        for name in zf.namelist():
            if 'MANIFEST.MF' in name or name.endswith('.version'):
                try:
                    content = zf.read(name).decode('utf-8', errors='replace')
                    # Bundle-SymbolicName: com.squareup.okhttp3
                    bsn = re.search(r'Bundle-SymbolicName:\s*([\w.]+)', content)
                    bver= re.search(r'Bundle-Version:\s*([\d.]+)', content)
                    impl= re.search(r'Implementation-Title:\s*(.+)', content)
                    iver= re.search(r'Implementation-Version:\s*([\d.]+)', content)
                    if bsn and bver:
                        parts = bsn.group(1).rsplit('.', 1)
                        grp = parts[0] if len(parts)>1 else bsn.group(1)
                        art = parts[1] if len(parts)>1 else bsn.group(1)
                        add_dep(grp, art, bver.group(1), name)
                    if impl and iver:
                        title = impl.group(1).strip()
                        add_dep('android-lib', title.replace(' ','-').lower(),
                                iver.group(1), name)
                except: pass
            # .jar names like libs/okhttp-3.12.0.jar
            if name.endswith('.jar') and '/' in name:
                fname = name.split('/')[-1].replace('.jar','')
                # artifact-x.y.z pattern
                m = re.match(r'^([\w.\-]+?)-(\d+\.\d+[\d.\w\-]*)$', fname)
                if m:
                    art = m.group(1)
                    ver = m.group(2)
                    grp = art.split('-')[0]
                    add_dep(grp, art, ver, name)
except Exception as e:
    print(f"APK zip scan error: {e}")

#  3. Known version strings from strings tool (common libs) 
KNOWN_LIBS = {
    'OkHttp':    ('com.squareup.okhttp3', 'okhttp'),
    'Retrofit':  ('com.squareup.retrofit2', 'retrofit'),
    'Gson':      ('com.google.code.gson', 'gson'),
    'Glide':     ('com.github.bumptech.glide', 'glide'),
    'Picasso':   ('com.squareup.picasso', 'picasso'),
    'RxJava':    ('io.reactivex.rxjava2', 'rxjava'),
    'Volley':    ('com.android.volley', 'volley'),
    'Jackson':   ('com.fasterxml.jackson.core', 'jackson-databind'),
    'log4j':     ('log4j', 'log4j'),
    'Guava':     ('com.google.guava', 'guava'),
    'Conscrypt': ('org.conscrypt', 'conscrypt-android'),
    'BouncyCastle': ('org.bouncycastle', 'bcprov-jdk15on'),
    'Firebase':  ('com.google.firebase', 'firebase-bom'),
}
# Search DEX strings for version identifiers
dex_strings_file = f"{raw_dir}/../dex_strings.txt"
if os.path.isfile(dex_strings_file):
    content = open(dex_strings_file, errors='replace').read()
    for lib, (grp, art) in KNOWN_LIBS.items():
        m = re.search(rf'{lib}[/\s\-](\d+\.\d+[\d.\-\w]*)', content, re.IGNORECASE)
        if m:
            add_dep(grp, art, m.group(1), 'dex-strings')

#  4. Extract from strings in classes.dex 
# Regex for Maven-style version refs in bytecode strings
if os.path.isdir(raw_dir):
    for dex in glob.glob(os.path.join(raw_dir, '*.dex'))[:3]:
        try:
            import subprocess
            out = subprocess.run(['strings', '--text', dex],
                                 capture_output=True, text=True, timeout=30).stdout
            for m in re.finditer(r'([\w.\-]+)/([\w.\-]+)/(\d+\.\d+[\d.\-\w]*)', out):
                add_dep(m.group(1), m.group(2), m.group(3), 'dex-binary')
        except: pass

with open(out_path, 'w') as f:
    json.dump(list(deps.values()), f, indent=2)
print(f"Extracted {len(deps)} unique library dependencies")
PYEOF

    if [ ! -s "${WORK_DIR}/deps.json" ]; then
        warn "No dependencies extracted  gradle files may not be in APK assets"
        add_finding "INFO" "Library CVEs" "No Library Versions Extracted" \
            "Could not extract dependency versions. This is common when gradle files are not bundled in the APK. Try providing the project's build.gradle separately." \
            "No gradle/pom/jar version info found in APK" "CONFIRMED" "general"
        return
    fi

    local dep_count
    dep_count=$(python3 -c "import json; print(len(json.load(open('${WORK_DIR}/deps.json'))))" 2>/dev/null || echo 0)
    info "Querying OSV.dev for $dep_count dependencies..."

    # Query OSV.dev API for each dependency (batched, rate-limited)
    python3 - "${WORK_DIR}/deps.json" "${SHARD_DIR}/shard_libcve.ndjson" << 'PYEOF'
import sys, json, urllib.request, urllib.error, time, re

deps_path  = sys.argv[1]
shard_path = sys.argv[2]

with open(deps_path) as f:
    deps = json.load(f)

OSV_URL = 'https://api.osv.dev/v1/query'
NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
output  = []

SEV_MAP = {
    'CRITICAL': ('CRITICAL', 9.5),
    'HIGH':     ('HIGH',     7.5),
    'MEDIUM':   ('MEDIUM',   5.5),
    'LOW':      ('LOW',      3.0),
}

def osv_query(group, artifact, version):
    payload = json.dumps({
        "version": version,
        "package": {"name": artifact, "ecosystem": "Maven"}
    }).encode()
    try:
        req = urllib.request.Request(
            OSV_URL,
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read())
    except Exception as e:
        return None

def parse_osv_vulns(data, group, artifact, version):
    if not data:
        return []
    results = []
    for vuln in data.get('vulns', []):
        vid    = vuln.get('id', '')
        summ   = vuln.get('summary', '')[:200]
        detail = vuln.get('details', '')[:300]

        # Severity from CVSS
        sev_raw = 'MEDIUM'
        cvss_score = 5.0
        for s in vuln.get('severity', []):
            score_str = s.get('score', '')
            # CVSS v3 scoring
            m = re.search(r'CVSS:[\d.]+/AV:.*/(\d+\.\d+)', score_str)
            if not m:
                # try base score directly
                m = re.search(r'(\d+\.\d+)$', score_str)
            if m:
                try:
                    base = float(m.group(1))
                    cvss_score = base
                    if base >= 9.0:   sev_raw = 'CRITICAL'
                    elif base >= 7.0: sev_raw = 'HIGH'
                    elif base >= 4.0: sev_raw = 'MEDIUM'
                    else:             sev_raw = 'LOW'
                except: pass

        # Find fixed version
        fixed_in = []
        for aff in vuln.get('affected', []):
            for rng in aff.get('ranges', []):
                for evt in rng.get('events', []):
                    if 'fixed' in evt:
                        fixed_in.append(evt['fixed'])

        fixed_str = ', '.join(fixed_in[:3]) if fixed_in else 'No fix recorded'
        aliases   = ', '.join(vuln.get('aliases', [])[:3])

        results.append({
            'id': vid, 'aliases': aliases, 'summary': summ,
            'detail': detail, 'severity': sev_raw,
            'cvss_score': cvss_score, 'fixed_in': fixed_str
        })
    return results

queried  = 0
total_vulns = 0

for dep in deps:
    group    = dep.get('group', '')
    artifact = dep.get('artifact', '')
    version  = dep.get('version', '')
    source   = dep.get('source', '')

    if not artifact or not version:
        continue

    # Rate limit: max 60 queries to avoid hammering OSV
    if queried >= 60:
        break
    queried += 1

    data   = osv_query(group, artifact, version)
    vulns  = parse_osv_vulns(data, group, artifact, version)

    if not vulns:
        # Try with just artifact name (some ecosystems differ)
        data2  = osv_query('', artifact, version)
        vulns  = parse_osv_vulns(data2, group, artifact, version)

    for v in vulns:
        sev   = v['severity']
        cvss  = v['cvss_score']
        total_vulns += 1

        cves = v['aliases'] or v['id']
        title = (
            f'CVE in {artifact} v{version}: '
            f'{v["id"]} ({cves})  {sev}'
        )
        desc = (
            f'Library {group}:{artifact} version {version} (found via {source}) '
            f'is affected by {v["id"]} ({cves}). '
            f'Summary: {v["summary"]}. '
            f'Detail: {v["detail"]}. '
            f'Fixed in: {v["fixed_in"]}.'
        )
        evidence = (
            f'Library: {group}:{artifact}:{version}\n'
            f'CVE/ID:  {v["id"]} | Aliases: {cves}\n'
            f'CVSS:    {cvss} ({sev})\n'
            f'Fixed in: {v["fixed_in"]}\n'
            f'Source:  {source}'
        )
        remediation = (
            f'Upgrade {group}:{artifact} from {version} to {v["fixed_in"]}. '
            f'Update your build.gradle: implementation "{group}:{artifact}:{v["fixed_in"]}". '
            f'Review the full advisory at https://osv.dev/vulnerability/{v["id"]}.'
        )
        output.append(json.dumps({
            'severity':    sev,
            'category':    'Library CVEs',
            'title':       title,
            'description': desc,
            'evidence':    evidence,
            'confidence':  'CONFIRMED',
            'cvss_score':  cvss,
            'remediation': remediation
        }))

    # Polite delay between requests
    time.sleep(0.1)

print(f"Queried {queried} deps, found {total_vulns} CVEs across {len(deps)} libraries")

with open(shard_path, 'w') as f:
    f.write('\n'.join(output))
PYEOF

    local cve_count
    cve_count=$(wc -l < "${SHARD_DIR}/shard_libcve.ndjson" 2>/dev/null || echo 0)
    success "Library CVE matching complete  $cve_count CVE findings"
}

# 
# MODULE: DEEP NATIVE BINARY ANALYSIS (Ghidra Headless + checksec)
# 
#
#  Goes beyond basic strings/readelf to perform real function-level analysis:
#
#  1. checksec  structured ELF mitigation audit (RELRO, NX, PIE, stack canary,
#     FORTIFY_SOURCE, RPATH, runpath) for ALL .so files in one shot
#
#  2. Ghidra headless (optional, auto-detected)  full CFG analysis:
#     - Finds dangerous function call sites (strcpy, system, sprintf, exec)
#     - Checks if function parameters have external data sources
#     - Reports xrefs to dangerous sinks with surrounding context
#     - Identifies JNI_OnLoad for native bridge attack surface
#
#  Ghidra is NOT auto-downloaded (too large, ~500MB). Install instructions
#  are printed if not found. The module still runs checksec without Ghidra.
# 
mod_nativedeep() {
    section "DEEP NATIVE BINARY ANALYSIS"

    local lib_dir="${WORK_DIR}/raw/lib"
    if [ ! -d "$lib_dir" ]; then
        info "No native libraries in APK  skipping"
        return
    fi

    local so_files
    so_files=$(find "$lib_dir" -name "*.so" 2>/dev/null | head -20)
    if [ -z "$so_files" ]; then
        info "No .so files found"
        return
    fi

    local so_count
    so_count=$(echo "$so_files" | wc -l)
    info "Found $so_count native library files"

    #  Part 1: checksec structured ELF audit 
    section "checksec  ELF Security Mitigations"

    local checksec_out="${WORK_DIR}/checksec_results.json"
    local checksec_cmd=""

    # Find checksec
    if tool_ok checksec; then
        checksec_cmd="checksec"
    elif [ -f "${HOME}/.android_audit/checksec.sh" ]; then
        checksec_cmd="bash ${HOME}/.android_audit/checksec.sh"
    else
        # Download checksec.sh (lightweight, ~50KB)
        info "checksec not found  downloading checksec.sh..."
        mkdir -p "${HOME}/.android_audit"
        if timeout 30 curl -fsSL \
            "https://raw.githubusercontent.com/slimm609/checksec.sh/main/checksec" \
            -o "${HOME}/.android_audit/checksec.sh" 2>/dev/null; then
            chmod +x "${HOME}/.android_audit/checksec.sh"
            checksec_cmd="bash ${HOME}/.android_audit/checksec.sh"
            success "checksec downloaded"
        else
            warn "Could not download checksec  ELF mitigation check will use readelf fallback"
        fi
    fi

    echo '{}' > "$checksec_out"

    if [ -n "$checksec_cmd" ]; then
        # Run checksec on each .so and collect JSON
        python3 - "$checksec_cmd" "$lib_dir" "$checksec_out" "${SHARD_DIR}/shard_nativedeep_checksec.ndjson" << 'PYEOF'
import sys, os, json, subprocess, re, glob

checksec_cmd = sys.argv[1]
lib_dir      = sys.argv[2]
out_path     = sys.argv[3]
shard_path   = sys.argv[4]

so_files = glob.glob(os.path.join(lib_dir, '**', '*.so'), recursive=True)
output   = []
results  = {}

MITIGATIONS = {
    'relro':   ('No RELRO',         'HIGH',   'GOT overwrite attacks are easier without RELRO. Compile with -Wl,-z,relro,-z,now'),
    'canary':  ('No Stack Canary',  'HIGH',   'Stack buffer overflows may not be detected. Compile with -fstack-protector-strong'),
    'nx':      ('No NX (Exec stack)','CRITICAL','Stack is executable  shellcode injection is directly possible. Compile with -Wl,-z,noexecstack'),
    'pie':     ('No PIE',           'HIGH',   'Binary loads at fixed address  ROP chains are easier to construct. Compile with -fPIE -pie'),
    'fortify': ('No FORTIFY_SOURCE','MEDIUM', 'Buffer overflow detection in libc functions is disabled. Compile with -D_FORTIFY_SOURCE=2'),
    'rpath':   ('Insecure RPATH',   'HIGH',   'RPATH/RUNPATH set  library hijacking may be possible. Remove with chrpath -d'),
}

for so in so_files[:15]:
    libname = os.path.basename(so)
    results[libname] = {}

    try:
        # checksec JSON output
        result = subprocess.run(
            checksec_cmd.split() + ['--file=' + so, '--output=json'],
            capture_output=True, text=True, timeout=15
        )
        data = json.loads(result.stdout or '{}')
        file_data = data.get(so, data.get(libname, {}))
        if not file_data and data:
            file_data = list(data.values())[0] if data else {}
        results[libname] = file_data

        for key, (label, sev, rem) in MITIGATIONS.items():
            val = str(file_data.get(key, '')).lower()
            is_bad = (
                val in ('no', 'none', 'false', '0', 'partial') or
                (key == 'rpath' and val not in ('no','none',''))
            )
            if is_bad:
                output.append(json.dumps({
                    'severity': sev,
                    'category': 'Native Deep / ELF Mitigations',
                    'title': f'{label} in {libname}',
                    'description': (
                        f'Native library {libname} is missing the {key.upper()} mitigation. '
                        f'{rem}. In the context of any memory corruption vulnerability in this '
                        f'library, this omission makes exploitation significantly easier.'
                    ),
                    'evidence': f'Library: {so}\nchecksec result for {key}: {val}',
                    'confidence': 'CONFIRMED',
                    'cvss_score': {'CRITICAL':9.0,'HIGH':7.0,'MEDIUM':5.0}.get(sev,5.0),
                    'remediation': rem
                }))
    except Exception as e:
        # Fall back to readelf-based check
        try:
            elf_out = subprocess.run(
                ['readelf', '-d', so], capture_output=True, text=True, timeout=10
            ).stdout
            if 'GNU_RELRO' not in elf_out:
                output.append(json.dumps({
                    'severity': 'HIGH', 'category': 'Native Deep / ELF Mitigations',
                    'title': f'No RELRO in {libname} (readelf fallback)',
                    'description': f'readelf confirmed no GNU_RELRO in {libname}.',
                    'evidence': f'readelf -d {libname}: no GNU_RELRO entry',
                    'confidence': 'CONFIRMED', 'cvss_score': 7.0,
                    'remediation': 'Compile with -Wl,-z,relro,-z,now'
                }))
        except: pass

with open(shard_path, 'w') as f:
    f.write('\n'.join(output))
with open(out_path, 'w') as f:
    json.dump(results, f, indent=2)
print(f"checksec: {len(output)} ELF mitigation findings across {len(so_files)} libraries")
PYEOF
    else
        # Pure readelf fallback (already in mod_native, but more comprehensive here)
        info "Using readelf fallback for ELF mitigation checks"
        while IFS= read -r so; do
            local lib
            lib=$(basename "$so")
            local elf
            elf=$(readelf -d "$so" 2>/dev/null || true)
            local elf_h
            elf_h=$(readelf -h "$so" 2>/dev/null || true)
            ! echo "$elf" | grep -q "GNU_RELRO" && \
                add_finding "HIGH" "Native Deep / ELF" "No RELRO: $lib" \
                    "Missing RELRO  GOT overwrite attacks easier." \
                    "readelf -d $lib: no GNU_RELRO" "CONFIRMED" "general"
            ! echo "$elf_h" | grep -qi "pie\|dyn" && \
                add_finding "HIGH" "Native Deep / ELF" "No PIE: $lib" \
                    "Library loads at fixed address  ROP chains easier." \
                    "$lib ELF type not DYN (not PIE)" "LIKELY" "general"
        done <<< "$so_files"
    fi

    #  Part 2: Dangerous function call-site analysis 
    section "Native Dangerous Function Deep Analysis"

    python3 - "$lib_dir" "${SHARD_DIR}/shard_nativedeep_func.ndjson" << 'PYEOF'
import sys, os, subprocess, re, json, glob

lib_dir    = sys.argv[1]
shard_path = sys.argv[2]

DANGEROUS = {
    'strcpy':   ('CRITICAL', 'No bounds checking  classic buffer overflow. Replace with strlcpy() or strncpy() with explicit length.'),
    'strcat':   ('CRITICAL', 'No bounds checking on destination. Replace with strlcat() or strncat() with explicit length.'),
    'sprintf':  ('HIGH',     'No bounds checking on output buffer. Replace with snprintf() with explicit buffer size.'),
    'vsprintf': ('HIGH',     'No bounds checking. Replace with vsnprintf().'),
    'gets':     ('CRITICAL', 'gets() is inherently unsafe  no bounds checking possible. Replace with fgets() or getline().'),
    'scanf':    ('HIGH',     'Unbounded %s format can overflow. Use width-limited format: scanf("%255s", buf).'),
    'system':   ('CRITICAL', 'OS command execution  if user input reaches this, it is RCE. Replace with execv() with argv array.'),
    'popen':    ('CRITICAL', 'Shell command execution via pipe. Same risk as system(). Use execv() family.'),
    'execl':    ('HIGH',     'Exec family call  verify argument sources are not user-controlled.'),
    'execlp':   ('HIGH',     'PATH-based exec  susceptible to PATH hijacking if not absolute.'),
    'execle':   ('HIGH',     'Exec with env  verify env is not attacker-controlled.'),
    'execv':    ('MEDIUM',   'Exec call  verify argv[0] path and all arguments are not user-controlled.'),
    'execvp':   ('HIGH',     'PATH-based exec  susceptible to PATH hijacking.'),
    'memcpy':   ('MEDIUM',   'If length parameter is user-controlled, heap overflow is possible.'),
    'memmove':  ('MEDIUM',   'If length is user-controlled, overflow is possible.'),
    'malloc':   ('MEDIUM',   'If size is user-controlled, integer overflow  heap overflow possible.'),
    'realloc':  ('MEDIUM',   'If size is user-controlled, integer overflow possible.'),
    'strtok':   ('LOW',      'Not thread-safe and modifies input string. Use strtok_r() in threaded contexts.'),
    'getenv':   ('MEDIUM',   'Environment variable content may be attacker-controlled in some contexts.'),
    'printf':   ('HIGH',     'If format string is user-controlled, format string attack is possible.'),
    'fprintf':  ('HIGH',     'If format string is user-controlled, format string attack is possible.'),
    'snprintf': ('LOW',      'Safer than sprintf but verify buffer size is correct and return value is checked.'),
    'dlopen':   ('HIGH',     'Dynamic library loading  if path is user-controlled, library hijacking is possible.'),
    'dlsym':    ('MEDIUM',   'Dynamic symbol lookup  verify symbol names are not user-controlled.'),
}

output = []
so_files = glob.glob(os.path.join(lib_dir, '**', '*.so'), recursive=True)

for so in so_files[:15]:
    libname = os.path.basename(so)
    try:
        # nm -D for dynamic symbols (what the library imports/exports)
        nm_out = subprocess.run(
            ['nm', '-D', '--defined-only', so],
            capture_output=True, text=True, timeout=15
        ).stdout + subprocess.run(
            ['nm', '-D', '--undefined-only', so],
            capture_output=True, text=True, timeout=15
        ).stdout
    except:
        nm_out = ''

    try:
        # strings for additional context
        str_out = subprocess.run(
            ['strings', '--text', so],
            capture_output=True, text=True, timeout=20
        ).stdout
    except:
        str_out = ''

    # Check which dangerous functions are imported (undefined in nm = imported)
    undef_out = ''
    try:
        undef_out = subprocess.run(
            ['nm', '-D', '--undefined-only', so],
            capture_output=True, text=True, timeout=15
        ).stdout
    except: pass

    for func, (sev, rem) in DANGEROUS.items():
        # Check if imported (much more reliable than strings)
        if re.search(rf'\bU\b.*\b{func}\b|\b{func}@', undef_out):
            # Cross-reference: does the library also import JNI functions?
            # If yes, native bridge is exposed to Java  higher risk
            has_jni = 'JNI_OnLoad' in nm_out or 'Java_' in nm_out
            jni_note = (' This library exposes a JNI bridge  Java code can call '
                       'into this native code, making the attack surface reachable '
                       'from the Java/Kotlin layer.') if has_jni else ''

            # Check for JNI wrapper near dangerous function in strings
            jni_wrappers = re.findall(r'Java_[\w_]+', nm_out)
            wrapper_str  = ', '.join(jni_wrappers[:5]) if jni_wrappers else 'none detected'

            output.append(json.dumps({
                'severity': sev,
                'category': 'Native Deep / Dangerous Functions',
                'title': f'Dangerous Import: {func}() in {libname}',
                'description': (
                    f'Native library {libname} imports the dangerous C function {func}(). '
                    f'{rem}{jni_note} '
                    f'The presence of this import does not guarantee exploitability, '
                    f'but every call site must be audited to verify argument sources.'
                ),
                'evidence': (
                    f'Library: {libname}\n'
                    f'Function: {func}() (imported, confirmed by nm -D)\n'
                    f'JNI bridge: {"YES" if has_jni else "NO"}\n'
                    f'JNI wrappers: {wrapper_str}'
                ),
                'confidence': 'CONFIRMED',
                'cvss_score': {'CRITICAL':8.5,'HIGH':7.0,'MEDIUM':5.0,'LOW':3.0}.get(sev,5.0),
                'remediation': rem
            }))

    # JNI_OnLoad  document attack surface
    if 'JNI_OnLoad' in nm_out:
        jni_wrappers = re.findall(r'Java_[\w_]+', nm_out)
        count = len(jni_wrappers)
        if count > 0:
            output.append(json.dumps({
                'severity': 'INFO',
                'category': 'Native Deep / JNI Surface',
                'title': f'JNI Bridge in {libname}: {count} Native Method(s)',
                'description': (
                    f'{libname} exposes {count} JNI-callable native methods. '
                    f'These methods are reachable from Java/Kotlin via native calls. '
                    f'Any memory corruption vulnerability in these functions is directly '
                    f'exploitable from the Java layer.'
                ),
                'evidence': f'JNI methods:\n' + '\n'.join(f'  {w}' for w in jni_wrappers[:20]),
                'confidence': 'CONFIRMED',
                'cvss_score': 2.0,
                'remediation': (
                    'Audit all JNI methods listed above for buffer overflows, '
                    'format string bugs, and integer overflows. Validate all Java '
                    'arguments before passing to native operations.'
                )
            }))

    # Format string detection  if printf/fprintf imported AND string patterns
    if re.search(r'\bU\b.*\b(printf|fprintf|sprintf)\b', undef_out):
        fmt_patterns = re.findall(r'%[0-9*]*[diouxXeEfgGcs]', str_out)
        # Look for user-controlled format strings (dynamic format  no literal format)
        user_fmt = [s for s in fmt_patterns if s in ('%s', '%d', '%x') and
                    str_out.count(s) > 5]
        if len(user_fmt) > 3:
            output.append(json.dumps({
                'severity': 'HIGH',
                'category': 'Native Deep / Format String',
                'title': f'Potential Format String Vulnerability in {libname}',
                'description': (
                    f'{libname} imports printf-family functions and contains multiple '
                    f'simple format specifiers (%s, %d, %x) that may indicate format '
                    f'strings are being passed dynamically. If a format string argument '
                    f'is user-controlled, arbitrary memory read/write is possible.'
                ),
                'evidence': (
                    f'Library: {libname}\n'
                    f'Imports: printf/fprintf/sprintf\n'
                    f'Format patterns found: {", ".join(set(user_fmt))}\n'
                    f'Pattern count: {len(user_fmt)}'
                ),
                'confidence': 'POSSIBLE',
                'cvss_score': 7.0,
                'remediation': (
                    'Ensure all printf-family calls use literal format strings, not '
                    'variables. For example: printf(user_input) is WRONG; '
                    'printf("%s", user_input) is correct.'
                )
            }))

with open(shard_path, 'w') as f:
    f.write('\n'.join(output))
print(f"Native deep function analysis: {len(output)} findings across {len(so_files)} libraries")
PYEOF

    #  Part 3: Ghidra headless (if available) 
    local ghidra_cmd=""
    for gpath in /opt/ghidra/support/analyzeHeadless \
                 "${HOME}/ghidra/support/analyzeHeadless" \
                 /usr/share/ghidra/support/analyzeHeadless \
                 "$(which analyzeHeadless 2>/dev/null)"; do
        [ -x "$gpath" ] && ghidra_cmd="$gpath" && break
    done

    if [ -z "$ghidra_cmd" ]; then
        warn "Ghidra not found  skipping CFG analysis (checksec + nm analysis still ran)"
        info "Install Ghidra: https://ghidra-sre.org/"
        info "Then: export PATH=\$PATH:/opt/ghidra/support"
        add_finding "INFO" "Native Deep / Ghidra" "Ghidra Not Installed  CFG Analysis Skipped" \
            "Ghidra headless was not found. The checksec and nm-based analysis above ran successfully, but full Control Flow Graph analysis of dangerous function call sites was not performed. Install Ghidra from https://ghidra-sre.org/ and re-run to enable CFG analysis." \
            "analyzeHeadless not in PATH or common locations" "CONFIRMED" "general"
        return
    fi

    info "Ghidra found at: $ghidra_cmd  running CFG analysis on primary .so"

    # Run Ghidra on the largest/most suspicious .so
    local primary_so
    primary_so=$(find "$lib_dir" -name "*.so" -printf "%s %p\n" 2>/dev/null | \
                 sort -rn | grep -v "libflutter\|libc++\|liblog\|libandroid" | \
                 head -1 | awk '{print $2}' || true)

    [ -z "$primary_so" ] && primary_so=$(find "$lib_dir" -name "*.so" | head -1)
    [ -z "$primary_so" ] && return

    local ghidra_proj="${WORK_DIR}/ghidra_proj"
    local ghidra_out="${WORK_DIR}/ghidra_output.txt"
    mkdir -p "$ghidra_proj"

    info "Ghidra CFG analysis on: $(basename "$primary_so") (timeout 10 min)"

    # Write Ghidra script inline
    local ghidra_script="${WORK_DIR}/AuditScript.java"
    cat > "$ghidra_script" << 'GSCRIPT'
// Ghidra Headless Script  Android Bug Bounty Audit
// Finds dangerous function call sites and prints xrefs
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.util.*;

public class AuditScript extends GhidraScript {
    private static final String[] DANGEROUS = {
        "strcpy","strcat","sprintf","vsprintf","gets","scanf",
        "system","popen","execl","execlp","execle","execv","execvp",
        "memcpy","memmove","malloc","realloc","printf","fprintf",
        "dlopen","strtok","getenv"
    };

    @Override
    public void run() throws Exception {
        SymbolTable st = currentProgram.getSymbolTable();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();

        for (String fname : DANGEROUS) {
            SymbolIterator syms = st.getSymbols(fname);
            while (syms.hasNext()) {
                Symbol sym = syms.next();
                if (sym.getSymbolType() == SymbolType.FUNCTION ||
                    sym.getSymbolType() == SymbolType.LABEL) {
                    ReferenceIterator refs = rm.getReferencesTo(sym.getAddress());
                    int xrefCount = 0;
                    while (refs.hasNext() && xrefCount < 10) {
                        Reference ref = refs.next();
                        Address fromAddr = ref.getFromAddress();
                        Function callerFn = fm.getFunctionContaining(fromAddr);
                        String callerName = callerFn != null ? callerFn.getName() : "unknown";
                        println("DANGEROUS_CALL|" + fname + "|" + fromAddr + "|" + callerName);
                        xrefCount++;
                    }
                    if (xrefCount > 0) {
                        println("XREF_COUNT|" + fname + "|" + xrefCount);
                    }
                }
            }
        }
        // JNI bridge
        SymbolIterator allSyms = st.getAllSymbols(true);
        while (allSyms.hasNext()) {
            Symbol sym = allSyms.next();
            String name = sym.getName();
            if (name.startsWith("Java_")) {
                Function fn = fm.getFunctionAt(sym.getAddress());
                int sz = fn != null ? (int)fn.getBody().getNumAddresses() : 0;
                println("JNI_METHOD|" + name + "|" + sym.getAddress() + "|size=" + sz);
            }
        }
        println("GHIDRA_ANALYSIS_COMPLETE");
    }
}
GSCRIPT

    timeout 600 "$ghidra_cmd" \
        "$ghidra_proj" "audit_project" \
        -import "$primary_so" \
        -postScript "$ghidra_script" \
        -scriptPath "$(dirname "$ghidra_script")" \
        -deleteProject \
        > "$ghidra_out" 2>&1 || true

    if grep -q "GHIDRA_ANALYSIS_COMPLETE" "$ghidra_out" 2>/dev/null; then
        success "Ghidra analysis complete"
        python3 - "$ghidra_out" "$(basename "$primary_so")" "${SHARD_DIR}/shard_ghidra.ndjson" << 'PYEOF'
import sys, re, json, collections

ghidra_log = sys.argv[1]
libname    = sys.argv[2]
shard_path = sys.argv[3]

content = open(ghidra_log, errors='replace').read()
output  = []

RISK = {
    'strcpy':('CRITICAL','Replace with strlcpy(dst,src,sizeof(dst))'),
    'strcat':('CRITICAL','Replace with strlcat(dst,src,sizeof(dst))'),
    'sprintf':('HIGH','Replace with snprintf(buf,sizeof(buf),fmt,...)'),
    'gets':('CRITICAL','Replace with fgets(buf,sizeof(buf),stdin)'),
    'system':('CRITICAL','Replace with execv() with explicit argv array'),
    'popen':('CRITICAL','Replace with execv() family functions'),
    'printf':('HIGH','Never pass user data as format string'),
    'fprintf':('HIGH','Never pass user data as format string'),
    'scanf':('HIGH','Use width-limited format: scanf("%255s",buf)'),
    'memcpy':('MEDIUM','Verify length parameter is not user-controlled'),
    'malloc':('MEDIUM','Verify size parameter cannot overflow'),
    'dlopen':('HIGH','Verify path cannot be attacker-controlled'),
    'vsprintf':('HIGH','Replace with vsnprintf()'),
    'memmove':('MEDIUM','Verify length is not user-controlled'),
    'realloc':('MEDIUM','Verify size cannot overflow'),
    'execl':('HIGH','Verify all arguments are not user-controlled'),
    'execlp':('HIGH','Use absolute path and sanitize arguments'),
    'execle':('HIGH','Verify env is not attacker-controlled'),
    'execv':('MEDIUM','Verify argv contents are not user-controlled'),
    'execvp':('HIGH','Use absolute path, not PATH-relative'),
    'strtok':('LOW','Use strtok_r() in threaded code'),
    'getenv':('MEDIUM','Validate environment variable values'),
}

# Parse dangerous calls
calls = re.findall(r'DANGEROUS_CALL\|(\w+)\|(0x[0-9a-fA-F]+)\|(\w+)', content)
call_map = collections.defaultdict(list)
for func, addr, caller in calls:
    call_map[func].append((addr, caller))

for func, sites in call_map.items():
    sev, rem = RISK.get(func, ('MEDIUM', 'Audit all call sites carefully'))
    callers = list({c for _, c in sites})[:5]
    addrs   = [a for a, _ in sites][:5]
    output.append(json.dumps({
        'severity': sev,
        'category': 'Native Deep / Ghidra CFG',
        'title': f'Ghidra CFG: {func}() called {len(sites)}x in {libname}',
        'description': (
            f'Ghidra CFG analysis confirmed {len(sites)} call site(s) to {func}() in {libname}. '
            f'Call sites are in functions: {", ".join(callers)}. '
            f'Each site must be audited to verify that buffer/string lengths are bounded '
            f'and that arguments are not user-controlled.'
        ),
        'evidence': (
            f'Library: {libname}\n'
            f'Function: {func}()  {len(sites)} xrefs\n'
            f'Caller functions: {", ".join(callers)}\n'
            f'Call addresses: {", ".join(addrs)}'
        ),
        'confidence': 'CONFIRMED',
        'cvss_score': {'CRITICAL':9.0,'HIGH':7.5,'MEDIUM':5.5,'LOW':3.0}.get(sev,5.0),
        'remediation': rem
    }))

# JNI methods
jni = re.findall(r'JNI_METHOD\|(Java_[\w_]+)\|(0x[0-9a-fA-F]+)\|size=(\d+)', content)
if jni:
    large_jni = [(n,a,int(s)) for n,a,s in jni if int(s) > 100]
    if large_jni:
        output.append(json.dumps({
            'severity': 'INFO',
            'category': 'Native Deep / Ghidra CFG',
            'title': f'Ghidra: {len(jni)} JNI Methods in {libname} ({len(large_jni)} large)',
            'description': (
                f'Ghidra found {len(jni)} JNI-exported methods. '
                f'{len(large_jni)} are large (>100 instructions) and warrant deeper review. '
                f'Large JNI functions with complex logic are higher risk for memory corruption.'
            ),
            'evidence': 'Large JNI methods:\n' + '\n'.join(
                f'  {n} @ {a} ({s} instrs)' for n,a,s in sorted(large_jni,key=lambda x:-x[2])[:10]
            ),
            'confidence': 'CONFIRMED',
            'cvss_score': 2.0,
            'remediation': 'Audit the largest JNI methods for buffer overflows, integer overflows, and format string bugs.'
        }))

with open(shard_path, 'w') as f:
    f.write('\n'.join(output))
print(f"Ghidra: {len(output)} CFG findings from {len(calls)} call sites")
PYEOF
    else
        warn "Ghidra did not complete analysis (check ${ghidra_out} for errors)"
    fi

    local native_count
    native_count=0
    for s in "${SHARD_DIR}/shard_nativedeep_checksec.ndjson" \
              "${SHARD_DIR}/shard_nativedeep_func.ndjson" \
              "${SHARD_DIR}/shard_ghidra.ndjson"; do
        [ -f "$s" ] && native_count=$((native_count + $(wc -l < "$s" 2>/dev/null || echo 0)))
    done
    success "Deep native analysis complete  $native_count total findings"
}

# 
# DIFF MODE  compare two APK scan results
# 
run_diff_mode() {
    local apk1="$1" apk2="$2"
    section "DIFF MODE: $apk1 vs $apk2"

    # Scan both APKs
    local work1="/tmp/android_audit_diff_new_${TIMESTAMP}"
    local work2="/tmp/android_audit_diff_old_${TIMESTAMP}"
    local findings1="${work1}/findings.json"
    local findings2="${work2}/findings.json"
    local diff_path="${work1}/diff_results.json"

    info "Scanning NEW APK: $apk1"
    WORK_DIR="$work1"
    FINDING_COUNTER=0
    init_findings
    extract_apk "$apk1"
    run_all_modules

    info "Scanning OLD APK: $apk2"
    WORK_DIR="$work2"
    FINDING_COUNTER=0
    init_findings
    extract_apk "$apk2"
    run_all_modules

    # Python diff analysis
    python3 - "$findings1" "$findings2" "$diff_path" << 'PYEOF'
import sys, json

def load(p):
    try:
        with open(p) as f: return json.load(f)
    except: return []

new_findings = load(sys.argv[1])
old_findings = load(sys.argv[2])
out_path = sys.argv[3]

def key(f): return f.get('title','') + '|' + f.get('category','')

new_keys = {key(f): f for f in new_findings}
old_keys = {key(f): f for f in old_findings}

added   = [f for k, f in new_keys.items() if k not in old_keys]
fixed   = [f for k, f in old_keys.items() if k not in new_keys]
persist = [f for k, f in new_keys.items() if k in old_keys]

result = {
    "added": added,
    "fixed": fixed,
    "persisting": persist,
    "summary": {
        "new_total": len(new_findings),
        "old_total": len(old_findings),
        "added_count": len(added),
        "fixed_count": len(fixed),
        "persisting_count": len(persist)
    }
}
with open(out_path, 'w') as f:
    json.dump(result, f, indent=2)
print(json.dumps(result['summary'], indent=2))
PYEOF

    # Use diff results for the report
    WORK_DIR="$work1"
    refresh_runtime_paths
    generate_report "$apk1" "$apk2"
}

should_skip() {
    local mod="$1"
    for s in "${SKIP_MODULES[@]}"; do
        [ "$s" = "$mod" ] && return 0
    done
    return 1
}

run_all_modules() {
    refresh_runtime_paths
    mkdir -p "${SHARD_DIR}"

    #  Sequential (must run first  others depend on their output)
    should_skip "apkid"    || mod_apkid      # detect packers FIRST  warns if results unreliable
    should_skip "metadata" || mod_metadata   # populates MIN_SDK, pkg name
    should_skip "manifest" || mod_manifest   # populates exported_components.txt

    #  Parallel batch 1  independent source analysis
    section "RUNNING PARALLEL ANALYSIS MODULES"
    info "Launching parallel source analysis modules..."

    should_skip "secrets"  || ( mod_secrets  > "${WORK_DIR}/parallel/secrets.log"  2>&1 ) &
    BG_PIDS+=($!) ; BG_NAMES+=("secrets")

    should_skip "crypto"   || ( mod_crypto   > "${WORK_DIR}/parallel/crypto.log"   2>&1 ) &
    BG_PIDS+=($!) ; BG_NAMES+=("crypto")

    should_skip "webview"  || ( mod_webview  > "${WORK_DIR}/parallel/webview.log"  2>&1 ) &
    BG_PIDS+=($!) ; BG_NAMES+=("webview")

    should_skip "storage"  || ( mod_storage  > "${WORK_DIR}/parallel/storage.log"  2>&1 ) &
    BG_PIDS+=($!) ; BG_NAMES+=("storage")

    should_skip "intents"  || ( mod_intents  > "${WORK_DIR}/parallel/intents.log"  2>&1 ) &
    BG_PIDS+=($!) ; BG_NAMES+=("intents")

    should_skip "smali"    || ( mod_smali    > "${WORK_DIR}/parallel/smali.log"    2>&1 ) &
    BG_PIDS+=($!) ; BG_NAMES+=("smali")

    should_skip "misc"     || ( mod_misc     > "${WORK_DIR}/parallel/misc.log"     2>&1 ) &
    BG_PIDS+=($!) ; BG_NAMES+=("misc")

    # Framework-specific (run in parallel with source analysis)
    should_skip "rn"       || ( mod_react_native > "${WORK_DIR}/parallel/rn.log"   2>&1 ) &
    BG_PIDS+=($!) ; BG_NAMES+=("react-native")

    should_skip "flutter"  || ( mod_flutter  > "${WORK_DIR}/parallel/flutter.log"  2>&1 ) &
    BG_PIDS+=($!) ; BG_NAMES+=("flutter")

    should_skip "cordova"  || ( mod_cordova  > "${WORK_DIR}/parallel/cordova.log"  2>&1 ) &
    BG_PIDS+=($!) ; BG_NAMES+=("cordova")

    wait_parallel "source + framework analysis modules"

    #  Parallel batch 2  structure-dependent + heavy tools
    should_skip "aidl"            || ( mod_aidl           > "${WORK_DIR}/parallel/aidl.log"    2>&1 ) &
    BG_PIDS+=($!) ; BG_NAMES+=("aidl")

    should_skip "contentprovider" || ( mod_contentprovider > "${WORK_DIR}/parallel/cp.log"     2>&1 ) &
    BG_PIDS+=($!) ; BG_NAMES+=("contentprovider")

    should_skip "backup"          || ( mod_backup          > "${WORK_DIR}/parallel/backup.log" 2>&1 ) &
    BG_PIDS+=($!) ; BG_NAMES+=("backup")

    should_skip "netconfig"       || ( mod_netconfig       > "${WORK_DIR}/parallel/netcfg.log" 2>&1 ) &
    BG_PIDS+=($!) ; BG_NAMES+=("netconfig")

    should_skip "native"          || ( mod_native          > "${WORK_DIR}/parallel/native.log" 2>&1 ) &
    BG_PIDS+=($!) ; BG_NAMES+=("native")

    should_skip "firebase"        || ( mod_firebase        > "${WORK_DIR}/parallel/fb.log"     2>&1 ) &
    BG_PIDS+=($!) ; BG_NAMES+=("firebase")

    # Semgrep and MobSF can run in parallel with batch 2
    should_skip "semgrep"         || ( mod_semgrep         > "${WORK_DIR}/parallel/semgrep.log"2>&1 ) &
    BG_PIDS+=($!) ; BG_NAMES+=("semgrep")

    should_skip "mobsf"           || ( mod_mobsf           > "${WORK_DIR}/parallel/mobsf.log"  2>&1 ) &
    BG_PIDS+=($!) ; BG_NAMES+=("mobsf")

    wait_parallel "deep analysis + semgrep + mobsf"

    #  Replay all parallel module logs to console
    for log in "${WORK_DIR}/parallel/"*.log; do
        [ -f "$log" ] && cat "$log"
    done

    #  Live checks  sequential (network I/O)
    should_skip "live" || mod_live_checks

    #  FlowDroid  sequential, heavy, runs AFTER all other modules
    should_skip "flowdroid"   || mod_flowdroid

    #  v2.3 additions  sequential heavy passes 
    # ICC runs after FlowDroid (uses same jadx/manifest output)
    should_skip "iccta"       || mod_iccta

    # String deobfuscation  parallel-safe, but runs after source mods done
    should_skip "stringdeob"  || ( mod_stringdeob > "${WORK_DIR}/parallel/stringdeob.log" 2>&1 ) &
    BG_PIDS+=($!) ; BG_NAMES+=("stringdeob")

    # Library CVE  network-dependent, run in parallel with stringdeob
    should_skip "libcve"      || ( mod_libcve > "${WORK_DIR}/parallel/libcve.log" 2>&1 ) &
    BG_PIDS+=($!) ; BG_NAMES+=("libcve")

    # Native deep  heavy (checksec + Ghidra), run in parallel
    should_skip "nativedeep"  || ( mod_nativedeep > "${WORK_DIR}/parallel/nativedeep.log" 2>&1 ) &
    BG_PIDS+=($!) ; BG_NAMES+=("nativedeep")

    wait_parallel "v2.3 analysis modules"

    # Replay v2.3 logs
    for log in "${WORK_DIR}/parallel/stringdeob.log" \
               "${WORK_DIR}/parallel/libcve.log" \
               "${WORK_DIR}/parallel/nativedeep.log"; do
        [ -f "$log" ] && cat "$log"
    done

    #  CRITICAL: Merge all per-subshell shards  findings.json 
    section "MERGING FINDINGS"
    merge_shards
    local total
    total=$(python3 -c "import json; print(len(json.load(open('${FINDINGS_JSON}'))))" 2>/dev/null || echo "?")
    success "Total unique findings after dedup: $total"
}

# 
# REPORT GENERATION  HTML + JSON + Markdown
# 
generate_report() {
    section "GENERATING REPORTS (HTML + JSON + Markdown + SARIF)"

    local apk1="${1:-target.apk}" apk2="${2:-}"
    local pkg="unknown"
    [ -f "${WORK_DIR}/pkg_name.txt" ] && pkg=$(cat "${WORK_DIR}/pkg_name.txt")

    # Pass file paths (not JSON blobs) to avoid ARG_MAX issues on large reports.
    local findings_path="${FINDINGS_JSON}"
    local diff_path="${WORK_DIR}/diff_results.json"

    python3 - \
        "$REPORT_HTML" "$REPORT_JSON" "$REPORT_MD" \
        "$pkg" "$(basename "$apk1")" "$apk2" \
        "$findings_path" "$diff_path" \
        "${MISSING_TOOLS[*]:-}" << 'PYEOF'

import sys, json, html as H
from datetime import datetime

html_out      = sys.argv[1]
json_out      = sys.argv[2]
md_out        = sys.argv[3]
pkg           = sys.argv[4]
apk_name      = sys.argv[5]
apk2_name     = sys.argv[6]
findings_path = sys.argv[7]
diff_path     = sys.argv[8]
missing       = sys.argv[9].split() if sys.argv[9].strip() else []

try:
    with open(findings_path, encoding='utf-8') as f:
        findings = json.load(f)
except Exception:
    findings = []

try:
    with open(diff_path, encoding='utf-8') as f:
        diff = json.load(f)
except Exception:
    diff = {}

now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

sev_order = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}
findings.sort(key=lambda x: (sev_order.get(x.get('severity','INFO'),99), -x.get('cvss_score',0)))

sev_col = {
    'CRITICAL':'#ff3b5c','HIGH':'#ff7a00',
    'MEDIUM':'#f5c518','LOW':'#4ec9b0','INFO':'#569cd6'
}
sev_bg = {
    'CRITICAL':'rgba(255,59,92,.1)','HIGH':'rgba(255,122,0,.1)',
    'MEDIUM':'rgba(245,197,24,.08)','LOW':'rgba(78,201,176,.08)','INFO':'rgba(86,156,214,.08)'
}
conf_col = {'CONFIRMED':'#4ec9b0','LIKELY':'#f5c518','POSSIBLE':'#888'}

counts = {s:sum(1 for f in findings if f.get('severity')==s)
          for s in ['CRITICAL','HIGH','MEDIUM','LOW','INFO']}
total  = len(findings)
score  = sum(f.get('cvss_score',0) for f in findings)
cats   = sorted(set(f.get('category','') for f in findings))

#  Executive Summary: top 5 by CVSS 
top5 = sorted(findings, key=lambda x: -x.get('cvss_score',0))[:5]

def esc(s): return H.escape(str(s))

def top5_html():
    out = ''
    for f in top5:
        sev = f.get('severity','INFO')
        col = sev_col.get(sev,'#888')
        out += f'''
        <div class="exec-item">
          <span class="exec-sev" style="color:{col};border-color:{col}">{esc(sev)}</span>
          <div class="exec-content">
            <div class="exec-title">{esc(f.get("title",""))}</div>
            <div class="exec-cat">{esc(f.get("category",""))}  CVSS {f.get("cvss_score","?")}</div>
          </div>
        </div>'''
    return out

def finding_card(f, idx):
    sev  = f.get('severity','INFO')
    col  = sev_col.get(sev,'#888')
    bg   = sev_bg.get(sev,'#1e1e1e')
    conf = f.get('confidence','LIKELY')
    ccol = conf_col.get(conf,'#888')
    safe_cat = f.get('category','').replace(' ','_').replace('/','_').replace('-','_').replace(':','_').replace('(','').replace(')','')
    return f'''
    <div class="finding" data-sev="{sev}" data-cat="{safe_cat}" id="f{idx}">
      <div class="fhdr" onclick="tog('f{idx}')">
        <div class="fhdr-left">
          <span class="sev-badge" style="background:{col}">{esc(sev)}</span>
          <span class="conf-badge" style="color:{ccol};border-color:{ccol}">{esc(conf)}</span>
          <span class="ftitle">{esc(f.get("title",""))}</span>
        </div>
        <div class="fhdr-right">
          <span class="fcat">{esc(f.get("category",""))}</span>
          <span class="cvss-score">CVSS {f.get("cvss_score","?")}</span>
          <span class="cvss-score">{esc(f.get("cwe","CWE-693"))}</span>
          <span class="chev" id="ch{idx}"></span>
        </div>
      </div>
      <div class="fbody" id="fb{idx}" style="display:none;background:{bg}">
        <div class="fb-section">
          <div class="fb-label">Description</div>
          <p class="fb-text">{esc(f.get("description",""))}</p>
        </div>
        <div class="fb-section">
          <div class="fb-label">Evidence</div>
          <pre class="evidence">{esc(f.get("evidence",""))}</pre>
        </div>
        <div class="fb-section verify-steps">
          <div class="fb-label">Steps To Verify</div>
          <pre class="verify-steps-pre">{esc(f.get("steps_to_verify",""))}</pre>
        </div>
        <div class="fb-section remediation">
          <div class="fb-label">Remediation</div>
          <p class="fb-text remedy">{esc(f.get("remediation",""))}</p>
        </div>
      </div>
    </div>'''

findings_cards = '\n'.join(finding_card(f,i) for i,f in enumerate(findings))

nav_links = ''
for cat in cats:
    sc = cat.replace(' ','_').replace('/','_').replace('-','_').replace(':','_').replace('(','').replace(')','')
    cnt = sum(1 for f in findings if f.get('category')==cat)
    nav_links += f'<div class="nav-item" onclick="filterCat(\'{sc}\')">{esc(cat)}<span class="nav-cnt">{cnt}</span></div>\n'

# Diff section HTML
diff_html = ''
if diff and diff.get('summary'):
    s = diff['summary']
    added_items = ''.join(f'<div class="diff-item diff-added">+ {esc(f.get("title",""))}</div>' for f in diff.get('added',[])[:20])
    fixed_items = ''.join(f'<div class="diff-item diff-fixed"> {esc(f.get("title",""))}</div>' for f in diff.get('fixed',[])[:20])
    diff_html = f'''
    <div class="diff-section" id="diffSection">
      <div class="diff-header">
        <h3>Version Diff: <span>{esc(apk_name)}</span> vs <span class="dim">{esc(apk2_name)}</span></h3>
        <div class="diff-stats">
          <span class="diff-stat added">+{s.get("added_count",0)} new</span>
          <span class="diff-stat fixed">-{s.get("fixed_count",0)} fixed</span>
          <span class="diff-stat persist">{s.get("persisting_count",0)} persisting</span>
        </div>
      </div>
      <div class="diff-columns">
        <div class="diff-col"><div class="diff-col-title"> New Findings</div>{added_items or "<div class='dim'>None</div>"}</div>
        <div class="diff-col"><div class="diff-col-title"> Fixed Findings</div>{fixed_items or "<div class='dim'>None</div>"}</div>
      </div>
    </div>'''

missing_html = ''
if missing:
    tools_str = ' '.join(f'<code>{m}</code>' for m in missing)
    missing_html = f'<div class="missing-bar"> Missing tools (reduced coverage): {tools_str}</div>'

#  HTML REPORT 
html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Android Audit  {esc(pkg)}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,400;0,700;1,400&family=Clash+Display:wght@400;600;700&family=Inter:wght@400;500;600&display=swap');
:root{{
  --bg:#08080a;--bg2:#0f0f12;--bg3:#16161b;--bg4:#1c1c23;
  --brd:#252530;--brd2:#2e2e3a;
  --txt:#dddde8;--muted:#6b6b80;--dim:#3a3a4a;
  --crit:#ff3b5c;--high:#ff7a00;--med:#f5c518;--low:#4ec9b0;--info:#569cd6;
  --accent:#7c6af7;--accent2:#a78bfa;
  --green:#22c55e;--red:#ef4444;
}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Inter',sans-serif;background:var(--bg);color:var(--txt);display:flex;min-height:100vh;overflow-x:hidden}}

/* Scrollbar */
::-webkit-scrollbar{{width:5px;height:5px}}
::-webkit-scrollbar-track{{background:var(--bg2)}}
::-webkit-scrollbar-thumb{{background:var(--dim);border-radius:3px}}
::-webkit-scrollbar-thumb:hover{{background:var(--accent)}}

/* Sidebar */
.sidebar{{width:240px;min-height:100vh;background:var(--bg2);border-right:1px solid var(--brd);
  position:fixed;top:0;left:0;bottom:0;overflow-y:auto;z-index:100;display:flex;flex-direction:column}}
.sb-logo{{padding:24px 18px 16px;border-bottom:1px solid var(--brd)}}
.sb-logo h1{{font-family:'Clash Display',sans-serif;font-size:15px;font-weight:700;
  letter-spacing:2px;text-transform:uppercase;color:var(--accent2)}}
.sb-logo .pkg{{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--muted);
  margin-top:5px;word-break:break-all;line-height:1.5}}
.sb-logo .ts{{font-size:10px;color:var(--dim);margin-top:3px}}

.sev-filters{{padding:12px;border-bottom:1px solid var(--brd);display:flex;flex-direction:column;gap:5px}}
.sf{{display:flex;align-items:center;justify-content:space-between;padding:7px 10px;
  border-radius:5px;cursor:pointer;font-size:11px;font-weight:600;letter-spacing:1.2px;
  transition:opacity .15s;border:1px solid transparent;user-select:none}}
.sf:hover{{opacity:.8}}
.sf.active{{box-shadow:0 0 0 1px currentColor}}
.sf-crit{{background:rgba(255,59,92,.12);color:var(--crit);border-color:rgba(255,59,92,.25)}}
.sf-high{{background:rgba(255,122,0,.12);color:var(--high);border-color:rgba(255,122,0,.25)}}
.sf-med{{background:rgba(245,197,24,.10);color:var(--med);border-color:rgba(245,197,24,.25)}}
.sf-low{{background:rgba(78,201,176,.10);color:var(--low);border-color:rgba(78,201,176,.25)}}
.sf-info{{background:rgba(86,156,214,.10);color:var(--info);border-color:rgba(86,156,214,.25)}}

.sb-sect{{font-size:9px;font-weight:600;letter-spacing:2px;text-transform:uppercase;
  color:var(--muted);padding:14px 16px 4px}}
.nav-item{{display:flex;align-items:center;justify-content:space-between;padding:7px 16px;
  font-size:11px;color:var(--muted);cursor:pointer;transition:all .15s;border-left:2px solid transparent}}
.nav-item:hover,.nav-item.active{{color:var(--txt);background:var(--bg3);border-left-color:var(--accent)}}
.nav-cnt{{background:var(--bg4);color:var(--muted);font-family:'JetBrains Mono',monospace;
  font-size:10px;padding:1px 6px;border-radius:8px}}
.sb-btn{{margin:10px 14px;padding:7px;background:transparent;border:1px solid var(--brd);
  color:var(--muted);border-radius:5px;font-family:'Inter',sans-serif;font-size:11px;
  cursor:pointer;transition:all .15s;text-align:center}}
.sb-btn:hover{{border-color:var(--accent);color:var(--accent)}}

/* Main */
.main{{margin-left:240px;flex:1;display:flex;flex-direction:column;min-width:0}}

/* Header */
.header{{padding:32px 36px 24px;border-bottom:1px solid var(--brd);background:var(--bg2);
  position:sticky;top:0;z-index:50;backdrop-filter:blur(8px)}}
.hdr-top{{display:flex;align-items:flex-start;justify-content:space-between;gap:20px}}
.hdr-left h2{{font-family:'Clash Display',sans-serif;font-size:28px;font-weight:700;letter-spacing:-0.5px}}
.hdr-left h2 span{{background:linear-gradient(135deg,var(--accent),var(--accent2));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}}
.hdr-meta{{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--muted);margin-top:6px}}
.hdr-score{{text-align:center}}
.hdr-score .score-n{{font-family:'Clash Display',sans-serif;font-size:48px;font-weight:700;
  line-height:1;color:var(--crit)}}
.hdr-score .score-l{{font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--muted)}}

/* Stats bar */
.stats{{display:flex;margin-top:18px;border:1px solid var(--brd);border-radius:8px;overflow:hidden}}
.stat{{flex:1;padding:10px 14px;display:flex;flex-direction:column;align-items:center;gap:2px;
  border-right:1px solid var(--brd);cursor:pointer;transition:background .15s}}
.stat:last-child{{border-right:none}}
.stat:hover{{background:var(--bg3)}}
.stat-n{{font-family:'Clash Display',sans-serif;font-size:22px;font-weight:700}}
.stat-l{{font-size:9px;letter-spacing:1.5px;text-transform:uppercase;color:var(--muted)}}

/* CVSS total */
.cvss-total{{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;
  background:var(--bg4);border:1px solid var(--brd);border-radius:4px;
  font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--med);margin-top:8px}}

/* Executive Summary */
.exec-section{{margin:20px 36px;background:var(--bg2);border:1px solid var(--brd);
  border-radius:10px;overflow:hidden}}
.exec-hdr{{padding:14px 18px;border-bottom:1px solid var(--brd);
  font-size:12px;font-weight:600;letter-spacing:1px;text-transform:uppercase;color:var(--accent2)}}
.exec-body{{padding:12px}}
.exec-item{{display:flex;align-items:center;gap:12px;padding:8px 6px;border-radius:6px;
  transition:background .15s}}
.exec-item:hover{{background:var(--bg3)}}
.exec-sev{{font-size:9px;font-weight:700;letter-spacing:1px;padding:3px 7px;
  border-radius:3px;border:1px solid;min-width:64px;text-align:center;flex-shrink:0}}
.exec-title{{font-size:13px;font-weight:500}}
.exec-cat{{font-size:10px;color:var(--muted);margin-top:2px}}

/* Diff section */
.diff-section{{margin:0 36px 16px;background:var(--bg2);border:1px solid var(--brd2);
  border-radius:10px;overflow:hidden}}
.diff-header{{padding:14px 18px;border-bottom:1px solid var(--brd);display:flex;
  align-items:center;justify-content:space-between}}
.diff-header h3{{font-size:13px;font-weight:600;color:var(--accent2)}}
.diff-header h3 span{{color:var(--txt)}}
.diff-header .dim{{color:var(--muted)}}
.diff-stats{{display:flex;gap:8px}}
.diff-stat{{font-size:11px;font-weight:600;padding:3px 8px;border-radius:4px}}
.diff-stat.added{{background:rgba(255,59,92,.1);color:var(--crit)}}
.diff-stat.fixed{{background:rgba(34,197,94,.1);color:var(--green)}}
.diff-stat.persist{{background:rgba(107,107,128,.1);color:var(--muted)}}
.diff-columns{{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--brd)}}
.diff-col{{background:var(--bg2);padding:14px}}
.diff-col-title{{font-size:11px;font-weight:600;color:var(--muted);margin-bottom:8px;
  text-transform:uppercase;letter-spacing:1px}}
.diff-item{{font-size:12px;padding:5px 8px;border-radius:4px;margin-bottom:3px}}
.diff-added{{background:rgba(255,59,92,.06);color:var(--txt);border-left:2px solid var(--crit)}}
.diff-fixed{{background:rgba(34,197,94,.06);color:var(--txt);border-left:2px solid var(--green)}}

/* Search bar */
.search-wrap{{padding:14px 36px;border-bottom:1px solid var(--brd);background:var(--bg2)}}
.search-input{{width:100%;background:var(--bg3);border:1px solid var(--brd);color:var(--txt);
  padding:9px 14px;border-radius:7px;font-family:'JetBrains Mono',monospace;font-size:12px;
  outline:none;transition:border-color .15s}}
.search-input:focus{{border-color:var(--accent)}}
.search-input::placeholder{{color:var(--muted)}}

/* Missing tools bar */
.missing-bar{{margin:12px 36px;padding:10px 14px;background:rgba(245,197,24,.06);
  border:1px solid rgba(245,197,24,.2);border-radius:6px;font-size:11px;color:var(--med)}}
.missing-bar code{{background:rgba(245,197,24,.08);padding:1px 5px;border-radius:3px;
  font-family:'JetBrains Mono',monospace;font-size:10px;margin:0 2px}}

/* Findings container */
.findings{{padding:16px 36px 48px;display:flex;flex-direction:column;gap:6px}}
.no-results{{text-align:center;color:var(--muted);padding:60px;font-size:14px;display:none}}

/* Finding card */
.finding{{border:1px solid var(--brd);border-radius:8px;overflow:hidden;transition:border-color .2s}}
.finding:hover{{border-color:var(--brd2)}}
.fhdr{{display:flex;align-items:center;justify-content:space-between;padding:12px 14px;
  cursor:pointer;background:var(--bg2);user-select:none;gap:10px}}
.fhdr-left{{display:flex;align-items:center;gap:8px;min-width:0;flex:1}}
.fhdr-right{{display:flex;align-items:center;gap:8px;flex-shrink:0}}
.sev-badge{{font-size:9px;font-weight:700;letter-spacing:1.2px;padding:2px 7px;
  border-radius:3px;color:#0a0a0a;min-width:64px;text-align:center;flex-shrink:0}}
.conf-badge{{font-size:9px;font-weight:600;letter-spacing:1px;padding:2px 6px;
  border-radius:3px;border:1px solid;flex-shrink:0}}
.ftitle{{font-size:13px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.fcat{{font-size:10px;color:var(--muted);font-family:'JetBrains Mono',monospace;
  background:var(--bg3);padding:2px 7px;border-radius:3px}}
.cvss-score{{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--med);
  background:var(--bg3);padding:2px 6px;border-radius:3px}}
.chev{{color:var(--muted);font-size:11px;transition:transform .2s}}

/* Finding body */
.fbody{{padding:14px 18px;border-top:1px solid var(--brd)}}
.fb-section{{margin-bottom:12px}}
.fb-label{{font-size:9px;font-weight:700;letter-spacing:2px;text-transform:uppercase;
  color:var(--muted);margin-bottom:5px}}
.fb-text{{font-size:13px;line-height:1.65;color:var(--txt)}}
.evidence{{font-family:'JetBrains Mono',monospace;font-size:11px;color:#7ec8a0;
  background:var(--bg);padding:10px 12px;border-radius:5px;border:1px solid var(--brd);
  overflow-x:auto;white-space:pre-wrap;word-break:break-all;max-height:160px;overflow-y:auto}}
.verify-steps{{background:rgba(86,156,214,.08);border:1px solid rgba(86,156,214,.22);
  border-radius:6px;padding:10px 14px!important}}
.verify-steps-pre{{font-family:'JetBrains Mono',monospace;font-size:11px;color:#b5dcff;
  background:var(--bg);padding:10px 12px;border-radius:5px;border:1px solid var(--brd);
  overflow-x:auto;white-space:pre-wrap;word-break:break-word;line-height:1.65}}
.remediation{{background:rgba(124,106,247,.06);border:1px solid rgba(124,106,247,.2);
  border-radius:6px;padding:10px 14px!important}}
.remedy{{color:#c4b5fd;font-size:12px;line-height:1.7}}

/* Footer */
.footer{{text-align:center;padding:18px;color:var(--muted);font-size:10px;
  font-family:'JetBrains Mono',monospace;border-top:1px solid var(--brd);margin-top:auto}}

@media(max-width:768px){{
  .sidebar{{display:none}}.main{{margin-left:0}}
  .header,.search-wrap,.findings,.exec-section,.diff-section{{padding-left:14px;padding-right:14px}}
  .diff-columns{{grid-template-columns:1fr}}
}}
</style>
</head>
<body>

<aside class="sidebar">
  <div class="sb-logo">
    <h1> Android Audit</h1>
    <div class="pkg">{esc(pkg)}</div>
    <div class="ts">{now}</div>
  </div>
  <div class="sev-filters">
    <div class="sf sf-crit" onclick="filterSev('CRITICAL')">CRITICAL<span>{counts['CRITICAL']}</span></div>
    <div class="sf sf-high" onclick="filterSev('HIGH')">HIGH<span>{counts['HIGH']}</span></div>
    <div class="sf sf-med"  onclick="filterSev('MEDIUM')">MEDIUM<span>{counts['MEDIUM']}</span></div>
    <div class="sf sf-low"  onclick="filterSev('LOW')">LOW<span>{counts['LOW']}</span></div>
    <div class="sf sf-info" onclick="filterSev('INFO')">INFO<span>{counts['INFO']}</span></div>
  </div>
  <div class="sb-sect">Categories</div>
  {nav_links}
  <div class="sb-btn" onclick="clearFilters()"> Clear Filters</div>
  <div class="sb-btn" onclick="expandAll()"> Expand All</div>
</aside>

<main class="main">
  <div class="header">
    <div class="hdr-top">
      <div class="hdr-left">
        <h2>Security <span>Report</span></h2>
        <div class="hdr-meta">APK: {esc(apk_name)}  Package: {esc(pkg)}  {now}</div>
        <div class="cvss-total"> Total CVSS Score: {round(score,1)}</div>
      </div>
      <div class="hdr-score">
        <div class="score-n" style="color:{'#ff3b5c' if counts['CRITICAL']>0 else '#ff7a00' if counts['HIGH']>0 else '#f5c518'}">{total}</div>
        <div class="score-l">findings</div>
      </div>
    </div>
    <div class="stats">
      <div class="stat" onclick="filterSev('CRITICAL')"><span class="stat-n" style="color:var(--crit)">{counts['CRITICAL']}</span><span class="stat-l">Critical</span></div>
      <div class="stat" onclick="filterSev('HIGH')"><span class="stat-n" style="color:var(--high)">{counts['HIGH']}</span><span class="stat-l">High</span></div>
      <div class="stat" onclick="filterSev('MEDIUM')"><span class="stat-n" style="color:var(--med)">{counts['MEDIUM']}</span><span class="stat-l">Medium</span></div>
      <div class="stat" onclick="filterSev('LOW')"><span class="stat-n" style="color:var(--low)">{counts['LOW']}</span><span class="stat-l">Low</span></div>
      <div class="stat" onclick="filterSev('INFO')"><span class="stat-n" style="color:var(--info)">{counts['INFO']}</span><span class="stat-l">Info</span></div>
    </div>
  </div>

  <div class="exec-section">
    <div class="exec-hdr"> Executive Summary  Top {len(top5)} Findings by CVSS Score</div>
    <div class="exec-body">{top5_html()}</div>
  </div>

  {diff_html}

  <div class="search-wrap">
    <input class="search-input" type="text" id="srch"
           placeholder="  Search findings by title, category, description, evidence, verification steps, or remediation..."
           oninput="applyFilters()">
  </div>

  {missing_html}

  <div class="findings" id="fc">
    {findings_cards}
    <div class="no-results" id="nr">No findings match your current filters.</div>
  </div>

  <div class="footer">
    Android Bug Bounty Static Analyzer v2.3  Kali Linux WSL2  {total} findings  {esc(pkg)}  {now}
  </div>
</main>

<script>
SCRIPT_PLACEHOLDER
</script>
</body>
</html>'''

# JS is kept in a plain (non-f) string so curly braces are literal, not format expressions
_js = r"""
let aS=null, aC=null;
const allF = document.querySelectorAll('.finding');

function tog(id){
  const b=document.getElementById('fb'+id.slice(1));
  const c=document.getElementById('ch'+id.slice(1));
  const open=b.style.display==='none';
  b.style.display=open?'block':'none';
  c.style.transform=open?'rotate(180deg)':'';
}

function expandAll(){
  allF.forEach((_,i)=>{
    const b=document.getElementById('fb'+i);
    const c=document.getElementById('ch'+i);
    if(b){b.style.display='block';c.style.transform='rotate(180deg)';}
  });
}

function filterSev(s){
  aS=(aS===s)?null:s; aC=null;
  document.querySelectorAll('.sf').forEach(e=>e.classList.remove('active'));
  if(aS) document.querySelectorAll('.sf-'+s.toLowerCase()).forEach(e=>e.classList.add('active'));
  document.querySelectorAll('.nav-item').forEach(e=>e.classList.remove('active'));
  applyFilters();
}

function filterCat(c){
  aC=(aC===c)?null:c; aS=null;
  document.querySelectorAll('.sf').forEach(e=>e.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(e=>{
    e.classList.toggle('active',e.getAttribute('onclick')&&e.getAttribute('onclick').includes(c));
  });
  applyFilters();
}

function clearFilters(){
  aS=null;aC=null;
  document.getElementById('srch').value='';
  document.querySelectorAll('.sf,.nav-item').forEach(e=>e.classList.remove('active'));
  applyFilters();
}

function applyFilters(){
  const q=document.getElementById('srch').value.toLowerCase();
  let vis=0;
  allF.forEach(f=>{
    const ok=((!aS||f.dataset.sev===aS)&&(!aC||f.dataset.cat===aC)&&(!q||f.textContent.toLowerCase().includes(q)));
    f.style.display=ok?'':'none';
    if(ok)vis++;
  });
  document.getElementById('nr').style.display=vis===0?'block':'none';
}
"""

html = html.replace('SCRIPT_PLACEHOLDER', _js)

#  Write HTML 
with open(html_out, 'w', encoding='utf-8') as f:
    f.write(html)
print(f"HTML report: {html_out}")

#  Write JSON 
with open(json_out, 'w', encoding='utf-8') as f:
    json.dump({
        "meta": {"package": pkg, "apk": apk_name, "generated": now, "total": total, "cvss_total": round(score,1)},
        "summary": counts,
        "findings": findings,
        "diff": diff if diff else {}
    }, f, indent=2)
print(f"JSON report: {json_out}")

#  Write Markdown 
md = f"# Android Security Audit Report\n\n"
md += f"**Package:** `{pkg}`  \n**APK:** `{apk_name}`  \n**Generated:** {now}\n\n"
md += f"## Summary\n\n| Severity | Count |\n|---|---|\n"
for sev in ['CRITICAL','HIGH','MEDIUM','LOW','INFO']:
    md += f"| {sev} | {counts[sev]} |\n"
md += f"\n**Total CVSS Score:** {round(score,1)}\n\n"
md += f"## Executive Summary (Top 5)\n\n"
for f in top5:
    md += f"- **[{f.get('severity','')}]** {f.get('title','')} _(CVSS {f.get('cvss_score','')})_\n"
md += f"\n## Findings\n\n"
for f in findings:
    md += f"### [{f.get('severity','')}] {f.get('title','')}\n\n"
    md += f"**Category:** {f.get('category','')}  \n"
    md += f"**Confidence:** {f.get('confidence','')}  \n"
    md += f"**CVSS Score:** {f.get('cvss_score','')}  \n\n"
    md += f"**CWE:** {f.get('cwe','CWE-693')}  \n\n"
    md += f"**Description:** {f.get('description','')}\n\n"
    md += f"**Evidence:**\n```\n{f.get('evidence','')}\n```\n\n"
    md += f"**Steps to Verify:**\n```\n{f.get('steps_to_verify','')}\n```\n\n"
    md += f"**Remediation:** {f.get('remediation','')}\n\n---\n\n"
with open(md_out, 'w', encoding='utf-8') as f:
    f.write(md)
print(f"Markdown report: {md_out}")
PYEOF

    #  SARIF output (GitHub Code Scanning / Burp Enterprise compatible)
    python3 - "${FINDINGS_JSON}" "${REPORT_SARIF}" << 'PYEOF'
import sys, json, re, hashlib
from datetime import datetime, timezone

findings_path = sys.argv[1]
sarif_path    = sys.argv[2]

try:
    with open(findings_path, encoding='utf-8') as f:
        findings = json.load(f)
except Exception:
    findings = []

sev_sarif = {
    'CRITICAL': 'error',
    'HIGH':     'error',
    'MEDIUM':   'warning',
    'LOW':      'note',
    'INFO':     'none'
}

def parse_location(evidence):
    for raw in str(evidence or '').splitlines():
        line = raw.strip()
        if not line:
            continue
        m = re.match(r'^(.+?):(\d+):', line)
        if not m:
            continue
        path = m.group(1).strip().replace("\\", "/")
        if path.startswith('/tmp/android_audit_'):
            # Keep SARIF paths relative and portable.
            parts = path.split('/')
            path = '/'.join(parts[3:]) if len(parts) > 3 else path
        try:
            line_no = max(1, int(m.group(2)))
        except Exception:
            line_no = 1
        return path or 'target.apk', line_no
    return 'target.apk', 1

rules = []
results = []
seen_rules = set()

for f in findings:
    category = f.get('category', 'General')
    title = f.get('title', 'unknown')
    sev = str(f.get('severity', 'INFO')).upper()
    cwe = f.get('cwe', 'CWE-693')
    steps = f.get('steps_to_verify', '') or 'Manual verification steps not provided.'

    rule_seed = f"{category}|{title}"
    rule_id = "APKCHECK_" + hashlib.sha1(rule_seed.encode('utf-8', errors='ignore')).hexdigest()[:16]

    if rule_id not in seen_rules:
        seen_rules.add(rule_id)
        rules.append({
            "id": rule_id,
            "name": title,
            "shortDescription": {"text": title},
            "fullDescription": {"text": f.get('description', '')},
            "help": {
                "text": f"Steps to verify:\n{steps}\n\nRemediation:\n{f.get('remediation', '')}" ,
                "markdown": f"**Steps to Verify**\n\n```\n{steps}\n```\n\n**Remediation**\n\n{f.get('remediation', '')}"
            },
            "helpUri": "https://mas.owasp.org/MASTG/",
            "properties": {
                "tags": [category, sev, cwe],
                "precision": str(f.get('confidence', 'LIKELY')).lower(),
                "problem.severity": sev_sarif.get(sev, 'warning')
            }
        })

    uri, start_line = parse_location(f.get('evidence', ''))
    message = f.get('description', '') or title

    results.append({
        "ruleId": rule_id,
        "level": sev_sarif.get(sev, 'warning'),
        "message": {"text": message},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": start_line}
            }
        }],
        "partialFingerprints": {
            "primaryLocationLineHash": hashlib.sha1(f"{rule_id}|{uri}|{start_line}".encode('utf-8')).hexdigest()[:20]
        },
        "properties": {
            "cvss_score": f.get('cvss_score', 0),
            "confidence": f.get('confidence', 'LIKELY'),
            "category": category,
            "cwe": cwe,
            "steps_to_verify": steps
        }
    })

sarif = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {
            "driver": {
                "name": "AndroidStaticAudit",
                "version": "2.3",
                "informationUri": "https://github.com/",
                "rules": rules
            }
        },
        "results": results,
        "invocations": [{
            "executionSuccessful": True,
            "endTimeUtc": datetime.now(timezone.utc).isoformat()
        }]
    }]
}

with open(sarif_path, 'w', encoding='utf-8') as f:
    json.dump(sarif, f, indent=2)

print(f"SARIF report: {sarif_path} ({len(results)} results, {len(rules)} rules)")
PYEOF
}

# 
# MAIN
# 
main() {
    banner

    [ $# -eq 0 ] && usage

    #  Parse args
    case "$1" in
        --check-tools) check_tools; exit 0 ;;
        --help|-h)     usage ;;
    esac

    local APK1="$1"
    shift

    # Second positional arg = old APK for diff mode
    if [ $# -gt 0 ] && [[ "$1" != --* ]]; then
        APK2="$1"
        DIFF_MODE=true
        shift
    fi

    # Flags
    while [ $# -gt 0 ]; do
        case "$1" in
            --resume)          RESUME_MODE=true ;;
            --live)            DO_LIVE_CHECKS=true ;;
            --no-live)         DO_LIVE_CHECKS=false ;;
            --whitelist)       shift; WHITELIST_FILE="$1" ;;
            --skip)            shift
                               IFS=',' read -ra SKIP_MODULES <<< "${1#modules:}" ;;
            --clear-cache)     # Wipe cache for this APK and re-decompile fresh
                               local _hash; _hash=$(md5sum "$APK1" 2>/dev/null | cut -c1-16)
                               [ -n "$_hash" ] && rm -rf "${CACHE_BASE}/${_hash}"
                               info "Cache cleared for $(basename "$APK1")" ;;
            *) warn "Unknown flag: $1" ;;
        esac
        shift
    done

    #  Validate input
    [ ! -f "$APK1" ] && { fail "APK not found: $APK1"; exit 1; }
    file "$APK1" | grep -qiE 'zip|APK|android|Java' || warn "File may not be a valid APK"

    #  Setup workspace
    refresh_runtime_paths
    mkdir -p "$WORK_DIR" "${WORK_DIR}/parallel"
    init_findings

    #  Run
    info "Starting scan: $(basename "$APK1")"
    info "Work dir: $WORK_DIR"
    [ "$RESUME_MODE"  = true ] && info "Resume mode ON"
    [ "$DIFF_MODE"    = true ] && info "Diff mode: $(basename "$APK1") vs $(basename "$APK2")"
    [ -n "$WHITELIST_FILE"  ] && info "Whitelist: $WHITELIST_FILE"
    [ ${#SKIP_MODULES[@]} -gt 0 ] && info "Skipping: ${SKIP_MODULES[*]}"
    echo ""

    check_tools

    if [ "$DIFF_MODE" = true ]; then
        run_diff_mode "$APK1" "$APK2"
    else
        extract_apk "$APK1"
        run_all_modules
        generate_report "$APK1"
    fi

    #  Final summary
    section "SCAN COMPLETE"
    echo ""
    if [ -f "${REPORT_HTML}" ]; then
        echo -e "  ${BOLD}${GREEN}HTML Report  :${RESET} ${REPORT_HTML}"
    else
        echo -e "  ${BOLD}${RED}HTML Report  :${RESET} ${REPORT_HTML} ${YELLOW}(missing)${RESET}"
    fi
    if [ -f "${REPORT_JSON}" ]; then
        echo -e "  ${BOLD}${GREEN}JSON Report  :${RESET} ${REPORT_JSON}"
    else
        echo -e "  ${BOLD}${RED}JSON Report  :${RESET} ${REPORT_JSON} ${YELLOW}(missing)${RESET}"
    fi
    if [ -f "${REPORT_MD}" ]; then
        echo -e "  ${BOLD}${GREEN}MD Report    :${RESET} ${REPORT_MD}"
    else
        echo -e "  ${BOLD}${RED}MD Report    :${RESET} ${REPORT_MD} ${YELLOW}(missing)${RESET}"
    fi
    if [ -f "${REPORT_SARIF}" ]; then
        echo -e "  ${BOLD}${GREEN}SARIF Report :${RESET} ${REPORT_SARIF}  ${CYAN}(import to GitHub Code Scanning / Burp)${RESET}"
    else
        echo -e "  ${BOLD}${RED}SARIF Report :${RESET} ${REPORT_SARIF} ${YELLOW}(missing)${RESET}"
    fi
    echo -e "  ${BOLD}${CYAN}Work Dir     :${RESET} ${WORK_DIR}"
    echo ""
    echo -e "  ${BOLD}Open in browser:${RESET}"
    echo -e "  xdg-open ${REPORT_HTML}"
    echo -e "  cp ${REPORT_HTML} /mnt/c/Users/\$USER/Desktop/"
    echo ""
    local total
    total=$(python3 -c "import json; print(len(json.load(open('${FINDINGS_JSON}'))))" 2>/dev/null || echo "?")
    success "Total findings: $total"
    echo ""
}

main "$@"
