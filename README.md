# Android Static Audit  apkcheck

**v2.3.4**  Kali Linux WSL2  Android Bug Bounty Static Analysis Suite

A single Bash script that decompiles an APK and runs every meaningful static analysis technique against it  secrets, crypto, WebView, ICC chains, native binaries, CVE matching, and more  producing HTML, JSON, Markdown, and SARIF reports.

## Latest Improvements (v2.3.4)

- Decompilation quality states: `OK`, `PARTIAL`, `PARTIAL_FALLBACK`, `FAILED`
- `jadx:fail` is now treated as partial coverage if Java files were still produced
- Automatic fallback (`dex2jar + CFR`) only when JADX yields zero Java files
- Decompilation telemetry files written to:
  - `/tmp/android_audit_<ts>/decomp_status.txt`
  - `/tmp/android_audit_<ts>/decomp_java_count.txt`
  - `/tmp/android_audit_<ts>/decomp_jadx_errors.txt`
- Metadata section now reports decompiler health as findings when coverage is partial/failed
- `--check-tools` now marks fallback tooling (`dex2jar`, `CFR_JAR`) as optional, not required
- Every finding now includes explicit **Steps to Verify** (HTML, JSON, Markdown, and SARIF help text) for manual validation
- Report generation is now ARG_MAX-safe (loads findings/diff from files, not giant CLI args), preventing missing HTML/JSON/MD outputs on large scans
- Firebase live-check false positive fix: CRITICAL is raised only when unauthenticated `.json` returns real data; `Permission denied` and `database disabled` are now treated as non-vulnerable states

---

## Quick Start

```bash
# One-time: fix permissions after install
sudo chmod +x /usr/local/bin/jadx

# Run
bash apkcheck.sh target.apk

# View report
xdg-open android_audit_*.html
# or copy to Windows desktop
cp android_audit_*.html /mnt/c/Users/$USER/Desktop/
```

---

## Installation (Kali WSL2)

### Step 1  System packages
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y \
    apktool adb aapt default-jdk openjdk-11-jdk \
    binutils unzip curl wget file jq nodejs npm \
    python3 python3-pip checksec
```

### Step 2  Python tools
```bash
pip3 install apkleaks semgrep apkid --break-system-packages
```

### Step 3  jadx (Java decompiler)
```bash
wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.5.0.zip
unzip jadx-1.5.0.zip -d ~/jadx
sudo ln -sf ~/jadx/bin/jadx /usr/local/bin/jadx
sudo chmod +x ~/jadx/bin/jadx          # critical: must be executable
sudo chmod +x ~/jadx/bin/jadx-gui
jadx --version                          # verify
```

### Step 4  trufflehog
```bash
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
  | sh -s -- -b /usr/local/bin
```

### Step 5  Set Java 11 as default
```bash
sudo update-alternatives --config java   # pick openjdk-11
java -version                            # verify 11.x.x
```

### Step 6  Verify all tools
```bash
bash apkcheck.sh --check-tools
```

### Optional: JADX fallback decompiler (dex2jar + CFR)
Used when JADX returns **0 Java files**. This improves recovery on heavily obfuscated APKs.
```bash
# dex2jar CLI
sudo apt install -y dex2jar

# CFR decompiler jar
mkdir -p ~/.android_audit/tools
wget -O ~/.android_audit/tools/cfr.jar https://www.benf.org/other/cfr/cfr-0.152.jar

# Optional: custom CFR path
export CFR_JAR=~/.android_audit/tools/cfr.jar

# Verify optional fallback visibility in tool check
bash apkcheck.sh --check-tools
```

### Optional: FlowDroid
Auto-downloads on first run. For restricted networks, download manually:
```
https://github.com/secure-software-engineering/FlowDroid/releases
 soot-infoflow-cmd-jar-with-dependencies.jar
 ~/.android_audit/flowdroid/soot-infoflow-cmd.jar
```

### Optional: MobSF
```bash
sudo apt install -y docker.io && sudo systemctl start docker
sudo usermod -aG docker $USER   # log out and back in
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
export MOBSF_APIKEY=<key_from_mobsf_settings>
```

### Optional: Ghidra (deep native CFG analysis)
```bash
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.1.2_build/ghidra_11.1.2_PUBLIC_20240709.zip
unzip ghidra_11.1.2_PUBLIC_20240709.zip -d /opt/ghidra_install
sudo ln -sf /opt/ghidra_install/ghidra_11.1.2_PUBLIC /opt/ghidra
echo 'export PATH=$PATH:/opt/ghidra/support' >> ~/.bashrc && source ~/.bashrc
```

---

## Usage

```
bash apkcheck.sh <apk> [options]
```

| Option | Description |
|--------|-------------|
| `--clear-cache` | Delete cached decompile for this APK and re-decompile fresh |
| `--resume` | Reuse a previously validated cache (skips decompilation) |
| `--skip modules:X,Y` | Skip named modules, e.g. `--skip modules:flowdroid,mobsf` |
| `--no-live` | Disable live network checks |
| `--whitelist file.txt` | Suppress findings by exact `Title`, exact `Category|Title`, or regex rule `re:<pattern>` |
| `--check-tools` | Print tool availability table and exit |
| `--diff apk2` | Compare two APK versions, show new/fixed findings |

### Whitelist File Format

Each non-empty line is one suppression rule:

- `Some Finding Title` -> suppresses exact title match
- `Category|Some Finding Title` -> suppresses exact category+title pair
- `re:regex_here` -> suppresses any finding whose title (or `Category|Title`) matches the regex
- `# comment` -> ignored

### Examples


```bash
# Basic scan
bash apkcheck.sh app.apk

# Clear stale cache and rescan (use this if you get 0 findings)
bash apkcheck.sh app.apk --clear-cache

# Skip slow modules for quick triage
bash apkcheck.sh app.apk --skip modules:flowdroid,iccta,nativedeep

# Compare two versions
bash apkcheck.sh v1.apk v2.apk --diff

# Offline mode
bash apkcheck.sh app.apk --no-live --skip modules:flowdroid,libcve
```

---

## Output Files

| File | Format | Use |
|------|--------|-----|
| `android_audit_<ts>.html` | Interactive HTML | Primary report  filter, search, expand findings, and follow per-finding **Steps to Verify** |
| `android_audit_<ts>.json` | JSON | CI/CD integration, custom tooling (`steps_to_verify` included per finding) |
| `android_audit_<ts>.md` | Markdown | GitHub issues, Notion, ticketing with evidence + verification checklist |
| `android_audit_<ts>.sarif` | SARIF 2.1.0 | GitHub Code Scanning/Burp with CWE tags, evidence-derived file:line, and verification/remediation guidance in rule help |

---

### Manual Verification Workflow

Each finding includes a `Steps to Verify` block with numbered, reproducible validation actions:

1. Open exact evidence file:line locations
2. Confirm vulnerable pattern/API presence
3. Validate reachability with attacker-controlled input
4. Reproduce impact on emulator/device

This is included in HTML cards, Markdown findings, JSON (`steps_to_verify` field), and SARIF rule help text.

---
## Analysis Modules

### Execution Flow

```
APKiD  Metadata  Manifest               (sequential)
           
     Parallel Batch 1 
     secrets  crypto  webview  storage  intents  smali  misc    
     react-native  flutter  cordova                              
                                                                
     Parallel Batch 2 
     aidl  contentprovider  backup  netconfig  native  firebase  
     semgrep  mobsf                                              
                                                                
     Live checks  FlowDroid  ICC                               
                                                                
     Parallel Batch 3 
     stringdeob  libcve  nativedeep
           
     merge_shards  generate_report
```

---

### APKiD  Packer & Protector Detection
Detects packers, obfuscators, anti-tamper, anti-VM, and copy-protection wrappers before any analysis runs. If a packer is detected, findings are flagged as potentially incomplete.

---

### AndroidManifest Analysis
Parses the apktool-decoded XML manifest (never the binary AXML copy in `original/`).

**Checks:** `debuggable`, `allowBackup`, `usesCleartextTraffic`, missing `networkSecurityConfig`, exported components without `android:permission`, providers with `grantUriPermissions`.

---

### Secrets & Credentials
Uses `scan_source()`  reads every source file **once** and applies all patterns simultaneously. Avoids the N-separate-grep performance collapse that produces 0 findings on large (30k+ file) codebases. Also runs apkleaks and trufflehog in parallel.

**Patterns:** AWS keys, Google API keys, Stripe live keys, JWT tokens, PEM private keys, Basic Auth URLs, GitHub PATs, Slack tokens, SendGrid keys, GCP service account blobs, hardcoded `password`/`api_key`/`access_token`, keys in `SecretKeySpec`, Telegram bot tokens.

---

### Cryptography Analysis

| Finding | Severity |
|---------|----------|
| AES/ECB mode | HIGH |
| DES / 3DES | HIGH |
| MD5 / SHA-1 | HIGH |
| Static/hardcoded IV | HIGH |
| Hardcoded key in SecretKeySpec | CRITICAL |
| RSA/ECB/PKCS1Padding | HIGH |
| RSA/None/NoPadding | CRITICAL |
| `Math.random()` for crypto | HIGH |
| `SecureRandom` with constant seed | HIGH |
| Empty/permissive TrustManager | CRITICAL |
| `AllowAllHostnameVerifier` | CRITICAL |
| `SSLContext("SSL")` (forces SSLv3) | CRITICAL |

---

### WebView Analysis

| Finding | Severity |
|---------|----------|
| `setJavaScriptEnabled(true)` | HIGH |
| `addJavascriptInterface()`  RCE | CRITICAL |
| `setAllowUniversalAccessFromFileURLs(true)`  UXSS | CRITICAL |
| `setAllowFileAccessFromFileURLs(true)` | HIGH |
| `handler.proceed()`  ignores TLS errors | CRITICAL |
| `loadUrl("http://...")` | HIGH |
| `loadUrl(getStringExtra(...))`  open redirect | CRITICAL |
| `evaluateJavascript(getStringExtra(...))`  JS injection | CRITICAL |
| `setWebContentsDebuggingEnabled(true)` | HIGH |

---

### Insecure Data Storage

| Finding | Severity |
|---------|----------|
| `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` | HIGH |
| External storage write | HIGH |
| Sensitive data in `Log.d/v/i/w/e` | HIGH |
| Sensitive keys in SharedPreferences | HIGH |
| Sensitive data copied to Clipboard | HIGH |
| Hardcoded password string literal | CRITICAL |
| Java `Serializable` / `ObjectOutputStream` | MEDIUM |

---

### Intent & IPC Vulnerabilities

| Finding | Severity |
|---------|----------|
| Mutable PendingIntent (missing `FLAG_IMMUTABLE`) | HIGH |
| Sticky broadcast | MEDIUM |
| `rawQuery`/`execSQL` with `getStringExtra`  SQL injection | CRITICAL |
| `new File(getStringExtra(...))`  path traversal | CRITICAL |
| `loadUrl(getStringExtra(...))`  open redirect | CRITICAL |
| `Runtime.exec(getStringExtra(...))`  command injection | CRITICAL |
| Fragment injection via intent | CRITICAL |
| `getSerializableExtra` / `getParcelableExtra`  deserialization | HIGH |

---

### Network Security Config
Parses `network_security_config.xml` for cleartext permissions, user CA trust, missing certificate pins, and debug overrides. Also scans source for empty `checkServerTrusted()`.

---

### ICC Cross-Component Intent Chain Analysis
Builds a directed component graph from manifest + jadx source. Detects multi-hop attack chains invisible to single-component tools.

| Pattern | Severity |
|---------|----------|
| Confused Deputy  unprotected component proxies to permission-protected one | HIGH |
| Data Laundering  forwards Intent extras without validation | MEDIUM |
| ContentResolver Proxy  exported component proxies protected ContentProvider | HIGH |
| Deep Link Chain  URI  Activity (no permission)  further launches | HIGH |
| PendingIntent Theft  exported component creates stealable PendingIntent | HIGH |

---

### FlowDroid  Inter-Procedural Taint Analysis
Tracks taint from 28 sources (Intent extras, SharedPreferences, location, camera, contacts, etc.) to 24 sinks (network, logs, files, SMS, clipboard). Auto-downloads JAR on first run. Requires Java 11.

---

### Obfuscated String Deobfuscation
Statically executes 7 compile-time obfuscation patterns without running the APK. Recovered strings are immediately tested against all secret patterns.

| Pattern | Example |
|---------|---------|
| Base64 decode | `Base64.decode("QVdTX0tFWT0=")`  `AWS_KEY=...` |
| XOR byte array | `new byte[]{0x41,0x13,...} ^ 0x42` |
| Hex string | `"4157534b..."`  UTF-8 |
| StringBuilder reverse | `new StringBuilder("yekipa").reverse()` |
| Char array construction | `new char[]{65,87,83,...}` |
| String join/split reassembly | `String.join("","AK","IA",...)` |
| Smali XOR const-push sequences | Bytecode-level patterns |

---

### Third-Party Library CVE Matching
Extracts library versions from Gradle files, JAR manifests, JAR filenames, and DEX strings, then queries the [OSV.dev](https://osv.dev) API. Reports CVE ID, CVSS score, affected version, and fixed version. Up to 60 libraries queried per scan.

---

### Deep Native Binary Analysis

**Layer 1  checksec (ELF mitigations)**

| Missing mitigation | Severity |
|-------------------|----------|
| NX (No-Execute) | CRITICAL |
| Full RELRO | HIGH |
| Stack Canary | HIGH |
| PIE | HIGH |
| FORTIFY_SOURCE | MEDIUM |

**Layer 2  nm dangerous function imports**
Confirms actual dynamic imports of `strcpy`, `strcat`, `sprintf`, `gets`, `system`, `popen`, `execv*`, `memcpy`, `dlopen`, `getenv`, etc. Cross-references JNI exports.

**Layer 3  Ghidra headless CFG (optional)**
Extracts call graph xrefs for dangerous functions, identifies large JNI methods (>100 instructions), maps caller addresses.

---

### Framework Analysis

| Framework | What's checked |
|-----------|----------------|
| React Native | Hardcoded secrets in JS bundle, disabled SSL, AsyncStorage with sensitive data, `console.log` leaks, `rejectUnauthorized: false` |
| Flutter | Dart snapshot detection, hardcoded strings in `libapp.so` |
| Cordova / Ionic / Capacitor | `allowNavigation` wildcards, `access origin="*"`, storage leaks in JS |

---

### Semgrep
Runs `p/android` and `p/owasp-mobile-top-10` rulesets against jadx source.

### MobSF REST API
If running locally on port 8000, uploads APK, imports all findings. Requires `MOBSF_APIKEY`.

---

## Architecture Notes

### scan_source()  Why It Exists
Earlier versions ran N separate `grep -rP` calls per module. On a 33k-file codebase each grep takes ~30s. `scan_source()` reads each file **once** in Python and applies all patterns simultaneously  total scan time for 33k files drops to ~30-60 seconds.

### Race-Free Parallel Shards
Each parallel module writes to its own PID-namespaced NDJSON shard file. No shared state, no locks. `merge_shards()` deduplicates and sorts by CVSS after all workers finish.

### Cache Validation
Cache must contain a decoded (non-binary) `AndroidManifest.xml` at apktool root level **and** at least one `.java` file. Stale/broken caches are automatically deleted. Use `--clear-cache` to force a fresh run.

### Manifest Safety
Always uses `-maxdepth 1` when searching for `AndroidManifest.xml` to find only the decoded root copy  never `apktool_out/original/AndroidManifest.xml` (binary AXML).

---

## Troubleshooting

### 0 findings on a large app
```bash
# Step 1: clear the cache
bash apkcheck.sh target.apk --clear-cache

# Step 2: confirm jadx produced output
find /tmp/android_audit_*/jadx_out -name "*.java" | wc -l
# Must be > 0

# Step 3: check jadx is executable (most common root cause)
jadx --version
# If "Permission denied":
sudo chmod +x /usr/local/bin/jadx ~/jadx/bin/jadx
```

### "jadx decompilation failed" but Java files exist
If JADX logs many decode errors, it can still output usable Java. In v2.3.2+ this is reported as partial coverage instead of hard failure.
```bash
cat /tmp/android_audit_*/parallel/jadx.log | tail -30
find /tmp/android_audit_*/jadx_out -name "*.java" | wc -l

# If count is 0, install fallback tools (dex2jar + CFR).
```

### Why this appears even with `--no-live`
`--no-live` disables external network/live checks only. It does **not** skip local decompilation (`apktool`/`jadx`), so JADX warnings/errors can still appear in terminal output.

### Check current decompiler state for a run
```bash
cat /tmp/android_audit_*/decomp_status.txt
cat /tmp/android_audit_*/decomp_java_count.txt
cat /tmp/android_audit_*/decomp_jadx_errors.txt
```

### Manifest appears binary / ICC skipped
```bash
cat /tmp/android_audit_*/parallel/apktool.log
# Must end with "apktool:ok"
# The script only uses the decoded XML at apktool_out/AndroidManifest.xml
```

### FlowDroid won't download (restricted network)
```bash
wget https://github.com/secure-software-engineering/FlowDroid/releases/download/v2.9/soot-infoflow-cmd-jar-with-dependencies.jar
mkdir -p ~/.android_audit/flowdroid
mv soot-infoflow-cmd-jar-with-dependencies.jar ~/.android_audit/flowdroid/soot-infoflow-cmd.jar
```

### WSL tips
```bash
# Copy report to Windows desktop
cp android_audit_*.html /mnt/c/Users/$USER/Desktop/

# Persistent Java 11
echo 'export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64' >> ~/.bashrc
echo 'export PATH=$JAVA_HOME/bin:$PATH' >> ~/.bashrc

# C:\Users\<you>\.wslconfig
[wsl2]
memory=8GB
processors=4
```

---

## Module Skip Names

```bash
apkid, metadata, manifest, secrets, crypto, webview, storage,
intents, smali, misc, rn, flutter, cordova, aidl,
contentprovider, backup, netconfig, native, firebase, semgrep,
mobsf, live, flowdroid, iccta, stringdeob, libcve, nativedeep
```

---

## Coverage

| Category | Status |
|----------|--------|
| Manifest misconfigurations |  |
| Hardcoded secrets (17 pattern classes + apkleaks + trufflehog) |  |
| Cryptographic weaknesses (14 patterns) |  |
| WebView vulnerabilities (11 patterns) |  |
| Insecure data storage (10 patterns) |  |
| Intent / IPC vulnerabilities (9 patterns) |  |
| Network security config + TrustManager |  |
| ICC cross-component chains (5 patterns) |  |
| Inter-procedural taint  FlowDroid (2824) |  |
| Native binary  checksec + nm + Ghidra |  |
| Third-party CVEs  OSV.dev |  |
| Obfuscated string deobfuscation (7 patterns) |  |
| Framework analysis  RN / Flutter / Cordova |  |
| Packer / protector detection  APKiD |  |
| OWASP Mobile Top 10  Semgrep |  |
| Runtime decryption (AES with runtime key) |  Requires Frida |
| Dynamic DEX loading (remote payload) |  Payload never on disk |
| Server-side / backend API testing |  Dynamic analysis |
| Xamarin / .NET IL analysis |  Not implemented |

---

## Version History

| Version | Changes |
|---------|---------|
| **v2.3.4** | Firebase live-check hardening: only confirms CRITICAL public-read when unauthenticated `/.json` returns real data; treats `Permission denied` and `database disabled` responses as non-vulnerable states. Also improves Firebase verification steps in reports. |
| **v2.3.3** | Added explicit `Steps to Verify` for each finding, auto-generated from evidence + finding type and propagated to HTML cards, JSON (`steps_to_verify`), Markdown, and SARIF rule help/properties for unambiguous manual validation, plus ARG_MAX-safe report generation that prevents large finding sets from breaking HTML/JSON/MD output. |
| **v2.3.2** | Decompiler reliability upgrade: explicit decompilation states (`OK/PARTIAL/PARTIAL_FALLBACK/FAILED`), partial-coverage handling when JADX emits errors but still outputs Java, automatic fallback path (`dex2jar + CFR`) when JADX yields zero Java files, decompilation telemetry files in `/tmp/android_audit_<ts>/`, metadata findings for decompiler health, and `--check-tools` optional fallback tooling visibility. |
| **v2.3.1** | Reliability + quality patch: unified shard-only `add_finding` path (race-safe), smart dedup merge (keeps strongest severity/confidence and merged evidence), diff-mode path fixes, CWE enrichment, SARIF file/line extraction from evidence, advanced whitelist matching (`Title`, `Category|Title`, `re:`). |
| **v2.3** | `scan_source()` single-pass scanner (fixes 0-findings on large apps); ICC analysis (5 patterns); obfuscated string deobfuscation (7 patterns); library CVE matching via OSV.dev; deep native analysis (checksec + nm + Ghidra); SARIF output; `--clear-cache` flag; cache validation with content checks; manifest binary guard (`-maxdepth 1`); apkleaks non-interactive fix; Python 3.13 regex fix; PATH auto-augmentation for subshells |
| v2.2 | FlowDroid inter-procedural taint (28 sources, 24 sinks) |
| v2.1 | Race condition fix (shard architecture); packer detection; React Native / Flutter / Cordova; MobSF integration |
| v2.0 | Initial release |
