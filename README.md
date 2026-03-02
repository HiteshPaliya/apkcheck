# Android Bug Bounty Static Analyzer

**Version 2.3 — Kali Linux WSL2 Edition**

A comprehensive static analysis tool for Android APKs designed for bug bounty hunters and penetration testers. Covers every major OWASP Mobile Top 10 vector, performs inter-procedural taint analysis via FlowDroid, and outputs navigable HTML, JSON, Markdown, and SARIF reports.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Usage](#usage)
4. [All Modules](#all-modules)
5. [FlowDroid Taint Analysis](#flowdroid-taint-analysis)
6. [Report Formats](#report-formats)
7. [Architecture — How It Works](#architecture--how-it-works)
8. [Environment Variables](#environment-variables)
9. [Tool Reference](#tool-reference)
10. [Findings Severity Guide](#findings-severity-guide)
11. [Version History](#version-history)
12. [Limitations & Known Issues](#limitations--known-issues)

---

## Quick Start

```bash
# Make executable
chmod +x apkcheck.sh

# Check all tools are installed
bash apkcheck.sh --check-tools

# Run full audit
bash apkcheck.sh target.apk

# Open the HTML report in Windows
cp android_audit_*.html /mnt/c/Users/$USER/Desktop/
```

---

## Installation

### Core Dependencies

```bash
# System tools
sudo apt update && sudo apt install -y \
    apktool \
    adb \
    default-jdk \
    openjdk-11-jdk \
    binutils \
    unzip \
    curl \
    file \
    jq \
    nodejs \
    npm

# Python tools
pip3 install apkleaks semgrep apkid

# trufflehog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /usr/local/bin

# jadx (Java decompiler)
wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.5.0.zip
unzip jadx-1.5.0.zip -d ~/jadx
sudo ln -sf ~/jadx/bin/jadx /usr/local/bin/jadx
```

### FlowDroid (Auto-downloaded)

FlowDroid is downloaded automatically on first run to `~/.android_audit/flowdroid/`. You need:

- **Java 8 or Java 11** (NOT Java 17+)
- At least **4 GB free RAM**

```bash
# Install Java 11 alongside your current JDK
sudo apt install openjdk-11-jdk

# Check available versions
update-java-alternatives --list

# Set Java 11 for the session before running
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
```

### MobSF (Optional)

```bash
# Run MobSF via Docker
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Then set your API key (found in MobSF → Settings → API Key)
export MOBSF_APIKEY=your_api_key_here
```

---

## Usage

### Basic Syntax

```
bash apkcheck.sh <apk> [options]
```

### All Modes

| Command | Description |
|---|---|
| `bash apkcheck.sh target.apk` | Full audit, all modules |
| `bash apkcheck.sh new.apk old.apk` | Diff two APK versions |
| `bash apkcheck.sh target.apk --resume` | Skip re-decompile (reuse cache) |
| `bash apkcheck.sh target.apk --skip modules:flowdroid,native` | Skip specific modules |
| `bash apkcheck.sh target.apk --whitelist known_ok.txt` | Suppress known findings |
| `bash apkcheck.sh target.apk --no-live` | Skip live network checks |
| `bash apkcheck.sh --check-tools` | Verify all tools are installed |

### Examples

```bash
# Fast run (skip all heavy modules)
bash apkcheck.sh target.apk --skip modules:flowdroid,iccta,nativedeep,libcve,semgrep

# Skip only FlowDroid and Ghidra, keep everything else
bash apkcheck.sh target.apk --skip modules:flowdroid,nativedeep

# Diff mode — see what changed between two versions
bash apkcheck.sh com.app.v2.apk com.app.v1.apk

# With MobSF integration enabled
export MOBSF_APIKEY=abc123
bash apkcheck.sh target.apk

# FlowDroid with more heap and longer timeout for a complex app
export FLOWDROID_HEAP=8g
export FLOWDROID_TIMEOUT=1800
bash apkcheck.sh large_app.apk

# Resume mode — reuse decompile output from a previous run
bash apkcheck.sh target.apk --resume

# Suppress findings you've already triaged
echo "No Certificate Pinning in NSC" >> whitelist.txt
bash apkcheck.sh target.apk --whitelist whitelist.txt
```

### Whitelist Format

One finding title per line. Matches are exact string-contains checks against the finding title.

```
# whitelist.txt
No Certificate Pinning in NSC
Missing HSTS Header: https://cdn.example.com
APKiD: ProGuard obfuscator detected (informational)
```

---

## All Modules

All modules run automatically unless skipped. The module name is used with `--skip modules:name`.

### Sequential (always first)

| Module | Name | Description |
|---|---|---|
| APKiD Packer Detection | `apkid` | Runs **first** — detects commercial packers (Jiagu, Bangcle, DexProtect). If a packer is found, all other modules warn their results may be incomplete. Also detects frameworks (RN, Flutter, Cordova) to activate downstream modules. |
| APK Metadata | `metadata` | Signing certificate (debug cert, key strength), minSdkVersion, targetSdkVersion. Populates MIN_SDK used for API-context on all findings. |
| AndroidManifest.xml | `manifest` | Exported activities/services/receivers/providers, debuggable, allowBackup, cleartext traffic, implicit exports, dangerous permissions, deep links, task hijacking. |

### Parallel Batch 1 — Source Analysis

| Module | Name | Description |
|---|---|---|
| Secrets | `secrets` | 19 regex patterns + apkleaks + trufflehog. AWS keys, Google API keys, JWTs, private keys, Stripe, Slack, Twilio, SendGrid, GitHub tokens, hardcoded passwords/secrets. |
| Cryptography | `crypto` | AES/ECB, DES/3DES, MD5/SHA-1, static IVs, hardcoded keys in SecretKeySpec, RSA without OAEP, empty TrustManagers, AllowAllHostnameVerifier. |
| WebView | `webview` | JavaScript enabled, addJavascriptInterface (RCE), file access, universal file access (UXSS), SSL error proceed, HTTP URLs in WebView, intent extras passed to loadUrl. |
| Data Storage | `storage` | World-readable files, external storage, sensitive data in logs, SharedPreferences leaks, clipboard leaks, hardcoded credentials. |
| Intent / IPC | `intents` | Mutable PendingIntents, sticky broadcasts, fragment injection, SQL injection via intent extras, path traversal via intent extras, WebView loading intent URLs. |
| Smali Analysis | `smali` | Bytecode-level analysis (obfuscation-resistant). Fires even when ProGuard/R8 fully renames classes. Covers all the same categories as Java analysis but at Dalvik bytecode level. |
| Miscellaneous | `misc` | SQL injection (rawQuery concatenation), Zip Slip, unsafe Java deserialization, StrictMode in production, missing FLAG_SECURE, tapjacking, SQL injection in content paths. |
| React Native | `rn` | JS bundle analysis — hardcoded secrets, disabled SSL, AsyncStorage leaks, eval(), console.log with sensitive data, HTTP endpoints. Hermes bytecode detection. |
| Flutter | `flutter` | Dart snapshot (libapp.so) strings analysis — secrets, SSL bypass, debug/profile mode artifacts, hardcoded endpoints. |
| Cordova / Ionic | `cordova` | config.xml wildcard allow-navigation/allow-intent/access-origin, JS/HTML source scanning, dangerous plugin audit (file, contacts, InAppBrowser), Cordova version CVE check. |

### Parallel Batch 2 — Deep Analysis

| Module | Name | Description |
|---|---|---|
| AIDL Interface | `aidl` | Finds all `extends Stub` AIDL implementations, checks each for missing `Binder.getCallingUid()` / `checkCallingPermission()`. |
| ContentProvider Tracer | `contentprovider` | Extracts `query()` method body from ContentProvider subclasses, checks if `selection` parameter flows into `rawQuery()` or string concat. Also checks `openFile()` for path traversal. |
| Backup Rules | `backup` | Parses `fullBackupContent` / `dataExtractionRules` XML, checks for missing `<exclude>` directives, cross-references against actual sensitive-named files in the APK. |
| Network Security Config | `netconfig` | Cleartext permitted, user CA trusted, no pin-set, debug-overrides, empty `checkServerTrusted()` in source. |
| Native Libraries | `native` | strings analysis of .so files — dangerous C functions (strcpy, gets, sprintf, system()), hardcoded secrets, HTTP URLs. ELF security mitigations: RELRO, BIND_NOW, debug symbols. |
| Firebase | `firebase` | Extracts Firebase config, tests DB public read (`/.json`), tests Storage bucket listing, tests API key scope (Maps, anonymous auth). |
| Semgrep | `semgrep` | Runs `p/owasp-top-ten`, `p/android`, and `p/secrets` rulesets on jadx source. Falls back to `--config auto`. |
| MobSF | `mobsf` | Uploads APK to local MobSF instance, triggers scan, merges manifest analysis + code analysis findings into unified report. |

### Sequential — Heavy Pass

| Module | Name | Description |
|---|---|---|
| FlowDroid | `flowdroid` | Inter-procedural taint analysis. Traces multi-hop data flows from sources (getIntent, URI params, SharedPrefs) to sinks (rawQuery, exec, loadUrl, Log.d, sendBroadcast). Auto-downloads JAR + android.jar platform stubs. |
| ICC / Cross-Component | `iccta` | Builds component call graph from manifest + jadx source. Detects: confused deputy attacks (unprotected exported component reaches protected one via Intent), data laundering across components, ContentResolver access from unprotected exported components, deep link chains, and PendingIntent theft risks. |
| String Deobfuscation | `stringdeob` | Statically executes 7 common obfuscation patterns without running the APK: Base64 decode, XOR byte-array decryption, hex string decoding, reversed strings, char-array reconstruction, split-join reassembly. Also scans smali bytecode for XOR const-push sequences. Recovered strings are re-scanned against all known secret patterns. |
| Library CVE Matching | `libcve` | Extracts library versions from gradle files, META-INF/MANIFEST.MF, .jar filenames in APK, and DEX strings. Queries the OSV.dev API for each dependency. Reports CVE ID, CVSS score, severity, and exact fixed version. Capped at 60 queries with rate limiting to avoid hammering the API. |
| Deep Native Analysis | `nativedeep` | Three-stage native analysis: (1) checksec — structured ELF mitigation audit (RELRO, NX, PIE, stack canary, FORTIFY, RPATH) for all .so files, auto-downloaded if not present. (2) nm-based dangerous function import analysis — detects strcpy/system/printf/dlopen imports, cross-references JNI bridge exposure, flags format string risks. (3) Ghidra headless CFG analysis (if installed) — full cross-reference analysis of dangerous function call sites with caller function names and addresses, JNI method size profiling. |

### Sequential — Network

| Module | Name | Description |
|---|---|---|
| Live Network Checks | `live` | Firebase DB public read, Firebase Storage bucket listing, Google API key scope tests, endpoint reachability + security header analysis (HSTS, Server disclosure). Disable with `--no-live`. |

---

## ICC Cross-Component Chain Analysis

Android apps communicate via Intents across components. A single exported unprotected component that sends Intents internally can act as a proxy into protected components — this is the **confused deputy** pattern and FlowDroid (single-component) completely misses it.

The ICC module builds a full call graph from the manifest (exported components, permissions, schemes) and jadx source (every `startActivity`, `startService`, `sendBroadcast`, `getContentResolver`, `setComponent`, `PendingIntent.get*` call). It then walks the graph looking for five specific dangerous patterns:

| Pattern | Severity | What it means |
|---|---|---|
| Confused deputy | HIGH | Unprotected exported A → startActivity → protected B |
| Data laundering | MEDIUM | Exported A forwards intent extras to another component without validation |
| ContentResolver from unprotected export | HIGH | Exported A reads from protected ContentProvider, leaking data back to caller |
| Deep link chain | HIGH | Deep link scheme → Activity → further component launches |
| PendingIntent theft | HIGH | Exported component creates mutable PendingIntent returnable to attacker |

---

## Obfuscated String Deobfuscation

Seven static deobfuscation patterns are applied to all Java/Kotlin source files and smali bytecode. No APK execution required.

| Pattern | Example in source | What we recover |
|---|---|---|
| `Base64.decode(...)` | `Base64.decode("QVdTX0tFWT0uLi4=", 0)` | `AWS_KEY=...` |
| XOR byte array | `new byte[]{0x41,0x13,...} ^ 0x42` | Plaintext secret |
| Hex string | `"41575354455354..."` | ASCII decoded value |
| StringBuilder.reverse() | `new StringBuilder("yekipa").reverse()` | `apikey` |
| char[] construction | `new char[]{65,87,83,75,69,89}` | `AWSKEY` |
| String.join reassembly | `String.join("","AK","IA","...")` | Full assembled secret |
| Smali XOR const-push | Sequence of `const/4` + `xor-int` | Decrypted bytes |

Every recovered string is immediately re-scanned against all known secret patterns (AWS key, Google API key, JWT, private key, etc.) so deobfuscated secrets automatically produce HIGH/CRITICAL findings.

---

## Library CVE Matching

Version extraction sources (in priority order):

1. **Gradle files** — `implementation "group:artifact:version"` in any `.gradle` / `.gradle.kts` file found in APK assets or jadx output
2. **META-INF/MANIFEST.MF** — `Bundle-SymbolicName`, `Bundle-Version`, `Implementation-Title`, `Implementation-Version` from every JAR manifest inside the APK
3. **JAR filenames** — `libs/okhttp-3.12.0.jar` → `okhttp:3.12.0`
4. **DEX binary strings** — Maven-style `group/artifact/version` paths embedded in bytecode

Each extracted dependency is queried against **OSV.dev** (`https://api.osv.dev/v1/query`) using the Maven ecosystem. OSV aggregates CVEs from NVD, GitHub Security Advisories, and ecosystem-specific databases. Each finding includes:

- CVE ID(s) and aliases (GHSA, PYSEC, etc.)
- CVSS score and severity
- Exact fixed version
- Direct link to OSV advisory
- Upgrade command for build.gradle

```bash
# Example finding:
# CRITICAL: CVE in okhttp v3.12.0: CVE-2023-3782 — improper certificate validation
# Fixed in: 4.11.0
# Remediation: implementation "com.squareup.okhttp3:okhttp:4.11.0"
```

---

## Deep Native Binary Analysis

Three layers, each independent — if a tool is missing, the others still run.

### Layer 1 — checksec (auto-downloaded)

Audits every `.so` file for 6 ELF security mitigations:

| Mitigation | Missing = Risk | Fix |
|---|---|---|
| RELRO | GOT overwrite attacks | `-Wl,-z,relro,-z,now` |
| Stack Canary | Stack overflows undetected | `-fstack-protector-strong` |
| NX | Stack/heap shellcode execution | `-Wl,-z,noexecstack` |
| PIE | Fixed-address ROP chains | `-fPIE -pie` |
| FORTIFY_SOURCE | libc overflow detection off | `-D_FORTIFY_SOURCE=2` |
| RPATH/RUNPATH | Library hijacking | `chrpath -d libname.so` |

### Layer 2 — nm dangerous function analysis

Uses `nm -D` (not just strings) to confirm which dangerous C functions are actually **imported** by each library. Strings produces false positives from comments and data; nm reports only what the dynamic linker will actually resolve.

For each confirmed import, also checks:
- Whether the library exports `JNI_OnLoad` / `Java_*` — meaning the dangerous function is reachable from Java code
- Whether the library imports printf-family functions with enough `%s`/`%d` patterns to suggest dynamic format strings

### Layer 3 — Ghidra headless CFG (optional)

If `analyzeHeadless` is in PATH (or `/opt/ghidra/`, `~/ghidra/`, `/usr/share/ghidra/`), runs a custom Java script against the primary `.so` that:

- Walks every xref to each dangerous function
- Reports caller function name and address for every call site
- Profiles all JNI-exported methods by instruction count (large = higher risk)
- Outputs structured `DANGEROUS_CALL|func|addr|caller` lines parsed into findings

```bash
# Install Ghidra:
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.1.2_build/ghidra_11.1.2_PUBLIC_20240709.zip
unzip ghidra_11.1.2_PUBLIC_20240709.zip -d /opt/ghidra
export PATH=$PATH:/opt/ghidra/support
```

---

FlowDroid is the most powerful module but also the most demanding. It performs **inter-procedural, context-sensitive, flow-sensitive taint analysis** — meaning it traces data across multiple method calls and class boundaries, across the Android lifecycle, and distinguishes which branch of an if-statement the tainted data flows through.

### What It Detects That Regex Cannot

Regex checks see one line at a time. FlowDroid sees the entire program. Example:

```java
// Activity.java
String userId = getIntent().getStringExtra("user");  // SOURCE
processUser(userId);

// DataUtils.java
void processUser(String input) {
    String cleaned = input.trim();
    DatabaseHelper.query(cleaned);  // passes through 2 methods
}

// DatabaseHelper.java
void query(String param) {
    db.rawQuery("SELECT * FROM users WHERE id=" + param, null);  // SINK
}
```

Regex cannot connect line 2 to line 11. FlowDroid does — and reports the complete call chain as evidence.

### Sources (What FlowDroid Tracks)

- Intent extras (`getStringExtra`, `getExtras`, `getData`)
- URI parameters (`getQueryParameter`, `getPath`, `getLastPathSegment`)
- SharedPreferences values
- ContentResolver query results
- Cursor data
- Clipboard content
- Telephony data (device ID, IMSI)
- Location data (latitude, longitude)
- File/stream reads
- System environment variables

### Sinks (Where FlowDroid Watches)

| Sink | Taint Flow Type Detected |
|---|---|
| `SQLiteDatabase.rawQuery()` | SQL Injection |
| `SQLiteDatabase.execSQL()` | SQL Injection |
| `Runtime.exec()` | OS Command Injection |
| `WebView.loadUrl()` | WebView URL Injection |
| `WebView.evaluateJavascript()` | WebView JS Injection |
| `Log.d/v/i/w/e()` | Sensitive Data Logging |
| `Context.sendBroadcast()` | Data Leak via Broadcast |
| `Intent.putExtra()` | Data Leak via Intent |
| `FileOutputStream.write()` | Insecure File Write |
| `SharedPreferences.Editor.putString()` | Insecure Preference Storage |
| `SmsManager.sendTextMessage()` | Data Leak via SMS |
| `okhttp3.Request.url()` | Data in Network Request |

### Tuning FlowDroid

```bash
# More heap for large apps
export FLOWDROID_HEAP=8g

# Longer timeout (default: 900s)
export FLOWDROID_TIMEOUT=1800

# Different Android platform API level for stubs
export FLOWDROID_PLATFORM_API=33

# Skip FlowDroid entirely for fast runs
bash android_static_audit_v2.2.sh target.apk --skip modules:flowdroid
```

### Java Version Requirement

FlowDroid uses Soot internals that are incompatible with Java 17+. You must have Java 8 or 11. The script auto-detects and tries to find a compatible Java in common paths. To install:

```bash
sudo apt install openjdk-11-jdk

# Check available JVMs
update-java-alternatives --list

# Temporarily use Java 11 for this session
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
export PATH=$JAVA_HOME/bin:$PATH
```

---

## Report Formats

Four report files are generated per scan, all named `android_audit_YYYYMMDD_HHMMSS.*`:

### HTML Report (`.html`)

The primary deliverable. Dark-themed, fully interactive:

- **Sidebar navigation** — filter by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO) or by category
- **Live search** — searches title, description, evidence, and remediation text simultaneously
- **Executive summary** — top 5 findings by CVSS score shown at the top
- **Diff section** — appears when two APKs are compared, shows new/fixed/persisting findings
- **Collapsible finding cards** — each card shows severity badge, confidence level, CVSS score, category, description, evidence, and remediation guidance
- **Expand All** button — opens all findings for printing or review
- **Total CVSS score** — aggregate risk score across all findings

```bash
# Open in browser from WSL
xdg-open android_audit_*.html

# Copy to Windows desktop
cp android_audit_*.html /mnt/c/Users/$USER/Desktop/
```

### JSON Report (`.json`)

Machine-readable structured output. Useful for piping into other tools, building CI/CD checks, or importing into Jira/Burp.

```json
{
  "meta": {
    "package": "com.example.app",
    "apk": "target.apk",
    "generated": "2025-01-15 14:32:10",
    "total": 47,
    "cvss_total": 284.5
  },
  "summary": {
    "CRITICAL": 3,
    "HIGH": 12,
    "MEDIUM": 18,
    "LOW": 8,
    "INFO": 6
  },
  "findings": [
    {
      "id": 1,
      "severity": "CRITICAL",
      "category": "FlowDroid / Taint Analysis",
      "title": "FlowDroid: SQL Injection via Taint Flow (MainActivity:47 → DatabaseHelper:23)",
      "description": "...",
      "evidence": "SOURCE: getStringExtra(\"query\")\n  in MainActivity.java:47\n\nSINK: rawQuery(\"SELECT...\" + param)\n  in DatabaseHelper.java:23\n\nTAINT PATH:\n  [MainActivity.java:47] ...",
      "confidence": "CONFIRMED",
      "cvss_score": 9.5,
      "remediation": "Use parameterized queries..."
    }
  ]
}
```

```bash
# Count critical findings with jq
jq '.summary.CRITICAL' android_audit_*.json

# Extract all HIGH+ findings titles
jq '.findings[] | select(.severity=="CRITICAL" or .severity=="HIGH") | .title' android_audit_*.json

# Get all FlowDroid findings
jq '.findings[] | select(.category | startswith("FlowDroid"))' android_audit_*.json
```

### Markdown Report (`.md`)

Human-readable text format for bug bounty write-ups, internal reports, or pasting into Notion/Confluence.

### SARIF Report (`.sarif`)

[SARIF 2.1.0](https://sarifweb.azurewebsites.net/) — the industry standard static analysis interchange format.

```bash
# Import into GitHub Code Scanning
# Upload via GitHub API or include in Actions workflow:
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: android_audit_*.sarif

# Import into Burp Suite Enterprise
# Dashboard → SAST → Import Results → SARIF
```

---

## Architecture — How It Works

### Execution Flow

```
main()
  ├── check_tools()          — verify 24 tools, show install commands
  ├── extract_apk()          — parallel: apktool + jadx + raw unzip (with cache)
  │
  ├── mod_apkid()            — sequential: packer detection FIRST
  ├── mod_metadata()         — sequential: populate MIN_SDK, pkg name
  ├── mod_manifest()         — sequential: populate exported_components.txt
  │
  ├── [PARALLEL BATCH 1]     — 10 modules run simultaneously
  │   ├── mod_secrets()      → shard_<PID>.ndjson
  │   ├── mod_crypto()       → shard_<PID>.ndjson
  │   ├── mod_webview()      → shard_<PID>.ndjson
  │   ├── mod_storage()      → shard_<PID>.ndjson
  │   ├── mod_intents()      → shard_<PID>.ndjson
  │   ├── mod_smali()        → shard_<PID>.ndjson
  │   ├── mod_misc()         → shard_<PID>.ndjson
  │   ├── mod_react_native() → shard_<PID>.ndjson
  │   ├── mod_flutter()      → shard_<PID>.ndjson
  │   └── mod_cordova()      → shard_<PID>.ndjson
  │   wait_parallel()
  │
  ├── [PARALLEL BATCH 2]     — 8 modules run simultaneously
  │   ├── mod_aidl()         → shard_<PID>.ndjson
  │   ├── mod_contentprovider() → shard_<PID>.ndjson
  │   ├── mod_backup()       → shard_<PID>.ndjson
  │   ├── mod_netconfig()    → shard_<PID>.ndjson
  │   ├── mod_native()       → shard_<PID>.ndjson
  │   ├── mod_firebase()     → shard_<PID>.ndjson
  │   ├── mod_semgrep()      → shard_semgrep.ndjson
  │   └── mod_mobsf()        → shard_mobsf.ndjson
  │   wait_parallel()
  │
  ├── mod_live_checks()      — sequential: network I/O
  ├── mod_flowdroid()        — sequential: FlowDroid taint analysis → shard_flowdroid.ndjson
  ├── mod_iccta()            — sequential: ICC cross-component graph → shard_iccta.ndjson
  │
  ├── [PARALLEL BATCH 3]     — 3 modules run simultaneously  ← v2.3
  │   ├── mod_stringdeob()   → shard_stringdeob.ndjson
  │   ├── mod_libcve()       → shard_libcve.ndjson  (OSV.dev API)
  │   └── mod_nativedeep()   → shard_nativedeep_checksec.ndjson
  │                             shard_nativedeep_func.ndjson
  │                             shard_ghidra.ndjson  (if Ghidra installed)
  │   wait_parallel()
  │
  ├── merge_shards()         — collect + deduplicate all shards → findings.json
  └── generate_report()      — HTML + JSON + Markdown + SARIF
```

### Race Condition Fix (v2.1)

Each parallel subshell writes to its own PID-namespaced NDJSON file (`/tmp/android_audit_*/shards/shard_<PID>.ndjson`). This means there are **zero concurrent writes to any shared file**. After all workers finish, `merge_shards()` reads all shard files sequentially, deduplicates by `title|category` hash, sorts by CVSS score, assigns sequential IDs, and writes the final `findings.json` atomically. No findings are lost regardless of how many modules run in parallel.

### Deduplication

Every call to `add_finding()` atomically creates a lock directory named after an MD5 hash of the finding's `title + category`. The `mkdir` syscall is atomic on Linux — if two processes race to create the same directory, exactly one wins and the other silently skips. This prevents the same finding from appearing twice even when multiple modules detect the same issue.

### Resume / Cache

Decompiled APK output is cached to `/tmp/android_audit_cache/<apk_md5>/`. On `--resume`, symlinks point to the cached directories, skipping the 2–5 minute decompilation step. The cache is keyed by APK content hash (MD5), so a different APK always triggers a fresh decompile.

### API-Level Context

`mod_metadata()` writes `MIN_SDK` and `TARGET_SDK` to files. The `api_context()` helper reads these and appends contextual notes to relevant findings, e.g.:

```
[API-context: exploitable on all supported API levels including minSdk=19]
[API-context: mitigated on API≥31 — but app supports API21+, so still relevant for older OS users]
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `FLOWDROID_HEAP` | `4g` | Java heap for FlowDroid. Increase for large/complex apps. |
| `FLOWDROID_TIMEOUT` | `900` | FlowDroid timeout in seconds. |
| `FLOWDROID_PLATFORM_API` | `29` | Android API level for platform stubs. |
| `MOBSF_URL` | `http://localhost:8000` | MobSF server URL. |
| `MOBSF_APIKEY` | _(empty)_ | MobSF API key. If empty, MobSF module is skipped. |
| `ANDROID_HOME` | _(unset)_ | Android SDK root. Used to find local `android.jar` stubs. |

---

## Tool Reference

| Tool | Purpose | Install |
|---|---|---|
| `apktool` | APK decode, smali output, resource decode | `sudo apt install apktool` |
| `jadx` | DEX → Java source decompilation | [GitHub Releases](https://github.com/skylot/jadx/releases) |
| `d2j-dex2jar` | DEX → JAR conversion | `sudo apt install dex2jar` |
| `adb` | Android Debug Bridge | `sudo apt install adb` |
| `java` (8 or 11) | FlowDroid runtime | `sudo apt install openjdk-11-jdk` |
| `aapt` | APK metadata extraction | `sudo apt install aapt` |
| `keytool` | Certificate analysis | Bundled with JDK |
| `strings` | Binary string extraction | `sudo apt install binutils` |
| `readelf` | ELF security mitigations | `sudo apt install binutils` |
| `nm` | Symbol table analysis | `sudo apt install binutils` |
| `apkleaks` | Secret pattern scanning | `pip3 install apkleaks` |
| `semgrep` | OWASP Mobile Top 10 rules | `pip3 install semgrep` |
| `trufflehog` | High-entropy secret detection | [Install script](https://github.com/trufflesecurity/trufflehog) |
| `apkid` | Packer/protector fingerprinting | `pip3 install apkid` |
| `node` | React Native bundle prettification | `sudo apt install nodejs` |
| `curl` | Live network checks | `sudo apt install curl` |
| `jq` | JSON processing | `sudo apt install jq` |
| MobSF | Full static + dynamic analysis platform | `docker run opensecurity/mobile-security-framework-mobsf` |
| FlowDroid | Inter-procedural taint analysis | Auto-downloaded by script |

---

## Findings Severity Guide

| Severity | CVSS Base | Meaning | Examples |
|---|---|---|---|
| **CRITICAL** | 9.0–10.0 | Direct exploitation, immediate impact | SQL injection via taint flow, Firebase DB public read, empty TrustManager, debug cert in prod, WebView JS interface with untrusted content |
| **HIGH** | 7.0–8.9 | Significant vulnerability, exploitable with moderate effort | Exported ContentProvider, cleartext traffic, hardcoded AWS key, AES/ECB, world-readable files, FlowDroid log sink, SSL error proceed |
| **MEDIUM** | 5.0–6.9 | Vulnerability with limited scope or requiring specific conditions | allowBackup=true, low targetSdkVersion, missing NSC, implicit exported components, mutable PendingIntent |
| **LOW** | 3.0–4.9 | Informational / defence-in-depth issue | No RELRO in .so, debug symbols present, lazy binding, missing HSTS header |
| **INFO** | 1.0–2.9 | Informational — requires context to evaluate | Deep link registered, dangerous permission declared, Firebase config extracted, ProGuard detected |

### Confidence Levels

| Level | CVSS Modifier | Meaning |
|---|---|---|
| **CONFIRMED** | ×1.0 | Pattern is unambiguous or live-tested (e.g. FlowDroid taint path, Firebase DB actually returned data, debug cert confirmed) |
| **LIKELY** | ×0.85 | Strong evidence in source but requires manual verification to confirm exploitability |
| **POSSIBLE** | ×0.65 | Pattern matched but context suggests it may be a false positive (e.g. matched in test code, or requires specific app flow) |

---

## Version History

### v2.3 (current)
- **NEW** `mod_iccta()` — ICC cross-component Intent chain analysis
  - Builds full component call graph from manifest + jadx source
  - Detects confused deputy attacks, data laundering, ContentResolver proxy leaks, deep link chains, PendingIntent theft
  - Writes directly to `shard_iccta.ndjson`
- **NEW** `mod_stringdeob()` — static obfuscated string deobfuscation
  - 7 deobfuscation patterns: Base64, XOR byte arrays, hex, reversed strings, char arrays, split-join, smali XOR const-push sequences
  - Recovered strings automatically re-scanned against all secret patterns
- **NEW** `mod_libcve()` — third-party library CVE matching
  - Extracts versions from gradle, META-INF/MANIFEST.MF, .jar filenames, DEX strings
  - Queries OSV.dev API per dependency (rate-limited, max 60 queries)
  - Reports CVE ID, CVSS, severity, fixed version, upgrade command
- **NEW** `mod_nativedeep()` — three-layer deep native analysis
  - Layer 1: checksec (auto-downloaded) — RELRO, NX, PIE, canary, FORTIFY, RPATH for all .so
  - Layer 2: nm-based dangerous function import detection (22 functions) with JNI bridge cross-referencing and format string risk detection
  - Layer 3: Ghidra headless CFG — call site xrefs, caller names, JNI method profiling (runs if Ghidra installed)
- Added v2.3 modules to parallel batch 3 in `run_all_modules()`
- Updated `--check-tools` output for new optional tools

### v2.2
- **NEW** `mod_flowdroid()` — inter-procedural taint analysis via FlowDroid 2.13
  - Auto-download FlowDroid JAR + Android platform stubs
  - Java 8/11 compatibility check with fallback path detection
  - 28 curated sources + 24 curated sinks covering OWASP Mobile Top 10
  - Full taint path parsing from FlowDroid XML output
  - Sink-to-severity + sink-to-remediation mapping
  - Timeout guard with partial results preservation
- FlowDroid added to tool checker (shows auto-download status)

### v2.1
- **FIX** Parallel race condition — per-subshell shard files, merged atomically
- **FIX** `add_finding()` no longer spawns Python per call (batched NDJSON append)
- **FIX** All `grep -rP` calls now include `--text` (was silently skipping binary-detected files)
- **NEW** `mod_apkid()` — packer/protector detection runs first
- **NEW** `mod_semgrep()` — OWASP Mobile Top 10 + Android + Secrets rulesets
- **NEW** `mod_react_native()` — JS bundle analysis (15 patterns, Hermes detection, endpoint extraction)
- **NEW** `mod_flutter()` — libapp.so + libflutter.so strings analysis
- **NEW** `mod_cordova()` — www/ JS/HTML analysis, config.xml audit, plugin audit
- **NEW** `mod_mobsf()` — fully implemented MobSF REST API integration
- **NEW** `api_context()` — API-level exploitability context on relevant findings
- **NEW** SARIF 2.1.0 output format
- **NEW** `merge_shards()` — atomic shard collection with global deduplication + sorting

### v2.0
- Parallel module execution (~60% faster)
- Timeout guards on all long-running tools
- Resume/cache mode
- Skip-modules flag
- Smali-level analysis (obfuscation-resistant)
- AIDL interface scanning
- ContentProvider SQL injection tracer
- Backup rules XML analysis
- CVSS-style risk scoring
- Remediation guidance per finding (25+ specific keys)
- Diff mode (compare two APK versions)
- Finding deduplication
- Confidence levels (CONFIRMED/LIKELY/POSSIBLE)
- Whitelist support
- Executive summary
- Live network checks (Firebase, API key scope, endpoints)
- JSON + Markdown export

### v1.0
- Initial release — 13 analysis modules
- apktool + jadx + smali decompilation
- Manifest analysis, secrets, crypto, WebView, data storage, intents, network config, native libs, Firebase, miscellaneous
- Single-threaded execution
- HTML report output

---

## Limitations & Known Issues

### Coverage — What's Still Missing

After v2.3 the tool covers every major static analysis vector. The remaining gaps all require dynamic analysis:

- **Runtime-decrypted secrets** — strings assembled via complex crypto (AES-CBC with runtime key, custom VM) cannot be statically recovered. Use Frida to hook `String` constructors or decryption functions at runtime.
- **Dynamic code loading** — `DexClassLoader` loading DEX from a remote URL or encrypted asset. APKiD warns when this is present; dynamic analysis is required to capture the loaded DEX.
- **Anti-tamper / root detection bypass** — out of scope for static analysis; use objection or Frida.
- **Server-side vulnerabilities** — this tool audits the APK, not the backend. API endpoints found are logged as INFO findings for manual follow-up.

### Static Analysis Limitations

**Packed APKs** — Commercial packers (Jiagu, Bangcle, DexProtect) load real DEX at runtime. APKiD detects these and fires a CRITICAL warning. Static results are partial. Use Frida or a memory dump tool to extract the real DEX.

**FlowDroid on large apps** — Very large apps (10,000+ classes) may hit the timeout or OOM. Use `--skip modules:flowdroid` for quick runs and increase `FLOWDROID_HEAP` / `FLOWDROID_TIMEOUT` for deep analysis.

**Ghidra headless timing** — Ghidra analysis on a large `.so` can take 5–15 minutes. It runs only on the largest non-system library. If it times out (10 min limit), the checksec and nm layers still ran.

**OSV.dev coverage** — OSV.dev covers Maven, PyPI, npm, Go, and others. Android-specific proprietary SDKs (some Xiaomi, Huawei, Samsung SDKs) may not be in OSV. The NVD fallback is not implemented (rate limits are strict); search NVD manually for any `INFO: No CVE` dependencies you're suspicious about.

**React Native Hermes bytecode** — When compiled to Hermes `.hbc`, the string scanner still runs but pattern coverage is reduced. Use `hermes-dec` externally.

**Flutter** — `libapp.so` contains Dart AOT native code. String extraction works; function-level analysis requires `blutter`.

### Known Issues

- The bash heredoc-inside-`$()` pattern triggers a benign bash parser warning (`1 unterminated here-document`) on some bash versions. Exit code is 0; this has no effect on execution.
- FlowDroid may report false positives for flows sanitized inside native code or via reflection. Verify manually.
- ICC confused deputy detection requires jadx to have decompiled the relevant classes. If jadx failed or timed out on specific classes, some chains may be missed.
- `mod_libcve()` caps at 60 OSV.dev queries to avoid rate limiting. If your app has more than 60 unique versioned dependencies, the remaining ones are skipped (a `SKIPPED_DEPS` count is logged).

---

## Contributing / Extending

### Adding a New Module

1. Define `mod_mymodule()` — each `add_finding()` call appends one NDJSON line to `${SHARD_DIR}/shard_$$.ndjson`
2. Add to `run_all_modules()` in the appropriate batch
3. Add to `check_tools()` if it needs a new tool
4. Document in README

### Adding New ICC Patterns

Edit the `ICC_PATTERNS` dict in `mod_iccta()` — keys are pattern labels, values are Python regex strings matching Java/Kotlin source.

### Adding New Deobfuscation Patterns

Add a new pattern block to the Python heredoc in `mod_stringdeob()`. Follow the existing pattern: extract candidate string → attempt decode → if decoded string matches `SECRET_RE` → emit finding.

### Adding New Sources/Sinks to FlowDroid

Edit the `SOURCESINKS` heredoc in `mod_flowdroid()`:
```
<fully.qualified.ClassName: returnType methodName(paramTypes)> -> _RETURN_|0|1|...
```

### Adding New CVE Data Sources

The `mod_libcve()` Python block queries OSV.dev. To add NVD or GHSA as additional sources, extend the `osv_query()` function with additional HTTP calls and merge the results into `vulns`.

---

*Built for bug bounty research on Kali Linux WSL2. Use responsibly and only against applications you have permission to test.*
