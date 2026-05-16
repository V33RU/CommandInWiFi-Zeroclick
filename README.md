<p align="center">
  <img src="CommandInWiFi-sticker.png" alt="CommandInWiFi" width="200"/>
</p>

<h1 align="center">CommandInWiFi</h1>
<p align="center"><strong>An SSID-injection test tool for IoT security research</strong></p>
<p align="center">
  <img src="https://img.shields.io/badge/ESP32-supported-green"/>
  <img src="https://img.shields.io/badge/ESP8266-supported-green"/>
  <img src="https://img.shields.io/badge/payloads-133-red"/>
  <img src="https://img.shields.io/badge/license-MIT-blue"/>
</p>

---

## Scope

A small research probe, not a pentesting framework. It calls `WiFi.softAP(ssid)` on an ESP32/ESP8266 with 133 crafted SSIDs and watches whether nearby devices crash on association. The mechanic is simple by design, there is no novel attack technique here.

It is useful for IoT researchers, bug hunters working unaudited firmware, educators, and anyone testing their own gear. It is probably not useful as a general pentest tool. Modern named-brand firmware mostly uses library APIs (`nmcli`, NetworkManager D-Bus, libiw) where SSID is passed as a parameter, so the SSID-to-shell class is rare. Real precedents exist (CVE-2023-45208 D-Link, CVE-2017-2915 Circle, CVE-2025-3328 Tenda, CVE-2023-42810 systeminformation, CVE-2021-30800 iOS WiFiDemon), but they cluster in specific segments: cheap consumer routers, CGI-script WiFi configs, older or custom firmware. On most targets the tool will flag nothing, which is the expected outcome.

The chip-firmware CVE class (Broadpwn, Marvell Avastar, MediaTek wappd, Windows WiFi driver, FreeBSD net80211, Realtek RTL8195A) is **out of scope**. Those need raw 802.11 frame injection with an attacker-controlled SSID IE length, which `WiFi.softAP()` does not produce. See [ATTACK_MODEL.md](ATTACK_MODEL.md) for the broader landscape.

The detector only signals association-time crashes: a quick disconnect under 10 seconds, confirmed by a second disconnect on the same SSID. Second-order classes (XSS, CRLF, NoSQL, JNDI, serialization, terminal escape, path) deliver the SSID into the air but the injection fires in a target-side component the detector cannot see. For those, the tool is delivery, verification is on you.

---

## Disclaimer

> **For authorized security testing and research only.**
> This tool is designed for IoT security professionals to evaluate device behavior under abnormal WiFi SSID input conditions. Use ethically, legally, and only on devices you own or have written authorization to test.

---

## Capabilities and Limits

What this tool actually delivers, stated plainly:

- **32-byte SSID cap.** Broadcasts use `WiFi.softAP()`, which enforces the IEEE 802.11 SSID length limit. Payloads longer than 32 bytes are not supported. Raw 802.11 frame injection via `esp_wifi_80211_tx()` is a future direction (see [ATTACK_MODEL.md](ATTACK_MODEL.md#future-work)), not implemented in the current firmware.
- **Most categories require target-side conditions beyond beacon receipt.** Command injection requires the target to feed the SSID to a shell on association. XSS / CRLF / path-traversal / NoSQL / JNDI categories deliver the string in a beacon, but the actual injection only fires when the target's web UI, config parser, or logger consumes the stored SSID through a vulnerable code path. These are real attack surfaces, they just aren't always triggered by broadcast alone. Payload categories are tiered below to reflect this.
- **Detector is heuristic, not ground truth, and narrow in scope.** A device disconnecting quickly from the AP may indicate a crash or may indicate normal behavior (open AP, no internet, captive-portal probe failed). The detector requires the same SSID to produce ≥2 quick disconnects within its broadcast window before raising a `Quick Disconnect` alert, and even then "save to results" is a human judgment call, not a confirmation of exploitation. **The detector only signals association-time crashes.** Second-order categories (XSS / CRLF / path / NoSQL / JNDI / serialization / terminal-escape) deliver the SSID but the actual injection happens elsewhere on the target, you must observe those on the target side (admin browser, target logs, web requests).
- **ESP32 and ESP8266 are not equivalent.** Both targets work; ESP32 has richer WiFi APIs and is preferred for future raw-frame work.
- **Chip-firmware-level CVEs (Broadpwn, Marvell Avastar, MediaTek wappd, Windows WiFi driver, etc.) are NOT reachable from this tool today.** They require raw frame manipulation with attacker-controlled IE length bytes. They are referenced in [ATTACK_MODEL.md](ATTACK_MODEL.md) for context only.

### Known Issues

- **11 payloads containing `\n` / `\r` (newline / CRLF) report a truncated SSID in the dashboard.** The firmware uses a line-based serial protocol (`CIW:SSID:<text>\n`), so an SSID that itself contains a newline splits the report across multiple lines and the dashboard records only the portion before the first newline. The 802.11 broadcast may itself be affected too, `WiFi.softAP()` accepts a C string and behavior with embedded `\n` is driver-defined. Affected categories: 2× `wifi_cmd`, 1× `wifi_overflow`, 1× `wifi_probe`, 2× `wifi_esc`, 1× `wifi_serial`, 4× `wifi_crlf`. A future fix would base64-encode the SSID in `CIW:SSID:` reports.
- **Payloads with embedded `\x00` (null byte) are truncated at the null by the WiFi driver** because `WiFi.softAP()` expects a C string. Affected: 10 payloads (2× `wifi_cmd`, 3× `wifi_overflow`, 2× `wifi_probe`, 3× `wifi_fuzz`). They still appear in the catalog because the truncated prefix is itself a useful fuzz input (e.g. `"reboot"` from `"reboot\x00ignored"` exercises a different code path than `"reboot"` alone), but the broadcast is shorter than the full string.

---
## Research Note


> The payload library includes RCE-class strings (e.g. `|reboot|`, `$(cmd)`, netcat bind shells) that would achieve command execution **if** the target firmware passes SSIDs to a shell unsanitized. These are standard penetration-testing primitives, not weaponized exploit chains.
>
> CommandInWiFi does **not** include device-specific exploits, confirmed 0-day payloads, or operational attack tooling. Its focus is behavioral detection: crash, reboot, and anomaly analysis through black-box observation.
>
> Detection does not equal exploitation. Confirming root cause requires separate target-side analysis (device logs, kernel debug, firmware reversing).
>
> As the project supports custom payloads, researchers may extend it independently for their authorized testing needs.
>
> Hunt beyond limits.

---

## Why "Zero-Click"?

Every WiFi-enabled device runs a background daemon (`wpa_supplicant`, `NetworkManager`, or a vendor-specific service) that **continuously scans for nearby networks and parses their SSID strings - without any user interaction**. No tap, no connect, no prompt. The SSID is read from the 802.11 beacon frame and processed automatically.

If the target firmware has a code flaw - passing the SSID string unsanitized to a shell call, `system()`, `popen()`, or a log pipeline - the SSID content **executes as a command**.
### Vulnerable Code Pattern (Target Side)

```c
// Common IoT firmware pattern - SSID reaches shell unsanitized
char cmd[128];
snprintf(cmd, sizeof(cmd), "iwconfig wlan0 essid %s", ssid);
system(cmd);   // If ssid = "|reboot|" → executes: iwconfig wlan0 essid |reboot|
```

```c
// Logging without format string protection
printf(ssid);  // If ssid = "%s%s%s%s" → crash via invalid memory read
```

```python
# Python-based IoT service
os.popen(f"nmcli dev wifi connect '{ssid}'")  # Shell metachar injection
```

### Detection Approach

This framework is designed for **black-box testing** - testing devices you don't have root, JTAG, or serial console access to. You can't attach a debugger to a smart doorbell or an off-the-shelf router.

What you CAN observe externally:
- **Behavioral signals**: device reboots, disconnects rapidly, or stops responding after exposure to a specific SSID
- **Timing analysis**: a device that connects and disconnects within seconds likely crashed processing the SSID
- **Correlation**: if SSID = `|reboot|` and the device reboots - that's not a coincidence, that's confirmed command execution

Once a triggering payload is identified, **target-side analysis** (device logs, kernel debug, firmware reverse engineering) is done separately as a second phase to determine root cause.

> **Deep dive:** See [ATTACK_MODEL.md](ATTACK_MODEL.md) for full technical analysis - 30+ real-world CVEs, vulnerable code patterns across every payload category, 802.11 beacon frame internals, and academic references.

---

## What It Does

CommandInWiFi broadcasts crafted WiFi SSIDs from an ESP32/ESP8266 to probe how nearby devices handle unusual SSID strings. **If** a target's firmware has a specific class of bug (and most targets won't), the SSID text may reach a vulnerable sink, shell call, format-string logger, web renderer, configuration parser. Possible target-side effects in that case include crashes, reboots, command execution, memory disclosure, configuration corruption, XSS, header injection, or downstream injection in stored-then-consumed pipelines. None of these are guaranteed; whether any of them happen depends entirely on the target. The tool's job is to deliver the SSID and to flag association-time crashes; everything else is operator-driven verification on the target.

The included **web dashboard** handles payload management, one-click firmware flashing, live serial monitoring, real-time device tracking, quick-disconnect alerting, and a results matrix for recording per-device-per-payload outcomes.

[![Watch the Demo](https://img.youtube.com/vi/XOZeVIV16Os/maxresdefault.jpg)](https://www.youtube.com/watch?v=XOZeVIV16Os)

<p align="center">
  <img src="poc/command.png" alt="CommandInWiFi PoC" width="600"/>
</p>


---

## Architecture (in one paragraph)

ESP32/ESP8266 firmware broadcasts SSIDs via `WiFi.softAP()`, cycling through a queue every two minutes, and reports station connect/disconnect events over USB serial using a line-based protocol (`CIW:...`). A FastAPI backend manages a SQLite-backed payload catalog, drives deployment, parses serial output, and exposes a WebSocket for live monitoring. A single-page browser dashboard handles payload selection, deployment, serial monitoring, and result recording. The detector runs entirely in the backend's serial parser and only signals quick disconnects with per-SSID confirmation (see [Vulnerability Detection](#vulnerability-detection) below). Source: [dashboard/](dashboard/), [CommandInWiFi.ino](CommandInWiFi.ino).

---

## Features

- **133 payloads** across 13 attack categories, tiered by delivery feasibility (pre-loaded)
- **Web Dashboard** - manage payloads, deploy to ESP, monitor serial, record results
- **One-Click Flash** - compile and flash firmware to ESP32/ESP8266 from the dashboard
- **Board Selection** - choose target board (ESP32 or ESP8266) before flashing
- **Real-Time Serial Monitor** - see CIW protocol messages, deploy progress, ESP output live
- **Real-Time Device Tracking** - see devices connecting/disconnecting from the malicious AP
- **Automated Vulnerability Detection** - time-based crash detection
  - Quick disconnect detection (device disconnects within 10 seconds of connecting)
  - False-positive filtering (SSID rotation disconnects excluded)
  - Per-device cooldown (30s) to prevent alert spam from crash-looping devices
- **Auto-Save Results** - detected vulnerabilities can be saved directly to the results database
- **Results Matrix** - track which payloads crash/reboot which devices
- **CIW Protocol** - custom serial protocol for remote payload deployment
- **Open AP** - SSIDs broadcast without password for maximum visibility
- **Cross-Platform Firmware** - single codebase supports both ESP32 and ESP8266

---

## Project Structure

```
CommandInWiFi-Zeroclick/
├── CommandInWiFi.ino          # ESP firmware (Arduino, ESP32 + ESP8266)
├── platformio.ini             # PlatformIO build config (both boards)
├── src/
│   └── CommandInWiFi.ino      # Symlink for PlatformIO build
├── code-python/
│   ├── micrypython-ciw.py     # MicroPython firmware (alternative)
│   └── install.sh             # MicroPython flash helper
├── dashboard/
│   ├── __init__.py
│   ├── app.py                 # FastAPI backend (REST + WebSocket)
│   ├── database.py            # SQLite schema + 133 default payloads
│   ├── serial_manager.py      # Serial I/O, deploy, flash, vuln detection
│   ├── requirements.txt       # Python dependencies
│   ├── templates/
│   │   └── index.html         # Dashboard HTML
│   └── static/
│       ├── app.js             # Dashboard frontend logic
│       └── style.css          # Dark theme styles
├── poc/                       # Proof-of-concept screenshots
├── LICENSE                    # MIT License
```

---

## Quick Start

### Requirements

- **Hardware**: ESP32 or ESP8266 board (NodeMCU, DevKit, etc.) + USB cable
- **Software**: Python 3.10+, pip

### 1. Clone and Setup

```bash
git clone https://github.com/V33RU/CommandInWiFi-Zeroclick.git
cd CommandInWiFi-Zeroclick

python3 -m venv .venv
source .venv/bin/activate       # Linux/macOS
# .venv\Scripts\activate        # Windows

pip install -r dashboard/requirements.txt
```

### 2. Start Dashboard

```bash
uvicorn dashboard.app:app --host 0.0.0.0 --port 8000
```

Open **http://localhost:8000** in your browser.

### 3. Flash Firmware (from Dashboard)

1. Plug in your ESP via USB
2. Go to **Serial Monitor** tab
3. Select your serial port (e.g. `/dev/ttyUSB0`)
4. Choose board type: **ESP32** or **ESP8266**
5. Click **Flash Firmware**
6. Watch compilation and flash progress in real-time

### 4. Deploy Payloads

1. Go to **Payloads** tab
2. Select payloads (click rows or use Select All)
3. Click **Deploy Selected**
4. Dashboard switches to Serial Monitor - watch the ESP receive and broadcast

### 5. Monitor and Detect Vulnerabilities

- **Serial Monitor** - see live ESP output (SSID changes, device events)
- **Connected Devices** panel - real-time list of devices on the malicious AP
- **Vulnerability Alerts** panel - automatic crash detection (quick disconnect < 10s)
- **Results Matrix** - record which payloads cause crashes/reboots on target devices

---

## Payload Categories

Payloads are grouped by how the injection actually fires, not by what they look like. This matters: a `<script>` payload broadcast in an SSID does nothing unless a target component renders it.

### Direct (beacon-deliverable)

The target processes the SSID during scan or scan-result logging. Bug fires before/without association.

| Category | Count | Description |
|---|---|---|
| `wifi_fmt` | 15 | Format string attacks (`%s`, `%n`, `%x`). Real precedent: CVE-2021-30800 (iOS `wifid`). |
| `wifi_probe` | 14 | Malformed SSIDs (null bytes, control chars, Unicode edge cases, WiFi Direct spoof). Generic parser fuzzing. |

### Association-required

The target associates with the AP and processes the SSID via a shell, logger, or config code. Most known SSID-CVEs sit here (CVE-2023-45208 D-Link, CVE-2017-2915 Circle).

| Category | Count | Description |
|---|---|---|
| `wifi_cmd` | 25 | Shell command injection via pipe, backtick, semicolon, subshell, IFS, BusyBox, PowerShell. Some targets fire at scan time, some at connect/config-store time. |
| `wifi_overflow` | 10 | 32-byte boundary fills and off-by-ones for fixed-size SSID buffers (>32-byte payloads removed, see Capabilities and Limits). |
| `wifi_enc` | 8 | Unicode fullwidth + URL-encoded shell metacharacters. Only fires if the target performs Unicode/URL normalization before shell exec, no documented WiFi CVE in this class; included as a defensive-research probe for filter bypasses. |
| `wifi_fuzz` | 8 | Byte-pattern fuzz inputs (debug-allocator markers, repeating bytes) for parser fault discovery. *Note: these are fuzz patterns, not exploit primitives, a 32-byte SSID broadcast cannot corrupt a target's heap on its own.* |

### Second-order (stored, then consumed by a different component)

Beacon delivers the SSID; the injection fires later, when a separate component on the target reads the stored value. Requires that second component to exist *and* to be reachable. **The automated `Quick Disconnect` detector does NOT signal these, they must be observed manually on the target side** (admin browser, target logs, etc.).

| Category | Count | Description | Required second component |
|---|---|---|---|
| `wifi_xss` | 8 | HTML / JS injection. | Web admin UI that renders scan results unsanitized (DD-WRT, BT Home Hub, Trendnet, TP-Link). |
| `wifi_serial` | 13 | JSON / XML / SQL / template / CSV / YAML / PHP injection. | Config storage or rendering code that re-parses stored SSIDs. |
| `wifi_esc` | 8 | ANSI escape injection. | A terminal viewer reading a log/syslog/serial stream that contains the SSID. |
| `wifi_path` | 6 | Directory traversal. | Firmware using SSID as a filesystem path component (rare). |
| `wifi_crlf` | 6 | HTTP header injection. | Web interface reflecting SSID into response headers. |
| `wifi_jndi` | 6 | Log4Shell / Spring EL. | Java-based logger ingesting SSIDs (rare on consumer IoT; relevant for enterprise APs). |
| `wifi_nosql` | 6 | MongoDB / LDAP filter injection. | Backend storing or querying SSIDs in NoSQL / LDAP (enterprise IoT). |

---

## CIW Serial Protocol

The dashboard communicates with the ESP via a line-based serial protocol:

### Commands (Dashboard -> ESP)

| Command | Description |
|---------|-------------|
| `CIW:CLEAR` | Clear payload queue |
| `CIW:ADD:<base64>` | Add payload (base64-encoded SSID) |
| `CIW:START` | Start broadcasting queued payloads |
| `CIW:STOP` | Stop broadcasting |
| `CIW:STATUS` | Request current status |

### Responses (ESP -> Dashboard)

| Response | Description |
|----------|-------------|
| `CIW:BOOT` | ESP has booted and is ready |
| `CIW:OK:CLEAR` | Queue cleared successfully |
| `CIW:OK:ADD:<index>` | Payload added at queue index |
| `CIW:OK:START:<count>` | Broadcasting started with N payloads |
| `CIW:OK:STOP` | Broadcasting stopped |
| `CIW:STATUS:<state>:<count>:<index>` | Current state, payload count, SSID index |
| `CIW:SSID:<ssid_text>` | Currently broadcasting this SSID |
| `CIW:STA_CONNECT:<mac>\|<ssid>` | Device connected to AP |
| `CIW:STA_DISCONNECT:<mac>\|<ssid>` | Device disconnected from AP |
| `CIW:DEVICE:<ip>\|<mac>` | Periodic device list entry |

---

## Vulnerability Detection

### How It Works

CommandInWiFi detects vulnerable devices using **time-based crash detection** (works on both ESP32 and ESP8266):

**1. Quick Disconnect Detection**

When a device connects to the malicious AP and disconnects within a short threshold (< 10 seconds), this suggests the device crashed while processing the SSID after connection.

```
Device connects -> Processes SSID -> Crashes -> Disconnects (< 10s)
                                                 ^^^ CRASH detected
```

**2. False Positive Filtering**

When the ESP rotates to a new SSID (via `WiFi.softAP()`), all connected stations are forcibly disconnected. These expected disconnects are filtered out by tracking SSID change timestamps and ignoring disconnects within a 5-second window.

**3. Per-Device Cooldown**

To prevent alert spam from devices stuck in a crash-reboot loop, a 30-second cooldown is applied per MAC address. The same device won't trigger duplicate alerts within this window.

---

## Dashboard API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/payloads` | List payloads (optional `?category=` filter) |
| `POST` | `/api/payloads` | Create payload |
| `PUT` | `/api/payloads/{id}` | Update payload |
| `DELETE` | `/api/payloads/{id}` | Delete payload |
| `GET` | `/api/results` | List all results (optional `?device_name=` filter) |
| `GET` | `/api/results/matrix` | Get device vs payload results matrix |
| `POST` | `/api/results` | Record test result |
| `GET` | `/api/serial/ports` | List available serial ports |
| `POST` | `/api/serial/connect` | Connect to serial port |
| `POST` | `/api/serial/disconnect` | Disconnect serial |
| `GET` | `/api/serial/status` | Get serial connection status |
| `POST` | `/api/deploy` | Deploy selected payloads to ESP |
| `POST` | `/api/deploy/stop` | Stop ESP broadcasting |
| `GET` | `/api/deploy/status` | Get deploy status |
| `GET` | `/api/devices` | Get connected devices and vuln events |
| `POST` | `/api/devices/save-result` | Auto-save detected vulnerability to results DB |
| `POST` | `/api/firmware/flash` | Compile and flash firmware (with board selection) |
| `WS` | `/ws/serial` | Real-time serial monitor WebSocket |

---

## MicroPython Alternative

For ESP32 boards running MicroPython instead of Arduino:

```bash
cd code-python
# Edit install.sh with your port
bash install.sh

# Then upload the script
ampy --port /dev/ttyUSB0 put micrypython-ciw.py main.py
```

The MicroPython version supports the same CIW protocol and works with the dashboard.

---

## Proof of Concept

<p align="center">
  <img src="poc/ssid-changing.png" alt="SSID Changing" width="500"/>
</p>
<p align="center"><em>ESP broadcasting crafted SSIDs - visible in WiFi scanner</em></p>

<p align="center">
  <img src="poc/expecte-output.png" alt="Expected Output" width="500"/>
</p>
<p align="center"><em>Target device crashes/reboots when exposed to malicious SSID</em></p>

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| No serial ports found | Check USB connection, install CP2102/CH340 drivers |
| Flash fails | Close Arduino IDE / other serial monitors (only one app can use the port) |
| ESP shows factory SSID | Flash the CommandInWiFi firmware first via Dashboard |
| `pio not found` error | Run `pip install platformio` in your venv |
| Permission denied on port | `sudo chmod 666 /dev/ttyUSB0` or add user to `dialout` group |
| Ubuntu can't find NodeMCU | `sudo apt remove brltty` (conflicts with USB serial) |
| False vuln alerts | Expected during SSID rotation. System filters disconnects within 5s of SSID change |

---

## References

- **[Attack Model - Full Technical Analysis](ATTACK_MODEL.md)** - 30+ CVEs, vulnerable code patterns, 802.11 internals, academic papers
- [WiFiDemon iOS 0-day - CVE-2021-30800 (Jamf)](https://www.jamf.com/blog/meet-wifidemon-ios-wifi-rce-0-day-vulnerability-and-a-zero-click-vulnerability-that-was-silently-patched/)
- [D-Link SSID Command Injection - CVE-2023-45208 (RedTeam Pentesting)](https://www.redteam-pentesting.de/en/advisories/rt-sa-2023-006/)
- [Marvell Avastar WiFi RCE - CVE-2019-6496 (CERT/CC)](https://www.kb.cert.org/vuls/id/730261/)
- [Broadpwn - CVE-2017-9417 (Exodus Intelligence)](https://blog.exodusintel.com/2017/07/26/broadpwn/)
- [Windows WiFi RCE - CVE-2024-30078 (CYFIRMA)](https://www.cyfirma.com/research/cve-2024-30078-remote-code-execution-vulnerability-analysis-and-exploitation/)
- [MediaTek Zero-Click - CVE-2024-20017 (SonicWall)](https://blog.sonicwall.com/en-us/2024/09/critical-exploit-in-mediatek-wi-fi-chipsets-zero-click-vulnerability-cve-2024-20017-threatens-routers-and-smartphones/)
- [wpa_supplicant P2P SSID Overflow - CVE-2015-1863 (w1.fi)](https://w1.fi/security/2015-1/wpa_supplicant-p2p-ssid-overflow.txt)
- [FreeBSD WiFi Heap Overflow - CVE-2022-23088 (ZDI)](https://www.thezdi.com/blog/2022/6/15/cve-2022-23088-exploiting-a-heap-overflow-in-the-freebsd-wi-fi-stack)
- [Over The Air: Exploiting Broadcom's WiFi Stack (Google Project Zero)](https://projectzero.google/2017/04/over-air-exploiting-broadcoms-wi-fi_4.html)
- [SSID Confusion - CVE-2023-52424 (Mathy Vanhoef)](https://papers.mathyvanhoef.com/wisec2024.pdf)
- [DD-WRT SSID Script Injection (WithSecure)](https://labs.withsecure.com/advisories/dd-wrt-ssid-script-injection-vulnerability)
- [OS Command Injection (PortSwigger)](https://portswigger.net/web-security/os-command-injection)
- [Zero-Click WiFi Attacks (Kaspersky)](https://www.kaspersky.com/resource-center/definitions/what-is-zero-click-malware)

---

## License

MIT License - see [LICENSE](LICENSE)
