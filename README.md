
<p align="center">
  <strong>CommandInWiFi</strong>
</p>

<p align="center">
  <img src="CommandInWiFi-sticker.png" alt="CommandInWiFi sticker" width="200"/>
</p>

<p align="center">
  <img src="poc/Command In Wi-Fi-1.png" alt="CommandInWiFi PoC" width="200"/>
</p>

<p align="center">
  <em>Investigating Command Injection Flaws in WiFi Access Point Storage</em><br/>
  Inspired by Zero-Click Attacks
</p>

---

## ⚠️ Disclaimer

> This project is under development.

- **Purpose**: Strictly for educational and research purposes only. Use ethically and legally.
- **IoT Pentesting Use Case**: Designed for IoT security professionals to evaluate device behavior under abnormal WiFi SSID input conditions.

---

## 📖 Description

This tool generates WiFi SSIDs based on user-defined payloads. Certain IoT devices and embedded systems mishandle SSID names by treating them as executable inputs or unsanitized strings during network discovery or storage. This leads to:

- Denial of Service (DoS)
- Remote Code Execution (RCE)
- Unexpected device reboots
- Unauthorized port access

The tool identifies if a device **reboots or crashes** when exposed to malicious SSIDs.

```text
Example Use:
- Inject payload into SSID
- Monitor device behavior (e.g., unexpected reboot, shell access, crash)
```

---

### ✅ Device Behavior Classification

| Status  | Description                                     |
|---------|-------------------------------------------------|
| SAFE    | Device ignores SSID payloads and behaves normally. |
| UNSAFE  | Device crashes or reboots upon seeing specific SSIDs. |

---

## 🧪 Target Devices Prone to Zero-Click Injection

| S.No | Device Description                                                               | Risk Level    |
|------|-----------------------------------------------------------------------------------|---------------|
| 1    | Devices auto-connecting to open SSIDs with no user interaction                   | Zero-Click    |
| 2    | Devices interpreting saved SSIDs as shell input during boot or network scanning  | Critical      |
| 3    | Devices with improper escaping of special characters in SSID                     | Low           |

---

## 🔬 Proof of Concept (PoC)

<p align="center">
  <img src="poc/ssid-changing.png" alt="SSID payload change">
</p>

<p align="center">
  <img src="poc/expecte-output.png" alt="Expected Output - Device reboot or crash">
</p>

---

## 📌 TODO List

- [ ] Develop full testing framework
- [ ] Auto-discover vulnerable IoT devices
- [ ] Write project documentation
- [ ] Add vulnerable firmware/source samples
- [ ] Maintain a payload injection list
- [ ] Build CLI-based SSID test tool
- [ ] Expand test modules:
  - [ ] OS Command Injection payloads
  - [ ] Bluetooth vulnerability tests
  - [ ] NFC fuzzing (planned)

---

## 🔗 Referral Links

- [Zero-Click Malware - Kaspersky](https://www.kaspersky.com/resource-center/definitions/what-is-zero-click-malware)
- [WiFiDemon - ZecOps](https://blog.zecops.com/research/meet-wifidemon-ios-wifi-rce-0-day-vulnerability-and-a-zero-click-vulnerability-that-was-silently-patched/)
- [Zero-Click Attacks - Check Point](https://www.checkpoint.com/cyber-hub/cyber-security/what-is-a-zero-click-attack/)
- [Apple Silent Patch - SecurityWeek](https://www.securityweek.com/researchers-apple-quietly-patched-0-click-wi-fi-code-execution-vulnerability-ios/)
- [Marvell Avastar Vulnerability](https://www.helpnetsecurity.com/2019/01/21/marvell-avastar-wi-fi-vulnerability/)
- [OS Command Injection - PortSwigger](https://portswigger.net/web-security/os-command-injection)
- [CVE-2023–45866 (Bluetooth Zero-Click)](https://github.com/marcnewlin/hi_my_name_is_keyboard)


