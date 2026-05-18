<p align="center">
  <img src="CommandInWiFi-sticker.png" alt="CommandInWiFi" width="200"/>
</p>

<h1 align="center">CommandInWiFi</h1>
<p align="center"><strong>An SSID and BLE-name injection test tool for IoT security research</strong></p>

---

## Before you start

This project exists to explain how SSID-injection and BLE-name-injection payloads work, and to help you understand the bug class behind them. If your goal is just to test, you can skip the project entirely. Rename your phone hotspot to something like `|reboot|` or `$(reboot)`, run `hostapd` on a laptop with the SSID set to a payload, or rename your phone's Bluetooth name and watch what a target device does. That reproduces most of what this tool does. The rest is a curated catalog of payloads grouped by bug class, an ESP32 board that cycles through them on a schedule across either radio, and a small dashboard for tracking results across many runs.

Use it if you want to step through the categories or run a longer session. For a one-off check against your own gear, a phone is faster.

The dashboard has a Radio selector at the top: WiFi (SSID), Bluetooth LE (Name), or Both. ESP32 supports all three. ESP8266 supports WiFi only.

Read [ATTACK_MODEL.md](ATTACK_MODEL.md) first to see which payload classes actually fire on real targets and which CVEs are verified precedents.

If you have the firmware or binary for the target and want to look for these bugs statically instead of probing them live, see [Sidewinder](https://github.com/V33RU/sidewinder). It scans binaries and firmware for the same class of SSID-handling sinks that this tool probes from the air.

---

## Disclaimer

For authorized security testing and research only. Test only devices you own or have written permission to test.

---

## How to use it

You need an ESP32 or ESP8266 board (NodeMCU, DevKit, etc.), a USB cable, and Python 3.10 or newer.

Clone and install:

```bash
git clone https://github.com/V33RU/CommandInWiFi-Zeroclick.git
cd CommandInWiFi-Zeroclick

python3 -m venv .venv
source .venv/bin/activate
pip install -r dashboard/requirements.txt
```

Start the dashboard:

```bash
uvicorn dashboard.app:app --host 0.0.0.0 --port 8000
```

Open http://localhost:8000 in your browser.

Flash the firmware: plug the ESP in, open the Serial Monitor tab, pick your port and board type, click Flash Firmware.

Deploy payloads: go to the Payloads tab, select the ones you want, click Deploy Selected. The Serial Monitor tab will show device connect and disconnect events, plus any Quick Disconnect alerts as they happen.

---

## License

MIT, see [LICENSE](LICENSE).
