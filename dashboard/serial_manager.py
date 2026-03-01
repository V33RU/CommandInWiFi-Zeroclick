from __future__ import annotations

import asyncio
import base64
import time
from pathlib import Path

import serial
import serial.tools.list_ports
from fastapi import WebSocket


CRASH_THRESHOLD = 10  # seconds — disconnect faster than this = likely crash
VULN_COOLDOWN = 30    # seconds — don't re-report same device within this window


class SerialManager:
    def __init__(self) -> None:
        self.port: str | None = None
        self.baud: int = 115200
        self.serial_conn: serial.Serial | None = None
        self.clients: set[WebSocket] = set()
        self._task: asyncio.Task | None = None
        self.deploy_status: str = "idle"  # idle, deploying, broadcasting, stopped
        self.deploy_count: int = 0
        # Device tracking
        self.current_ssid: str = ""
        self.last_ssid_change: float = 0.0
        self.devices: dict[str, dict] = {}  # mac -> {connected_at, ssid}
        self.device_events: list[dict] = []  # event log (last 200)
        # Vuln throttle: mac -> last_reported_time
        self._vuln_reported: dict[str, float] = {}

    def list_ports(self) -> list[dict]:
        return [
            {"device": p.device, "description": p.description, "hwid": p.hwid}
            for p in serial.tools.list_ports.comports()
        ]

    async def connect(self, port: str, baud: int = 115200) -> None:
        await self.stop()
        self.port = port
        self.baud = baud
        self.serial_conn = serial.Serial(port, baud, timeout=0.1)
        self._task = asyncio.create_task(self._read_loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        if self.serial_conn and self.serial_conn.is_open:
            self.serial_conn.close()
            self.serial_conn = None

    async def _read_loop(self) -> None:
        loop = asyncio.get_event_loop()
        while True:
            try:
                line = await loop.run_in_executor(None, self._read_line)
                if line:
                    self._parse_ciw_response(line)
                    await self._broadcast(line)
            except asyncio.CancelledError:
                break
            except serial.SerialException:
                await self._broadcast("[SERIAL ERROR] Connection lost")
                break

    def _parse_ciw_response(self, line: str) -> None:
        """Track deploy state and device events from ESP responses."""
        if line.startswith("CIW:OK:START:"):
            self.deploy_status = "broadcasting"
            try:
                self.deploy_count = int(line.split(":")[3])
            except (IndexError, ValueError):
                pass
        elif line == "CIW:OK:STOP":
            self.deploy_status = "stopped"
        elif line == "CIW:OK:CLEAR":
            self.deploy_status = "idle"
            self.deploy_count = 0
        elif line.startswith("CIW:STATUS:"):
            parts = line.split(":")
            if len(parts) >= 4:
                self.deploy_status = parts[2]
                try:
                    self.deploy_count = int(parts[3])
                except (IndexError, ValueError):
                    pass
        elif line.startswith("CIW:SSID:"):
            self.current_ssid = line[9:]
            self.last_ssid_change = time.time()
        elif line.startswith("CIW:STA_CONNECT:"):
            self._handle_device_connect(line[16:])
        elif line.startswith("CIW:STA_DISCONNECT:"):
            self._handle_device_disconnect(line[19:])

    @staticmethod
    def _parse_mac_ssid(data: str) -> tuple[str, str]:
        """Parse 'MAC|SSID' from firmware data.

        The firmware uses pipe (|) as separator between MAC and SSID
        because MACs contain colons.
        """
        idx = data.find("|")
        if idx > 0:
            return data[:idx], data[idx + 1:]
        # Fallback: no pipe found, treat entire string as MAC
        return data, ""

    def _handle_device_connect(self, data: str) -> None:
        """Track device connection."""
        mac, ssid = self._parse_mac_ssid(data)
        if not ssid:
            ssid = self.current_ssid
        now = time.time()

        self.devices[mac] = {"connected_at": now, "ssid": ssid}
        event = {
            "type": "connect", "mac": mac, "ssid": ssid, "time": now,
        }
        self._push_event(event)

    def _handle_device_disconnect(self, data: str) -> None:
        """Track device disconnection and detect vulnerability (time-based)."""
        mac, ssid = self._parse_mac_ssid(data)
        if not ssid:
            ssid = self.current_ssid
        now = time.time()

        duration = 0.0
        connect_ssid = ssid
        if mac in self.devices:
            duration = now - self.devices[mac]["connected_at"]
            connect_ssid = self.devices[mac]["ssid"]
            del self.devices[mac]

        # Ignore disconnects caused by SSID rotation (expected)
        if (now - self.last_ssid_change) < 5.0:
            return

        event: dict = {
            "type": "disconnect", "mac": mac, "ssid": connect_ssid,
            "time": now, "duration": round(duration, 1),
        }

        # Time-based vulnerability detection
        if duration > 0 and duration < CRASH_THRESHOLD:
            # Throttle: don't spam alerts for same device
            last_reported = self._vuln_reported.get(mac, 0)
            if (now - last_reported) > VULN_COOLDOWN:
                event["vuln"] = "crash"
                self._vuln_reported[mac] = now

        self._push_event(event)

    def _push_event(self, event: dict) -> None:
        """Add event to log, keeping last 200 entries."""
        self.device_events.append(event)
        if len(self.device_events) > 200:
            self.device_events = self.device_events[-200:]

    def _read_line(self) -> str | None:
        if self.serial_conn and self.serial_conn.is_open and self.serial_conn.in_waiting:
            raw = self.serial_conn.readline()
            return raw.decode("utf-8", errors="replace").strip()
        time.sleep(0.05)
        return None

    async def _broadcast(self, message: str) -> None:
        dead: set[WebSocket] = set()
        for ws in self.clients:
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)
        self.clients -= dead

    def register(self, ws: WebSocket) -> None:
        self.clients.add(ws)

    def unregister(self, ws: WebSocket) -> None:
        self.clients.discard(ws)

    def write(self, data: str) -> None:
        if self.serial_conn and self.serial_conn.is_open:
            self.serial_conn.write((data + "\n").encode())

    def send_command(self, cmd: str) -> None:
        """Send a CIW protocol command to the ESP."""
        self.write(cmd)

    async def push_payloads(self, payload_texts: list[str]) -> dict:
        """Deploy payloads to ESP via CIW serial protocol."""
        if not self.serial_conn or not self.serial_conn.is_open:
            return {"ok": False, "error": "Serial not connected. Connect to ESP first."}

        total = len(payload_texts)
        self.deploy_status = "deploying"
        self.deploy_count = total

        await self._broadcast(f"[DEPLOY] Starting deploy of {total} payload(s) to ESP...")

        self.send_command("CIW:CLEAR")
        await asyncio.sleep(0.15)

        for i, text in enumerate(payload_texts, 1):
            encoded = base64.b64encode(text.encode("utf-8", errors="replace")).decode("ascii")
            await self._broadcast(f"[DEPLOY] Sending payload {i}/{total}: {text}")
            self.send_command("CIW:ADD:" + encoded)
            await asyncio.sleep(0.05)

        self.send_command("CIW:START")
        await asyncio.sleep(0.15)

        self.deploy_status = "broadcasting"
        await self._broadcast(f"[DEPLOY] ESP broadcasting {total} payload(s)")

        return {"ok": True, "count": total}

    async def stop_esp(self) -> None:
        """Send stop command to ESP."""
        self.send_command("CIW:STOP")
        self.deploy_status = "stopped"
        await self._broadcast("[DEPLOY] ESP stopped")

    async def request_status(self) -> None:
        """Request status from ESP."""
        self.send_command("CIW:STATUS")

    async def flash_firmware(self, port: str, board: str = "esp32") -> dict:
        """Compile and flash CommandInWiFi firmware to ESP via PlatformIO."""
        project_root = Path(__file__).resolve().parent.parent

        env = "esp32" if board == "esp32" else "esp8266"

        if not (project_root / "platformio.ini").exists():
            return {"ok": False, "error": "platformio.ini not found in project root"}

        saved_port = self.port
        saved_baud = self.baud
        await self.stop()
        await self._broadcast("[FLASH] Disconnected serial for firmware upload")

        await self._broadcast(f"[FLASH] Compiling for {board}...")

        # Step 1: Compile
        try:
            proc = await asyncio.create_subprocess_exec(
                "pio", "run", "-e", env,
                cwd=str(project_root),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").rstrip()
                if text:
                    await self._broadcast(f"[FLASH] {text}")
            await proc.wait()

            if proc.returncode != 0:
                await self._broadcast("[FLASH] ERROR: Compilation failed!")
                return {"ok": False, "error": "Compilation failed"}

            await self._broadcast("[FLASH] Compilation successful!")
        except FileNotFoundError:
            await self._broadcast("[FLASH] ERROR: PlatformIO CLI (pio) not found. Install with: pip install platformio")
            return {"ok": False, "error": "PlatformIO not installed"}

        # Step 2: Flash
        await self._broadcast(f"[FLASH] Flashing {board} on {port}...")

        try:
            proc = await asyncio.create_subprocess_exec(
                "pio", "run", "-e", env, "-t", "upload",
                "--upload-port", port,
                cwd=str(project_root),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").rstrip()
                if text:
                    await self._broadcast(f"[FLASH] {text}")
            await proc.wait()

            if proc.returncode != 0:
                await self._broadcast("[FLASH] ERROR: Flash failed!")
                return {"ok": False, "error": "Flash failed"}

        except FileNotFoundError:
            await self._broadcast("[FLASH] ERROR: PlatformIO CLI not found")
            return {"ok": False, "error": "PlatformIO not installed"}

        await self._broadcast("[FLASH] Firmware flashed successfully! ESP rebooting...")

        # Step 3: Reconnect serial
        await asyncio.sleep(2)
        try:
            await self.connect(port, saved_baud or 115200)
            await self._broadcast("[FLASH] Serial reconnected.")
        except Exception as e:
            await self._broadcast(f"[FLASH] Could not reconnect serial: {e}")

        return {"ok": True}
