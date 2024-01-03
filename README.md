<p align="center">
  <strong>CommandInWiFi</strong>
</p>

<p align="center">
  <img src="CommandInWiFi-sticker.png" alt="CommandInWiFi sticker" style="width:200px;"/>
</p>

<p align="center">
  Investigating Command Injection Flaws in WiFi Access Point Storage , This project inspired by zero-click attacks.
</p>


-------------------------------

### Description :
This code is designed to interact with Wi-Fi SSIDs stored on client devices. It is common knowledge that devices save Wi-Fi SSIDs internally, and understanding how they store and discover these SSID names is crucial. 

From my observations, some devices allow SSID names to be used as carriers for payloads. In scenarios where devices lack proper security, these payload-bearing SSIDs can be executed at the Linux level. The reaction of a device to specific payloads is key here. If a device interprets a payload as a command, it can range from causing Denial of Service (DoS) to enabling Remote Code Execution (RCE). This includes actions like opening ports for unauthorized access, which can significantly impact network-based IoT devices. 

My code specifically targets this vulnerability by forcing the device to reboot whenever it encounters an SSID that carries a predetermined payload. This approach demonstrates the potential impacts and risks associated with how devices handle SSID names. 

| Status | Condition                                                         |
|--------|-------------------------------------------------------------------|
| SAFE   | Device does not reboot and does not open ports unless necessary.  |
| UNSAFE | Device reboots when it finds an SSID or at user-selected intervals. |

------------------------------------
PoC:

![](poc/ssid-changing.png)

![](poc/expecte-output.png)

----------------------------------
### Installaion and Requirements 
#### 1. Hardware Setup
Ensure you have:
- A NodeMCU ESP8266 board.
- A USB cable for connection.
- A computer with Arduino IDE installed.

#### 2. Arduino IDE Setup
- **Install Arduino IDE**: Download from [Arduino website](https://www.arduino.cc/en/Main/Software).
- **Add ESP8266 Board**:
  - Open Arduino IDE.
  - Go to `File > Preferences`.
  - Add URL: `http://arduino.esp8266.com/stable/package_esp8266com_index.json`.
  - Install ESP8266 via `Tools > Board > Boards Manager`.
- **Select Your Board**:
  - `Tools > Board` and select "NodeMCU 1.0 (ESP-12E Module)".
- **Choose Correct Port**:
  - `Tools > Port` and select your NodeMCU's COM port.

#### 3. Loading the Code
- **Open New Sketch**:
  - `File > New` in Arduino IDE.
- **Copy-Paste Code**:
  - Copy provided NodeMCU code.
  - Paste into Arduino IDE sketch.

#### 4. Customizing the Code
- Modify SSID and password as needed.

#### 5. Uploading the Code
- **Compile and Upload**:
  - Click "Upload" in Arduino IDE.
  - Wait for completion message.

#### 6. Monitoring and Debugging
- **Open Serial Monitor**:
  - `Tools > Serial Monitor`.
  - Match baud rate with your code (commonly `115200`).

#### 7. Testing and Iteration
- **Test Functionality** and iterate as needed.

<p align="center">
  <img src="poc/flash.png" alt="flash" style="width:200px;"/>
</p>

#### 8. Safety and Legal Concerns
- **Handle with Care**: Disconnect power when adjusting connections.
- **Legal Compliance**: Ensure compliance with laws and regulations.

-----------------
#### Note for Ubuntu 22.04 Users: Ensuring NodeMCU Discovery

To ensure your laptop can discover the NodeMCU via USB in the Arduino IDE:
  
  **Remove Conflicting Packages**:
   - Ubuntu 22.04 may have `brltty` installed, which can interfere with USB recognition. Remove it using:
   `
   sudo apt remove brltty
   `
----------------------------------
#### Referral Links

- [What is Zero-Click Malware? - Kaspersky](https://www.kaspersky.com/resource-center/definitions/what-is-zero-click-malware)
- [Meet WiFiDemon: iOS WiFi RCE 0-Day Vulnerability - ZecOps Blog](https://blog.zecops.com/research/meet-wifidemon-ios-wifi-rce-0-day-vulnerability-and-a-zero-click-vulnerability-that-was-silently-patched/)
- [What is a Zero-Click Attack? - Check Point](https://www.checkpoint.com/cyber-hub/cyber-security/what-is-a-zero-click-attack/)
- [Apple Quietly Patched 0-Click Wi-Fi Code Execution Vulnerability - SecurityWeek](https://www.securityweek.com/researchers-apple-quietly-patched-0-click-wi-fi-code-execution-vulnerability-ios/)
- [Marvell Avastar Wi-Fi Vulnerability - Help Net Security](https://www.helpnetsecurity.com/2019/01/21/marvell-avastar-wi-fi-vulnerability/)
- [OS Command Injection - PortSwigger](https://portswigger.net/web-security/os-command-injection)

