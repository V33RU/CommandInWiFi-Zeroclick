/*
   Project Name: CommandInWiFi
   Description: This NodeMCU application cycles through a set of predefined SSIDs every 2 minutes, monitors connected devices (displaying their IP and MAC addresses), and logs SSID changes with timestamps.
*/

#include <ESP8266WiFi.h>
#include <ESP8266WiFiType.h>

// Array of predefined SSIDs
const char* ssids[] = {"|reboot|", "&reboot&", "`reboot`", "$reboot$"};
// Password for the AP
const char *password = "12345678"; // Consider using a more secure password in production
// Index to track the current SSID
unsigned int ssidIndex = 0;
// Total number of SSIDs
const int totalSSIDs = sizeof(ssids) / sizeof(ssids[0]);
// Track the last time the SSID was changed and devices were listed
unsigned long lastChangeMillis = 0;
unsigned long lastDeviceListMillis = 0;
// Interval for SSID change and device listing (2 minutes and 1 minute in milliseconds)
const long ssidChangeInterval = 2 * 60 * 1000; // 2 minutes
const long deviceListInterval = 60 * 1000; // 1 minute

void setup() {
  Serial.begin(115200);
  while (!Serial) { ; } // Wait for Serial to be ready
  Serial.println("Setup started...");
  
  changeSSID();
  Serial.println("Setup completed.");
}

void loop() {
  unsigned long currentMillis = millis();

  if (currentMillis - lastChangeMillis >= ssidChangeInterval) {
    lastChangeMillis = currentMillis;
    changeSSID();
  }

  if (currentMillis - lastDeviceListMillis >= deviceListInterval) {
    lastDeviceListMillis = currentMillis;
    listConnectedDevices();
  }
}

void changeSSID() {
  const char* newSSID = ssids[ssidIndex];
  WiFi.softAP(newSSID, password);

  Serial.println("-------------------------------------------------");
  Serial.print("SSID Changed: ");
  Serial.print(newSSID);
  Serial.print(" | Time: ");
  Serial.print(millis()/1000);
  Serial.println(" seconds");
  
  ssidIndex = (ssidIndex + 1) % totalSSIDs;
}

void listConnectedDevices() {
  Serial.println("-------------------------------------------------");
  Serial.println("Listing Connected Devices:");
  struct station_info *station_list = wifi_softap_get_station_info();
  
  if (station_list == NULL) {
    Serial.println("No devices connected.");
  }

  while (station_list != NULL) {
    Serial.print("Device - IP Address: ");
    Serial.print(IPAddress((&station_list->ip)->addr));
    Serial.print(", MAC Address: ");
    Serial.println(macToString(station_list->bssid));
    station_list = STAILQ_NEXT(station_list, next);
  }
  wifi_softap_free_station_info();
}

String macToString(const uint8_t* mac) {
  char buf[20];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}
