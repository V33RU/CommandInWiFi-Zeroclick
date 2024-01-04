#!/bin/bash

# Define the ESP32 port and MicroPython firmware URL
ESP32_PORT="/dev/ttyUSB0"  # Change this to the correct port
MICROPYTHON_URL="https://micropython.org/resources/firmware/esp32-idf4-20210202-v1.14.bin"  # URL of the MicroPython firmware

# Install esptool.py
echo "Installing esptool..."
pip install esptool

# Download the latest MicroPython firmware
echo "Downloading MicroPython firmware..."
wget $MICROPYTHON_URL -O micropython.bin

# Erase the current firmware
echo "Erasing current firmware..."
esptool.py --port $ESP32_PORT erase_flash

# Flash the MicroPython firmware
echo "Flashing MicroPython firmware..."
esptool.py --chip esp32 --port $ESP32_PORT write_flash -z 0x1000 micropython.bin

echo "MicroPython installation complete."
