# ESP8266 Wi-Fi Fingerprinter & Deauther

This project leverages the ESP8266 microcontroller to function as a Wi-Fi network analyzer and deauthentication tool. It allows for the sniffing of nearby Access Points (APs) and connected Stations (STAs), collecting detailed "fingerprints" of the network environment. Additionally, it provides the capability to perform deauthentication attacks on specified targets. The project includes an ESP8266 firmware component and a Python-based Command Line Interface (CLI) for interaction.

## Features

* **Wi-Fi Sniffing**: Discover and collect information about Access Points and connected Stations in the vicinity.
* **Network Fingerprinting**: Retrieve detailed data about detected Wi-Fi devices, including MAC addresses, SSIDs, RSSI, and channels.
* **Deauthentication Attacks**: Perform targeted deauthentication attacks on specific Wi-Fi devices (APs or STAs).
* **Python CLI**: Interact with the ESP8266 module via a user-friendly command-line interface.
* **Status Monitoring**: Check the current operational status (sniffing or deauthing) of the ESP8266.

## Hardware Requirements

* ESP8266 Development Board (e.g., NodeMCU, ESP-01S, ESP-12E/F)
* USB to Serial Converter (if your board doesn't have one built-in)

## Software Requirements

### For ESP8266 Firmware

* Arduino IDE
* ESP8266 Boards Manager installed in Arduino IDE
* Required libraries (ensure these are installed via Arduino Library Manager or manually):
    * `ESP8266WiFi`
    * `user_interface.h` (part of ESP8266 SDK)
    * Custom headers: `data_structures.h`, `sniffer.h`, `deauther.h`, `wifi_ieee_802_11_enums.h`

### For Python CLI

* Python 3.x
* `pyserial` library

## Setup and Installation

### 1. ESP8266 Firmware (Main Sketch)

1.  **Open in Arduino IDE**: Open your main sketch file (e.g., `ESP8266_Jammer.ino` or `main.ino`) located in the `main/` directory with the Arduino IDE.
2.  **Configure Board**: Go to `Tools > Board` and select your specific ESP8266 board (e.g., "NodeMCU 1.0 (ESP-12E Module)").
3.  **Set Port**: Select the correct serial port under `Tools > Port`.
4.  **Manage Libraries**: Ensure all necessary libraries (like `ESP8266WiFi`) are installed. For custom files in `include/` and `src/`, make sure your sketch is structured as follows:
    ```
    esp8266_deauther_ifingerprint/
    ├── cli/
    │   ├── esp_cli.py
    │   └── include
    |       ├── esp_protocol.py
    |       └── fingerprint_data.py
    └── main/
        ├── main.ino (or ESP8266_Jammer.ino)
        ├── include/
        │   ├── data_structures.h
        │   ├── deauther.h
        │   ├── sniff.h
        │   └── wifi_ieee_802_11_enums.h
        └── src/
            ├── deauther.cpp
            └── sniffer.cpp
    ```
    And ensure your `.ino` file includes headers from the `include/` directory like this:
    ```cpp
    #include "include/data_structures.h"
    #include "include/sniffer.h"
    #include "include/deauther.h"
    // ... other includes
    ```
5.  **Upload Firmware**: Compile and upload the sketch to your ESP8266 board.

### 2. Python CLI Client

1.  **Navigate to `cli` directory**: Open your terminal or command prompt and change your current directory to the `cli/` folder where `esp_cli.py` is located.
    ```bash
    cd /path/to/your/project/esp8266_deauther_ifingerprint/cli
    ```
2.  **Install `pyserial`**: If you don't have it, install the `pyserial` library using pip:
    ```bash
    pip install pyserial
    ```

## Usage

To start the interactive shell for controlling the ESP8266:

```bash
python esp_cli.py
