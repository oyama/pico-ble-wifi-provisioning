# BLE-based Wi-Fi provisioning demo for Raspberry Pi Pico W / Pico 2 W

This repository demonstrates how to configure Wi-Fi on a Raspberry Pi Pico W or Pico 2 W using BLE (Bluetooth Low Energy). You can use a generic BLE client (e.g., nRF Connect) on a smartphone or PC to send Wi-Fi SSID and password to the device, which will then connect to a wireless network.
Wi-Fi provisioning over BLE on Raspberry Pi Pico W / 2 W. Uses a simple GATT-based protocol with custom UUIDs, tested with nRF Connect.

## Features

- Receives Wi-Fi SSID and password via BLE and connects to Wi-Fi
- IP address is provided via BLE read and notify
- Reconnecting triggered by updated credentials
- Uses custom UUIDs, not a standardized GATT profile
- Rudimentary implementation for proof of concept

## Required Tools

- Generic BLE debugging software (e.g., [nRF Connect for Mobile](https://www.nordicsemi.com/Products/Development-tools/nRF-Connect-for-mobile) for iOS/Android)
- A BLE-capable smartphone or PC

## Build and Install

To compile and install this project, a setup with the [pico-sdk](https://github.com/raspberrypi/pico-sdk) is necessary. Please refer to [Getting Started with Raspberry Pi Pico](https://datasheets.raspberrypi.com/pico/getting-started-with-pico.pdf) to prepare your toolchain.

```bash
git clone https://github.com/oyama/pico-ble-wifi-provisioning.git
cd pico-ble-wifi-provisioning

mkdir build; cd build;
PICO_SDK_PATH=/path/to/pico-sdk cmake .. -DPICO_BOARD=pico_w
make
```
After successful compilation, the `ble-wifi-provisioning.uf2` binary will be produced. Simply drag and drop this file onto your Raspberry Pi Pico W while in BOOTSEL mode to install.
The device will begin advertising over BLE once powered up.
The firmware runs as a USB serial device. You can monitor the debug log using a serial terminal such as `minicom`, `screen`, or `PuTTY` (baud rate: 115200).

## How to Use via BLE

1. Open nRF Connect or similar app and scan for devices. Look for a name like `Pico 00:...` and connect.
2. In the GATT service list, locate the following characteristics:

| Characteristic Name | UUID                                   | Description                       |
|---------------------|----------------------------------------|-----------------------------------|
| SSID                | `BE3D7601-0EA0-4E96-82E0-89AA6A3DC19F` | Wi-Fi SSID (read/write)           |
| Password            | `BE3D7602-0EA0-4E96-82E0-89AA6A3DC19F` | Wi-Fi password (write only)       |
| IP Address          | `BE3D7603-0EA0-4E96-82E0-89AA6A3DC19F` | Acquired IP address (read/notify) |

3. Write the SSID, then the password. The device will attempt to connect to Wi-Fi.
4. Once connected, the assigned IP address can be read via BLE.
5. Onboard LED lights up when connected to Wi-Fi and assigned an IP address.

⚠️  nRF Connect should be sent and received in **UTF-8**.

<img src="https://github.com/user-attachments/assets/6f93441c-f8b3-4805-bc2c-b6a5e4bc41f8" width=300/>

<img src="https://github.com/user-attachments/assets/61f2fa72-e977-499d-b522-48bc87be769a" width=300/>

## License

This project is licensed under the 3-Clause BSD License. For details, see the [LICENSE](LICENSE.md) file.

## Contributions Welcome!

This project is experimental and under development. Ideas, feedback, issues, and pull requests are always welcome!
