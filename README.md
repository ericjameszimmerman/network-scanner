# LLDP Network Scanner

A simple network scanner application that detects devices on the network by capturing LLDP (Link Layer Discovery Protocol) messages.

## Features

- Scans for LLDP messages on the network
- Displays detected devices with:
  - MAC address
  - IP address
  - Hostname (if available)
  - Status (Active/Inactive)
  - Last seen timestamp
- Real-time updates as devices are discovered
- Visual indication of device status (green for active, red for inactive)
- Detailed logging of scanner activity and errors

## Requirements

- Windows operating system
- Python 3.6+
- PySide6
- Scapy
- Npcap (for packet capture on Windows)

## Installation

1. Install Npcap from https://npcap.com/

   - During installation, make sure to select "Install Npcap in WinPcap API-compatible Mode"

2. Install the required Python packages:

```
pip install PySide6 scapy
```

3. Run the application as administrator:
   - Right-click on the command prompt or PowerShell and select "Run as administrator"
   - Navigate to the application directory
   - Run:
   ```
   python network_scanner.py
   ```

## Usage

1. Launch the application with administrator privileges
2. The scanner will automatically start capturing LLDP packets
3. Discovered devices will appear in the table
4. Use the "Refresh" button to manually update the device list
5. Use the "Start/Stop Scanning" button to control the scanning process
6. Check the log area at the bottom for status messages and errors

## Test Mode

For testing purposes, you can run the application in test mode, which simulates LLDP devices without requiring administrator privileges or network packet capture:

```
python network_scanner.py --test
```

Test mode options:

- `--test`: Enable test mode with simulated devices
- `--devices N`: Specify the number of simulated devices (default: 5)

Example:

```
python network_scanner.py --test --devices 10
```

In test mode:

- New simulated devices will be added periodically
- Some devices will randomly become inactive
- No actual network packet capture is performed
- Administrator privileges are not required

## How It Works

The application uses Scapy to capture LLDP packets on the network. LLDP is a vendor-neutral protocol used by network devices to advertise their identity, capabilities, and neighbors. The application parses these packets to extract information about the devices on the network.

LLDP packets are typically sent every 30 seconds by network devices. The application listens for these packets on all available network interfaces and extracts information such as:

- MAC address (unique identifier for the device)
- IP address (if available in the LLDP packet)
- Hostname (system name from the LLDP packet)

Devices are considered inactive if no LLDP packet has been received from them in the last 60 seconds

- The application scans all available network interfaces for LLDP packets.

## Troubleshooting

If no devices are detected:

1. **Administrator Privileges**: Ensure you're running the application as administrator
2. **Npcap Installation**: Verify Npcap is installed correctly
   - Try reinstalling Npcap with the "WinPcap API-compatible Mode" option
3. **Network Configuration**:
   - Ensure your network devices support and have LLDP enabled
   - Check that your network interface is properly configured
   - Verify no firewall is blocking LLDP packets (Ethernet type 0x88cc)
4. **Check the Log Area**:

   - The application logs errors and status messages in the log area
   - Look for specific error messages that might indicate the problem

5. **Common Issues**:
   - "Access is denied" errors indicate insufficient privileges
   - "No such device" errors may indicate issues with network interfaces
   - "Npcap/WinPcap not found" errors indicate Npcap installation issues

## About LLDP

Link Layer Discovery Protocol (LLDP) is an industry-standard protocol used by network devices to advertise their identity, capabilities, and neighbors on a local area network. It's commonly enabled on managed switches, routers, and other network infrastructure devices.

If you're not seeing any devices, it might be because LLDP is not enabled on your network equipment. Check your switch or router configuration to enable LLDP if possible.

## Troubleshooting

- If no devices are detected, ensure that:
  - You're running the application with administrator privileges
  - Your network devices support and have LLDP enabled
  - Your network interface is properly configured
  - No firewall is blocking the LLDP packets (Ethernet type 0x88cc)
- On Windows, you may need to install Npcap (https://npcap.com/) for Scapy to work properly
