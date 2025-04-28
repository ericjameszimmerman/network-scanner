#!/usr/bin/env python3
import sys
import time
import datetime
import os
import traceback
import random
import argparse
from threading import Thread, Lock
import socket
import struct
from PySide6.QtWidgets import (QApplication, QMainWindow, QTableWidget, 
                              QTableWidgetItem, QVBoxLayout, QWidget, 
                              QPushButton, QHBoxLayout, QLabel, QMessageBox,
                              QStatusBar, QHeaderView, QDialog, QLineEdit,
                              QDialogButtonBox, QFormLayout, QMenu)
from PySide6.QtCore import Qt, QTimer, Signal, QObject
from PySide6.QtGui import QColor, QFont, QIcon

# Parse command line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description='LLDP Network Scanner')
    parser.add_argument('--test', action='store_true', help='Run in test mode with simulated devices')
    parser.add_argument('--devices', type=int, default=5, help='Number of simulated devices in test mode (default: 5)')
    return parser.parse_args()

# Global arguments
args = parse_arguments()
TEST_MODE = args.test
TEST_DEVICES_COUNT = args.devices

# Try to import scapy with error handling
try:
    from scapy.all import sniff, Ether, conf, get_if_list
    SCAPY_AVAILABLE = True
except ImportError as e:
    SCAPY_AVAILABLE = False
    SCAPY_ERROR = str(e)
    # In test mode, we don't need scapy
    if not TEST_MODE:
        print(f"Error importing Scapy: {e}")
        print("Please install Scapy: pip install scapy")
        print("Alternatively, run with --test flag to use test mode without Scapy")

# Device status constants
STATUS_ACTIVE = "Active"
STATUS_INACTIVE = "Inactive"

# LLDP Ethernet type
LLDP_ETHER_TYPE = 0x88cc

class LLDPScanner(QObject):
    """Class to handle LLDP packet scanning"""
    device_discovered = Signal(dict)
    scan_status = Signal(str)
    error_occurred = Signal(str)
    
    def __init__(self):
        super().__init__()
        self.devices = {}  # MAC address -> device info
        self.lock = Lock()
        self.running = False
        self.thread = None
        self.sniff_threads = []
        
        # If in test mode, we don't need to check for Scapy
        if TEST_MODE:
            self.scan_status.emit("Running in test mode with simulated devices")
            return
            
        # Check if scapy is available
        if not SCAPY_AVAILABLE:
            self.error_occurred.emit(f"Scapy is not available: {SCAPY_ERROR}")
            self.error_occurred.emit("Please install Scapy: pip install scapy")
            return
            
        # Get network interfaces
        self.interfaces = self._get_interfaces()
        if not self.interfaces:
            self.error_occurred.emit("No network interfaces found")
    
    def _get_interfaces(self):
        """Get list of network interfaces"""
        try:
            interfaces = get_if_list()
            if not interfaces:
                self.error_occurred.emit("No network interfaces detected")
                return []
                
            # Filter out loopback interfaces on Windows
            if sys.platform.startswith('win'):
                interfaces = [iface for iface in interfaces if not iface.startswith('lo')]
                
            return interfaces
        except Exception as e:
            error_msg = f"Error getting interfaces: {e}"
            self.error_occurred.emit(error_msg)
            self.error_occurred.emit(traceback.format_exc())
            return []
    
    def start_scanning(self):
        """Start the scanning thread"""
        if TEST_MODE:
            # In test mode, start generating fake devices
            self.running = True
            self.thread = Thread(target=self._test_mode_thread, daemon=True)
            self.thread.start()
            self.scan_status.emit(f"Test mode started - generating {TEST_DEVICES_COUNT} simulated devices")
            return
            
        if not SCAPY_AVAILABLE:
            self.error_occurred.emit("Cannot start scanning: Scapy is not available")
            return
            
        if not self.interfaces:
            self.error_occurred.emit("Cannot start scanning: No network interfaces available")
            return
            
        if self.thread is None or not self.thread.is_alive():
            self.running = True
            self.thread = Thread(target=self._scan_thread, daemon=True)
            self.thread.start()
            self.scan_status.emit("Scanning started")
    
    def stop_scanning(self):
        """Stop the scanning thread"""
        self.running = False
        
        # Wait for main thread to finish
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)
            
        # Clear any remaining sniff threads
        self.sniff_threads = []
        self.scan_status.emit("Scanning stopped")
    
    def _test_mode_thread(self):
        """Thread function to generate fake devices in test mode"""
        try:
            # Generate initial set of test devices
            self._generate_test_devices(TEST_DEVICES_COUNT)
            
            # Periodically update devices (add new ones, mark some as inactive)
            counter = 0
            while self.running:
                # Every 10 seconds, add a new device or mark one as inactive
                if counter % 10 == 0:
                    if random.random() < 0.7:  # 70% chance to add a new device
                        self._generate_test_devices(1)
                    else:  # 30% chance to mark a random device as inactive
                        self._mark_random_device_inactive()
                
                # Update device statuses
                self._update_device_status()
                
                # Sleep for 1 second
                time.sleep(1)
                counter += 1
                
        except Exception as e:
            error_msg = f"Error in test mode thread: {e}"
            self.error_occurred.emit(error_msg)
            self.error_occurred.emit(traceback.format_exc())
    
    def _generate_test_devices(self, count):
        """Generate fake devices for test mode"""
        for _ in range(count):
            # Generate a random MAC address
            mac = ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)])
            
            # Generate a random IP address
            ip = '.'.join([str(random.randint(1, 254)) for _ in range(4)])
            
            # Generate a random hostname
            device_types = ['Switch', 'Router', 'AP', 'Server', 'Printer', 'Camera']
            locations = ['Office', 'Lobby', 'Floor1', 'Floor2', 'DataCenter', 'Meeting']
            hostname = f"{random.choice(device_types)}-{random.choice(locations)}-{random.randint(1, 99)}"
            
            # Create device info
            device_info = {
                'mac_address': mac,
                'ip_address': ip,
                'hostname': hostname,
                'status': STATUS_ACTIVE,
                'last_seen': datetime.datetime.now()
            }
            
            # Add to devices dictionary
            with self.lock:
                self.devices[mac] = device_info
                self.device_discovered.emit(device_info)
                
            self.scan_status.emit(f"Test mode: Added device {hostname} ({mac})")
    
    def _mark_random_device_inactive(self):
        """Mark a random device as inactive in test mode"""
        with self.lock:
            if not self.devices:
                return
                
            # Select a random device
            mac = random.choice(list(self.devices.keys()))
            device = self.devices[mac]
            
            # Set last seen time to make it inactive
            device['last_seen'] = datetime.datetime.now() - datetime.timedelta(seconds=70)
            
            self.scan_status.emit(f"Test mode: Device {device['hostname']} ({mac}) will become inactive")
    
    def _scan_thread(self):
        """Thread function to scan for LLDP packets"""
        try:
            # Start packet sniffing
            self.scan_status.emit(f"Sniffing on interfaces: {', '.join(self.interfaces)}")
            
            # Use a separate thread for each interface
            self.sniff_threads = []
            for iface in self.interfaces:
                try:
                    t = Thread(target=self._sniff_interface, args=(iface,), daemon=True)
                    t.start()
                    self.sniff_threads.append(t)
                    self.scan_status.emit(f"Started sniffing on {iface}")
                except Exception as e:
                    error_msg = f"Error starting sniff on {iface}: {e}"
                    self.error_occurred.emit(error_msg)
            
            if not self.sniff_threads:
                self.error_occurred.emit("Failed to start sniffing on any interface")
                return
                
            # Monitor thread to check for inactive devices
            while self.running:
                self._update_device_status()
                time.sleep(1)
                
        except Exception as e:
            error_msg = f"Error in scan thread: {e}"
            self.error_occurred.emit(error_msg)
            self.error_occurred.emit(traceback.format_exc())
    
    def _sniff_interface(self, iface):
        """Sniff packets on a specific interface"""
        try:
            self.scan_status.emit(f"Starting sniff on {iface}")
            
            # Use scapy's sniff function to capture packets
            sniff(
                iface=iface,
                filter="ether proto 0x88cc",  # LLDP Ethernet type
                prn=self._process_packet,
                store=0,  # Don't store packets in memory
                stop_filter=lambda _: not self.running  # Stop when self.running is False
            )
        except Exception as e:
            error_msg = f"Error sniffing on {iface}: {e}"
            self.error_occurred.emit(error_msg)
            
            # On Windows, provide more specific error messages
            if sys.platform.startswith('win'):
                if "access is denied" in str(e).lower() or "permission" in str(e).lower():
                    self.error_occurred.emit("Access denied. Make sure you're running as administrator.")
                elif "npcap" in str(e).lower() or "winpcap" in str(e).lower():
                    self.error_occurred.emit("Npcap/WinPcap issue. Please install Npcap from https://npcap.com/")
    
    def _process_packet(self, packet):
        """Process a captured packet"""
        try:
            # Check if it's an LLDP packet
            if packet.haslayer(Ether) and packet[Ether].type == LLDP_ETHER_TYPE:
                # Extract source MAC address
                src_mac = packet[Ether].src
                
                # Parse LLDP TLVs
                device_info = self._parse_lldp_packet(packet)
                device_info['mac_address'] = src_mac
                device_info['last_seen'] = datetime.datetime.now()
                device_info['status'] = STATUS_ACTIVE
                
                with self.lock:
                    self.devices[src_mac] = device_info
                    self.device_discovered.emit(device_info)
                    
                self.scan_status.emit(f"Received LLDP packet from {src_mac}")
                
        except Exception as e:
            self.error_occurred.emit(f"Error processing packet: {e}")
    
    def _update_device_status(self):
        """Update status of devices based on last seen time"""
        now = datetime.datetime.now()
        with self.lock:
            for mac, device in self.devices.items():
                # Mark as inactive if not seen in the last 60 seconds
                if (now - device['last_seen']).total_seconds() > 60:
                    if device['status'] == STATUS_ACTIVE:
                        device['status'] = STATUS_INACTIVE
                        self.device_discovered.emit(device)
    
    def _parse_lldp_packet(self, packet):
        """Parse LLDP packet to extract device information"""
        device_info = {
            'hostname': 'Unknown',
            'ip_address': 'Unknown',
        }
        
        try:
            # Extract raw bytes from the packet
            raw_bytes = bytes(packet)
            
            # Skip Ethernet header (14 bytes) to get to LLDP data
            lldp_data = raw_bytes[14:]
            
            i = 0
            while i < len(lldp_data):
                # Check if we have at least 2 bytes for TLV header
                if i + 2 > len(lldp_data):
                    break
                    
                # LLDP TLV format: 7 bits type + 9 bits length, followed by value
                type_and_length = (lldp_data[i] << 8) | lldp_data[i+1]
                tlv_type = type_and_length >> 9
                length = type_and_length & 0x1FF
                
                # Check if we have enough bytes for the value
                if i + 2 + length > len(lldp_data):
                    break
                    
                # Extract value based on TLV type
                if tlv_type == 0:  # End of LLDPDU
                    break
                elif tlv_type == 5:  # System Name
                    try:
                        device_info['hostname'] = lldp_data[i+2:i+2+length].decode('utf-8', errors='ignore')
                    except:
                        pass
                elif tlv_type == 8:  # Management Address
                    try:
                        # This is a simplified parsing, actual implementation may vary
                        if length > 5:  # Ensure there's enough data
                            addr_len = lldp_data[i+2]
                            addr_subtype = lldp_data[i+3]
                            if addr_subtype == 1 and addr_len == 4:  # IPv4
                                ip_bytes = lldp_data[i+4:i+8]
                                device_info['ip_address'] = socket.inet_ntoa(ip_bytes)
                    except:
                        pass
                
                # Move to next TLV
                i += 2 + length
        except Exception as e:
            self.error_occurred.emit(f"Error parsing LLDP packet: {e}")
            
        return device_info
    
    def get_devices(self):
        """Get a copy of the current devices dictionary"""
        with self.lock:
            return self.devices.copy()


class IPAddressDialog(QDialog):
    """Dialog for entering an IP address"""
    def __init__(self, parent=None, current_ip="0.0.0.0"):
        super().__init__(parent)
        self.setWindowTitle("Set IP Address")
        self.resize(300, 150)
        
        # Create layout
        layout = QFormLayout(self)
        
        # IP address input
        self.ip_input = QLineEdit(current_ip)
        self.ip_input.setPlaceholderText("Enter IP address (e.g., 192.168.1.100)")
        layout.addRow("IP Address:", self.ip_input)
        
        # Subnet mask input
        self.subnet_input = QLineEdit("255.255.255.0")
        self.subnet_input.setPlaceholderText("Enter subnet mask (e.g., 255.255.255.0)")
        layout.addRow("Subnet Mask:", self.subnet_input)
        
        # Gateway input
        self.gateway_input = QLineEdit()
        self.gateway_input.setPlaceholderText("Enter gateway (e.g., 192.168.1.1)")
        layout.addRow("Gateway:", self.gateway_input)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addRow(button_box)
    
    def get_ip_address(self):
        """Get the entered IP address"""
        return self.ip_input.text()
    
    def get_subnet_mask(self):
        """Get the entered subnet mask"""
        return self.subnet_input.text()
    
    def get_gateway(self):
        """Get the entered gateway"""
        return self.gateway_input.text()


class NetworkScannerApp(QMainWindow):
    """Main application window"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LLDP Network Scanner")
        self.resize(800, 600)
        
        # Create UI
        self.setup_ui()
        
        # Create scanner
        self.scanner = LLDPScanner()
        self.scanner.device_discovered.connect(self.update_device_list)
        self.scanner.scan_status.connect(self.update_status)
        self.scanner.error_occurred.connect(self.handle_error)
        
        # Start scanning
        self.scanner.start_scanning()
        
        # Setup refresh timer
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_device_list)
        self.refresh_timer.start(5000)  # Refresh every 5 seconds
        
        # Show test mode indicator if in test mode
        if TEST_MODE:
            self.setWindowTitle(f"LLDP Network Scanner - TEST MODE ({TEST_DEVICES_COUNT} devices)")
            self.log_message(f"Running in TEST MODE with {TEST_DEVICES_COUNT} simulated devices")
    
    def setup_ui(self):
        """Set up the user interface"""
        # Main widget and layout
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        
        # Header
        header_layout = QHBoxLayout()
        title_label = QLabel("LLDP Network Scanner")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        header_layout.addWidget(title_label)
        
        # Test mode indicator
        if TEST_MODE:
            test_label = QLabel("TEST MODE")
            test_label.setStyleSheet("font-size: 14px; color: red; font-weight: bold;")
            header_layout.addWidget(test_label)
            
        header_layout.addStretch()
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.scan_button = QPushButton("Stop Scanning")
        self.scan_button.clicked.connect(self.toggle_scanning)
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh_device_list)
        button_layout.addWidget(self.scan_button)
        button_layout.addWidget(self.refresh_button)
        button_layout.addStretch()
        
        # Device table
        self.device_table = QTableWidget(0, 5)
        self.device_table.setHorizontalHeaderLabels([
            "MAC Address", "IP Address", "Hostname", "Status", "Last Seen"
        ])
        
        # Set column widths
        header = self.device_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # MAC
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # IP
        header.setSectionResizeMode(2, QHeaderView.Stretch)           # Hostname
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Status
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Last Seen
        
        self.device_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.device_table.setAlternatingRowColors(True)
        self.device_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.device_table.customContextMenuRequested.connect(self.show_context_menu)
        
        # Log area
        self.log_area = QTableWidget(0, 2)
        self.log_area.setHorizontalHeaderLabels(["Time", "Message"])
        self.log_area.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.log_area.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.log_area.setMaximumHeight(150)
        
        # Status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.status_label = QLabel("Ready")
        self.statusBar.addWidget(self.status_label)
        
        # Add widgets to main layout
        main_layout.addLayout(header_layout)
        main_layout.addLayout(button_layout)
        main_layout.addWidget(self.device_table)
        main_layout.addWidget(QLabel("Log Messages:"))
        main_layout.addWidget(self.log_area)
        
        self.setCentralWidget(main_widget)
    
    def toggle_scanning(self):
        """Toggle scanning on/off"""
        if self.scanner.running:
            self.scanner.stop_scanning()
            self.scan_button.setText("Start Scanning")
            self.update_status("Scanning stopped")
        else:
            self.scanner.start_scanning()
            self.scan_button.setText("Stop Scanning")
            self.update_status("Scanning for LLDP packets...")
    
    def update_status(self, message):
        """Update the status label with a message"""
        self.status_label.setText(message)
        self.log_message(message)
    
    def handle_error(self, error_message):
        """Handle error messages from the scanner"""
        self.log_message(f"ERROR: {error_message}")
        
        # Show critical errors in a message box
        if any(critical in error_message.lower() for critical in 
               ["administrator", "permission", "access denied", "npcap"]):
            QMessageBox.critical(self, "Error", error_message)
    
    def log_message(self, message):
        """Add a message to the log area"""
        now = datetime.datetime.now().strftime("%H:%M:%S")
        row = self.log_area.rowCount()
        self.log_area.insertRow(row)
        
        # Set time
        time_item = QTableWidgetItem(now)
        time_item.setFlags(time_item.flags() & ~Qt.ItemIsEditable)
        self.log_area.setItem(row, 0, time_item)
        
        # Set message
        msg_item = QTableWidgetItem(message)
        msg_item.setFlags(msg_item.flags() & ~Qt.ItemIsEditable)
        
        # Color code error messages
        if "error" in message.lower():
            msg_item.setForeground(QColor(255, 0, 0))  # Red for errors
        elif "test mode" in message.lower():
            msg_item.setForeground(QColor(0, 0, 255))  # Blue for test mode messages
        
        self.log_area.setItem(row, 1, msg_item)
        
        # Scroll to the bottom
        self.log_area.scrollToBottom()
    
    def update_device_list(self, device_info):
        """Update a single device in the table"""
        mac = device_info['mac_address']
        
        # Check if device already in table
        for row in range(self.device_table.rowCount()):
            if self.device_table.item(row, 0).text() == mac:
                # Update existing row
                self.device_table.item(row, 1).setText(device_info['ip_address'])
                self.device_table.item(row, 2).setText(device_info['hostname'])
                self.device_table.item(row, 3).setText(device_info['status'])
                self.device_table.item(row, 4).setText(
                    device_info['last_seen'].strftime('%Y-%m-%d %H:%M:%S')
                )
                
                # Update row color
                for col in range(5):
                    item = self.device_table.item(row, col)
                    if device_info['status'] == STATUS_ACTIVE:
                        item.setBackground(QColor(200, 255, 200))  # Light green
                    else:
                        item.setBackground(QColor(255, 200, 200))  # Light red
                        
                return
        
        # Add new row
        row = self.device_table.rowCount()
        self.device_table.insertRow(row)
        
        # Set data
        mac_item = QTableWidgetItem(mac)
        ip_item = QTableWidgetItem(device_info['ip_address'])
        hostname_item = QTableWidgetItem(device_info['hostname'])
        status_item = QTableWidgetItem(device_info['status'])
        last_seen_item = QTableWidgetItem(
            device_info['last_seen'].strftime('%Y-%m-%d %H:%M:%S')
        )
        
        # Make items non-editable
        for item in [mac_item, ip_item, hostname_item, status_item, last_seen_item]:
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            
            # Set background color based on status
            if device_info['status'] == STATUS_ACTIVE:
                item.setBackground(QColor(200, 255, 200))  # Light green
            else:
                item.setBackground(QColor(255, 200, 200))  # Light red
        
        # Add items to table
        self.device_table.setItem(row, 0, mac_item)
        self.device_table.setItem(row, 1, ip_item)
        self.device_table.setItem(row, 2, hostname_item)
        self.device_table.setItem(row, 3, status_item)
        self.device_table.setItem(row, 4, last_seen_item)
        
        # Log the new device
        self.log_message(f"New device detected: {mac} ({device_info['hostname']})")
    
    def refresh_device_list(self):
        """Refresh the entire device list"""
        devices = self.scanner.get_devices()
        
        # Update status label
        self.update_status(f"Found {len(devices)} devices. Last updated: {datetime.datetime.now().strftime('%H:%M:%S')}")
        
        # Refresh all devices in the table
        for device_info in devices.values():
            self.update_device_list(device_info)
    
    def show_context_menu(self, position):
        """Show context menu for the device table"""
        # Get the row under the cursor
        row = self.device_table.rowAt(position.y())
        if row < 0:
            return
            
        # Select the row
        self.device_table.selectRow(row)
        
        # Create context menu
        context_menu = QMenu(self)
        set_ip_action = context_menu.addAction("Set IP Address")
        
        # Show context menu at cursor position
        action = context_menu.exec_(self.device_table.mapToGlobal(position))
        
        if action == set_ip_action:
            # Get device info
            mac_address = self.device_table.item(row, 0).text()
            current_ip = self.device_table.item(row, 1).text()
            hostname = self.device_table.item(row, 2).text()
            
            # Show IP address dialog
            self.show_ip_dialog(mac_address, current_ip, hostname)
    
    def show_ip_dialog(self, mac_address, current_ip, hostname):
        """Show dialog for setting IP address"""
        dialog = IPAddressDialog(self, current_ip)
        if dialog.exec_():
            new_ip = dialog.get_ip_address()
            subnet_mask = dialog.get_subnet_mask()
            gateway = dialog.get_gateway()
            
            # Send DCP set request
            success = self.send_dcp_set_request(mac_address, new_ip, subnet_mask, gateway)
            
            if success:
                self.log_message(f"Set IP address for {hostname} ({mac_address}) to {new_ip}")
                
                # Update device in table
                for row in range(self.device_table.rowCount()):
                    if self.device_table.item(row, 0).text() == mac_address:
                        self.device_table.item(row, 1).setText(new_ip)
                        break
            else:
                self.log_message(f"Failed to set IP address for {hostname} ({mac_address})")
    
    def send_dcp_set_request(self, mac_address, ip_address, subnet_mask, gateway):
        """Send DCP set request to set IP address"""
        try:
            # In test mode, just simulate success
            if TEST_MODE:
                # Update the device in the scanner's device list
                with self.scanner.lock:
                    if mac_address in self.scanner.devices:
                        self.scanner.devices[mac_address]['ip_address'] = ip_address
                
                self.log_message(f"TEST MODE: Simulated DCP set request for {mac_address} to {ip_address}")
                return True
            
            # In real mode, we would send a DCP set request
            # This would typically involve using a library like scapy to send the request
            # For now, we'll just log that we would send the request
            self.log_message(f"Would send DCP set request for {mac_address} to {ip_address}")
            self.log_message("DCP set request implementation not available in this version")
            
            # Here's where you would implement the actual DCP set request
            # Example (pseudo-code):
            # if SCAPY_AVAILABLE:
            #     # Create DCP set request packet
            #     packet = Ether(dst=mac_address) / DCP(...)
            #     # Send packet
            #     sendp(packet, iface=self.scanner.interfaces[0])
            #     return True
            
            return False
            
        except Exception as e:
            self.log_message(f"Error sending DCP set request: {e}")
            return False
    
    def closeEvent(self, event):
        """Handle window close event"""
        self.scanner.stop_scanning()
        event.accept()


if __name__ == "__main__":
    # Start the application
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show the main window
    window = NetworkScannerApp()
    window.show()
    
    # Start the event loop
    sys.exit(app.exec())
    