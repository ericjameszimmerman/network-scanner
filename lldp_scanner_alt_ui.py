from PySide6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
                                 QLabel, QPushButton, QTableWidget, QTableWidgetItem,
                                 QWidget, QHeaderView, QFrame, QSpacerItem, QSizePolicy)
from PySide6.QtCore import Qt
import sys
import datetime

class LLDPMonitor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LLDP Monitor")
        self.resize(1000, 650)

        self.setup_ui()

        self.fake_devices = [
            {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.1.101", "hostname": "printer"},
            {"mac": "01:23:45:67:89:AB", "ip": "N/A", "hostname": "switch-core"},
            {"mac": "00:11:22:33:44:55", "ip": "192.168.1.100", "hostname": "router1"},
        ]

        self.populate_devices()

    def setup_ui(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(30, 30, 30, 30)
        main_layout.setSpacing(20)

        title = QLabel("LLDP Monitor")
        title.setStyleSheet("font-size: 28px; font-weight: bold; color: #1e293b;")
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)

        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background-color: white;
                border: 1px solid #e5e7eb;
                border-radius: 12px;
            }
        """)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(20, 20, 20, 20)
        card_layout.setSpacing(15)

        header_layout = QHBoxLayout()
        header_title = QLabel("LLDP Detected Devices")
        header_title.setStyleSheet("font-size: 20px; font-weight: bold; color: #334155;")
        header_layout.addWidget(header_title)

        header_layout.addStretch()

        header_subtitle = QLabel("Devices discovered via LLDP packets on the network.")
        header_subtitle.setStyleSheet("""
            font-size: 14px;
            color: #64748b;
            padding: 6px 12px;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
        """)
        header_layout.addWidget(header_subtitle)

        card_layout.addLayout(header_layout)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Status", "MAC Address", "IP Address", "Hostname", "Last Seen"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)

        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)

        self.table.setStyleSheet("""
            QTableWidget {
                background-color: white;
                border: none;
                font-size: 14px;
            }
            QTableWidget::item {
                padding: 12px;
            }
            QTableWidget::item:selected {
                background-color: #e0f2fe;
                color: #0f172a;
            }
            QHeaderView::section {
                background-color: #f1f5f9;
                font-weight: bold;
                border: none;
                padding: 8px;
            }
        """)

        card_layout.addWidget(self.table)

        bottom_layout = QHBoxLayout()
        bottom_layout.addStretch()

        rescan_button = QPushButton("🔄 Rescan Network")
        rescan_button.setFixedHeight(40)
        rescan_button.setStyleSheet("""
            QPushButton {
                background-color: #3b82f6;
                color: white;
                padding: 8px 20px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2563eb;
            }
            QPushButton:pressed {
                background-color: #1d4ed8;
            }
        """)
        bottom_layout.addWidget(rescan_button)

        card_layout.addLayout(bottom_layout)

        main_layout.addWidget(card)

        self.setCentralWidget(main_widget)

    def populate_devices(self):
        self.table.setRowCount(0)
        for device in self.fake_devices:
            row = self.table.rowCount()
            self.table.insertRow(row)

            # Status badge
            badge = QLabel("Online")
            badge.setAlignment(Qt.AlignCenter)
            badge.setMinimumHeight(24)
            badge.setMinimumWidth(70)
            badge.setStyleSheet("""
                QLabel {
                    background-color: #3b82f6;
                    color: white;
                    padding: 4px 12px;
                    border-radius: 999px;
                    font-size: 12px;
                }
            """)
            self.table.setCellWidget(row, 0, badge)

            self.table.setItem(row, 1, QTableWidgetItem(device["mac"]))
            self.table.setItem(row, 2, QTableWidgetItem(device["ip"]))
            self.table.setItem(row, 3, QTableWidgetItem(device["hostname"]))
            self.table.setItem(row, 4, QTableWidgetItem(datetime.datetime.now().strftime("%H:%M:%S")))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LLDPMonitor()
    window.show()
    sys.exit(app.exec())
