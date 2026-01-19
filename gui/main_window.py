#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Main Window Module

This module contains the MainWindow class which is the primary GUI
for the PhishGuard application.
"""

import os
import logging
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QSystemTrayIcon, QMenu, QAction,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QStatusBar, QTabWidget, QTextEdit, QCheckBox, QGroupBox
)
from PyQt5.QtGui import QIcon, QFont, QColor, QPixmap
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtWidgets import QStyle

from gui.alert_dialog import AlertDialog

logger = logging.getLogger('PhishGuard.MainWindow')


class MainWindow(QMainWindow):
    """Main window for the PhishGuard application"""
    
    def __init__(self, browser_monitor, phishing_detector):
        """Initialize the main window
        
        Args:
            browser_monitor: An instance of BrowserMonitor
            phishing_detector: An instance of PhishingDetector
        """
        super().__init__()
        
        self.browser_monitor = browser_monitor
        self.phishing_detector = phishing_detector
        
        # Connect signals
        self.browser_monitor.url_detected.connect(self.on_url_detected)
        self.browser_monitor.phishing_detected.connect(self.on_phishing_detected)
        # Always receive analysis results with threat score
        if hasattr(self.browser_monitor, 'analysis_completed'):
            self.browser_monitor.analysis_completed.connect(self.on_analysis_completed)
        
        # Set up the UI
        self.setWindowTitle("PhishGuard")
        self.setMinimumSize(800, 600)
        
        # Set up the system tray icon
        self.setup_tray_icon()
        
        # Set up the central widget
        self.setup_central_widget()
        
        # Set up the status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("PhishGuard is running and monitoring your browsers")
        
        logger.info("MainWindow initialized")
    
    def setup_tray_icon(self):
        """Set up the system tray icon"""
        self.tray_icon = QSystemTrayIcon(self)
        icon_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                'resources', 'icon.svg')
        if os.path.exists(icon_path):
            self.tray_icon.setIcon(QIcon(icon_path))
        else:
            # Use a default icon if the custom icon is not found
            self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        
        # Create the tray menu
        tray_menu = QMenu()
        
        # Add actions to the tray menu
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)
        
        hide_action = QAction("Hide", self)
        hide_action.triggered.connect(self.hide)
        tray_menu.addAction(hide_action)
        
        tray_menu.addSeparator()
        
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.close)
        tray_menu.addAction(quit_action)
        
        # Set the tray menu
        self.tray_icon.setContextMenu(tray_menu)
        
        # Show the tray icon
        self.tray_icon.show()
        
        # Connect the tray icon activated signal
        self.tray_icon.activated.connect(self.on_tray_icon_activated)
    
    def setup_central_widget(self):
        """Set up the central widget"""
        # Create the central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create the main layout
        main_layout = QVBoxLayout(central_widget)
        
        # Create the header
        header_layout = QHBoxLayout()
        
        # Add the logo
        logo_label = QLabel()
        logo_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               'resources', 'logo.svg')
        if os.path.exists(logo_path):
            logo_pixmap = QPixmap(logo_path)
            logo_label.setPixmap(logo_pixmap.scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            # Use text if the logo is not found
            logo_label.setText("PhishGuard")
            logo_label.setFont(QFont("Arial", 24, QFont.Bold))
        
        header_layout.addWidget(logo_label)
        
        # Add the title
        title_label = QLabel("PhishGuard")
        title_label.setFont(QFont("Arial", 24, QFont.Bold))
        header_layout.addWidget(title_label)
        
        # Add spacer to push the status to the right
        header_layout.addStretch()
        
        # Add the status
        self.status_label = QLabel("Monitoring")
        self.status_label.setFont(QFont("Arial", 14))
        self.status_label.setStyleSheet("color: green;")
        header_layout.addWidget(self.status_label)
        
        main_layout.addLayout(header_layout)
        
        # Create the tab widget
        tab_widget = QTabWidget()
        
        # Create the dashboard tab
        dashboard_tab = QWidget()
        dashboard_layout = QVBoxLayout(dashboard_tab)
        
        # Add the current URL group
        current_url_group = QGroupBox("Current URL")
        current_url_layout = QVBoxLayout(current_url_group)
        
        url_refresh_layout = QHBoxLayout()
        
        self.current_url_label = QLabel("No URL detected yet")
        self.current_url_label.setFont(QFont("Arial", 12))
        self.current_url_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        url_refresh_layout.addWidget(self.current_url_label)
        
        # Add refresh button
        self.refresh_button = QPushButton()
        self.refresh_button.setIcon(self.style().standardIcon(QStyle.SP_BrowserReload))
        self.refresh_button.setToolTip("Refresh browser monitoring")
        self.refresh_button.clicked.connect(self.on_refresh_clicked)
        self.refresh_button.setFixedSize(30, 30)
        url_refresh_layout.addWidget(self.refresh_button)
        
        current_url_layout.addLayout(url_refresh_layout)

        # Current threat score label
        self.current_threat_label = QLabel("Threat score: N/A")
        self.current_threat_label.setFont(QFont("Arial", 11))
        self.current_threat_label.setStyleSheet("color: #888;")
        current_url_layout.addWidget(self.current_threat_label)
        
        dashboard_layout.addWidget(current_url_group)
        
        # Add the recent alerts group
        recent_alerts_group = QGroupBox("Recent Alerts")
        recent_alerts_layout = QVBoxLayout(recent_alerts_group)
        
        self.alerts_table = QTableWidget(0, 3)
        self.alerts_table.setHorizontalHeaderLabels(["URL", "Threat Score", "Time"])
        self.alerts_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.alerts_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.alerts_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        recent_alerts_layout.addWidget(self.alerts_table)
        
        dashboard_layout.addWidget(recent_alerts_group)
        
        # Add the dashboard tab to the tab widget
        tab_widget.addTab(dashboard_tab, "Dashboard")
        
        # Create the settings tab
        settings_tab = QWidget()
        settings_layout = QVBoxLayout(settings_tab)
        
        # Add the general settings group
        general_settings_group = QGroupBox("General Settings")
        general_settings_layout = QVBoxLayout(general_settings_group)
        
        # Add the start on boot checkbox
        start_on_boot_checkbox = QCheckBox("Start on system boot")
        start_on_boot_checkbox.setChecked(True)
        general_settings_layout.addWidget(start_on_boot_checkbox)
        
        # Add the minimize to tray checkbox
        minimize_to_tray_checkbox = QCheckBox("Minimize to tray when closed")
        minimize_to_tray_checkbox.setChecked(True)
        general_settings_layout.addWidget(minimize_to_tray_checkbox)
        
        # Add the show notifications checkbox
        show_notifications_checkbox = QCheckBox("Show notifications")
        show_notifications_checkbox.setChecked(True)
        general_settings_layout.addWidget(show_notifications_checkbox)
        
        settings_layout.addWidget(general_settings_group)
        
        # Add the alert settings group
        alert_settings_group = QGroupBox("Alert Settings")
        alert_settings_layout = QVBoxLayout(alert_settings_group)
        
        # Add the alert threshold checkbox
        alert_threshold_checkbox = QCheckBox("Alert on medium threat (score > 40)")
        alert_threshold_checkbox.setChecked(False)
        alert_settings_layout.addWidget(alert_threshold_checkbox)
        
        # Add the block phishing sites checkbox
        block_phishing_checkbox = QCheckBox("Block access to detected phishing sites")
        block_phishing_checkbox.setChecked(True)
        alert_settings_layout.addWidget(block_phishing_checkbox)
        
        settings_layout.addWidget(alert_settings_group)
        
        # Add spacer to push the buttons to the bottom
        settings_layout.addStretch()
        
        # Add the buttons layout
        buttons_layout = QHBoxLayout()
        
        # Add the save button
        save_button = QPushButton("Save Settings")
        save_button.clicked.connect(self.on_save_settings)
        buttons_layout.addWidget(save_button)
        
        # Add the reset button
        reset_button = QPushButton("Reset to Defaults")
        reset_button.clicked.connect(self.on_reset_settings)
        buttons_layout.addWidget(reset_button)
        
        settings_layout.addLayout(buttons_layout)
        
        # Add the settings tab to the tab widget
        tab_widget.addTab(settings_tab, "Settings")
        
        # Create the about tab
        about_tab = QWidget()
        about_layout = QVBoxLayout(about_tab)
        
        # Add the about text
        about_text = QTextEdit()
        about_text.setReadOnly(True)
        about_text.setHtml("""
        <h1>PhishGuard</h1>
        <p>PhishGuard is a Windows application that helps protect you from phishing websites.</p>
        <p>It monitors your web browsers and alerts you when it detects a potential phishing site.</p>
        <h2>Features</h2>
        <ul>
            <li>Real-time browser monitoring</li>
            <li>Advanced phishing detection</li>
            <li>Customizable alert settings</li>
            <li>System tray integration</li>
        </ul>
        <h2>Version</h2>
        <p>1.0.0</p>
        <h2>Contact</h2>
        <p>For support or feedback, please contact us at support@phishguard.example.com</p>
        """)
        about_layout.addWidget(about_text)
        
        # Add the about tab to the tab widget
        tab_widget.addTab(about_tab, "About")
        
        main_layout.addWidget(tab_widget)
    
    def on_url_detected(self, url):
        """Handle URL detected event
        
        Args:
            url (str): The detected URL
        """
        logger.info(f"URL detected: {url}")
        self.current_url_label.setText(url)
        self.statusBar.showMessage(f"Monitoring: {url}")
    
    def on_analysis_completed(self, result):
        """Update current threat score for the detected URL."""
        try:
            score = int(result.get('threat_score', 0))
        except Exception:
            score = 0
        # Color by severity
        if score >= 80:
            color = 'red'
        elif score >= 60:
            color = 'orange'
        elif score >= 40:
            color = 'yellow'
        else:
            color = 'green'
        self.current_threat_label.setText(f"Threat score: {score}/100")
        self.current_threat_label.setStyleSheet(f"color: {color};")
        # Keep status bar informative
        self.statusBar.showMessage(f"Monitoring: {result.get('url', '')} | Score: {score}")

    def on_phishing_detected(self, result):
        """Handle phishing detected event
        
        Args:
            result (dict): The phishing analysis result
        """
        logger.warning(f"Phishing detected: {result['url']}")
        
        # Add to the alerts table
        row_position = self.alerts_table.rowCount()
        self.alerts_table.insertRow(row_position)
        
        # Add the URL
        url_item = QTableWidgetItem(result['url'])
        self.alerts_table.setItem(row_position, 0, url_item)
        
        # Add the threat score
        threat_score_item = QTableWidgetItem(str(result['threat_score']))
        if result['threat_score'] >= 80:
            threat_score_item.setBackground(QColor(255, 0, 0, 100))  # Red
        elif result['threat_score'] >= 60:
            threat_score_item.setBackground(QColor(255, 165, 0, 100))  # Orange
        else:
            threat_score_item.setBackground(QColor(255, 255, 0, 100))  # Yellow
        self.alerts_table.setItem(row_position, 1, threat_score_item)
        
        # Add the time
        import datetime
        time_item = QTableWidgetItem(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.alerts_table.setItem(row_position, 2, time_item)
        
        # Show the alert dialog immediately with setWindowFlags to ensure it appears on top
        alert_dialog = AlertDialog(result, self)
        alert_dialog.setWindowFlags(alert_dialog.windowFlags() | Qt.WindowStaysOnTopHint)
        alert_dialog.raise_()
        alert_dialog.activateWindow()
        alert_dialog.exec_()
        
        # Show a system tray notification
        self.tray_icon.showMessage(
            "PhishGuard - Phishing Detected",
            f"Potential phishing site detected: {result['url']}",
            QSystemTrayIcon.Warning,
            5000  # 5 seconds
        )
    
    def on_tray_icon_activated(self, reason):
        """Handle tray icon activated event
        
        Args:
            reason: The reason for the activation
        """
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()
            self.activateWindow()
    
    def on_save_settings(self):
        """Handle save settings button click"""
        QMessageBox.information(self, "Settings Saved", "Settings have been saved successfully.")
    
    def on_reset_settings(self):
        """Handle reset settings button click"""
        QMessageBox.information(self, "Settings Reset", "Settings have been reset to defaults.")
    
    def on_refresh_clicked(self):
        """Handle refresh button click"""
        # Restart the browser monitoring
        self.browser_monitor.stop()
        self.browser_monitor.start()
        
        # Update the status
        self.statusBar.showMessage("Browser monitoring refreshed")
        self.tray_icon.showMessage(
            "PhishGuard",
            "Browser monitoring has been refreshed",
            QSystemTrayIcon.Information,
            3000  # 3 seconds
        )
        
        logger.info("Browser monitoring refreshed")
    
    def closeEvent(self, event):
        """Handle close event
        
        Args:
            event: The close event
        """
        # Minimize to tray instead of closing
        event.ignore()
        self.hide()
        
        # Show a system tray notification
        self.tray_icon.showMessage(
            "PhishGuard",
            "PhishGuard is still running in the background. Click the tray icon to show the window.",
            QSystemTrayIcon.Information,
            5000  # 5 seconds
        )