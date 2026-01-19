#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Alert Dialog Module

This module contains the AlertDialog class which is used to display
phishing alerts to the user.
"""

import logging
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QGroupBox, QSizePolicy
)
from PyQt5.QtGui import QFont, QIcon, QPixmap
from PyQt5.QtCore import Qt

logger = logging.getLogger('PhishGuard.AlertDialog')


class AlertDialog(QDialog):
    """Dialog for displaying phishing alerts"""
    
    def __init__(self, phishing_result, parent=None):
        """Initialize the alert dialog
        
        Args:
            phishing_result (dict): The phishing analysis result
            parent: The parent widget
        """
        super().__init__(parent)
        
        self.phishing_result = phishing_result
        
        # Set up the UI
        self.setWindowTitle("PhishGuard - Phishing Alert")
        self.setMinimumSize(500, 400)
        
        # Ensure dialog appears on top and gets focus
        self.setWindowFlags(self.windowFlags() | Qt.WindowStaysOnTopHint)
        self.setAttribute(Qt.WA_ShowWithoutActivating, False)  # Ensure window activates
        
        # Set up the layout
        self.setup_ui()
        
        logger.info("AlertDialog initialized")
    
    def setup_ui(self):
        """Set up the UI"""
        # Create the main layout
        main_layout = QVBoxLayout(self)
        
        # Create the header layout
        header_layout = QHBoxLayout()
        
        # Add the warning icon
        warning_label = QLabel()
        warning_label.setPixmap(self.style().standardIcon(self.style().SP_MessageBoxWarning).pixmap(64, 64))
        header_layout.addWidget(warning_label)
        
        # Add the title
        title_label = QLabel("Phishing Website Detected!")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_label.setStyleSheet("color: red;")
        header_layout.addWidget(title_label)
        
        # Add spacer to push the title to the left
        header_layout.addStretch()
        
        main_layout.addLayout(header_layout)
        
        # Add the URL group
        url_group = QGroupBox("Suspicious URL")
        url_layout = QVBoxLayout(url_group)
        
        url_label = QLabel(self.phishing_result['url'])
        url_label.setFont(QFont("Arial", 12))
        url_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        url_label.setWordWrap(True)
        url_layout.addWidget(url_label)
        
        main_layout.addWidget(url_group)
        
        # Add the threat score group
        threat_score_group = QGroupBox("Threat Assessment")
        threat_score_layout = QHBoxLayout(threat_score_group)
        
        threat_score_label = QLabel(f"Threat Score: {self.phishing_result['threat_score']}/100")
        threat_score_label.setFont(QFont("Arial", 12, QFont.Bold))
        
        # Set the color based on the threat score
        if self.phishing_result['threat_score'] >= 80:
            threat_score_label.setStyleSheet("color: red;")
        elif self.phishing_result['threat_score'] >= 60:
            threat_score_label.setStyleSheet("color: orange;")
        else:
            threat_score_label.setStyleSheet("color: yellow;")
        
        threat_score_layout.addWidget(threat_score_label)
        
        main_layout.addWidget(threat_score_group)
        
        # Add the reasons group
        reasons_group = QGroupBox("Detection Reasons")
        reasons_layout = QVBoxLayout(reasons_group)
        
        reasons_text = QTextEdit()
        reasons_text.setReadOnly(True)
        reasons_text.setPlainText("\n".join([f"• {reason}" for reason in self.phishing_result['reasons']]))
        reasons_layout.addWidget(reasons_text)
        
        main_layout.addWidget(reasons_group)
        
        # Add the recommendation group
        recommendation_group = QGroupBox("Recommendation")
        recommendation_layout = QVBoxLayout(recommendation_group)
        
        recommendation_label = QLabel(
            "This website has been identified as a potential phishing attempt. "
            "We recommend that you do not proceed to this website or enter any personal information."
        )
        recommendation_label.setWordWrap(True)
        recommendation_label.setFont(QFont("Arial", 10))
        recommendation_layout.addWidget(recommendation_label)
        
        main_layout.addWidget(recommendation_group)
        
        # Add the buttons layout
        buttons_layout = QHBoxLayout()
        
        # Add spacer to push the buttons to the right
        buttons_layout.addStretch()
        
        # Add the block button
        block_button = QPushButton("Block Website")
        block_button.setIcon(self.style().standardIcon(self.style().SP_DialogCancelButton))
        block_button.clicked.connect(self.on_block_clicked)
        buttons_layout.addWidget(block_button)
        
        # Add the proceed anyway button
        proceed_button = QPushButton("Proceed Anyway (Not Recommended)")
        proceed_button.setIcon(self.style().standardIcon(self.style().SP_DialogApplyButton))
        proceed_button.clicked.connect(self.on_proceed_clicked)
        buttons_layout.addWidget(proceed_button)
        
        main_layout.addLayout(buttons_layout)
    
    def on_block_clicked(self):
        """Handle block button click"""
        logger.info(f"User chose to block phishing site: {self.phishing_result['url']}")
        self.accept()
    
    def on_proceed_clicked(self):
        """Handle proceed button click"""
        logger.warning(f"User chose to proceed to phishing site: {self.phishing_result['url']}")
        self.reject()