#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Main entry point for the PhishGuard application.

This module initializes the GUI and starts the browser monitoring service to detect
and prevent access to phishing websites.
"""

from __future__ import annotations

import logging
import os
import socket
import sys
from typing import Any, Callable, Optional, TypeVar
import win32api  # type: ignore
import win32con  # type: ignore
import win32gui  # type: ignore
from PyQt5.QtCore import QTimer  # type: ignore
from PyQt5.QtGui import QIcon  # type: ignore
from PyQt5.QtWidgets import QApplication, QMessageBox  # type: ignore

from core.browser_monitor import BrowserMonitor
from core.phishing_detector import PhishingDetector
from gui.main_window import MainWindow

# Type variable for window handle callbacks
Hwnd = int
WindowCallback = Callable[[Hwnd, Any], bool]
T = TypeVar('T')

def setup_logging() -> None:
    """Configure logging for the application.

    Sets up both file and console logging with a consistent format.
    Logs are written to 'phishguard.log' in the application directory.
    """
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    log_file = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'phishguard.log'
    )
    
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(),
        ],
    )

# Initialize logging at module level
logger = logging.getLogger('phishguard')

def is_already_running(port: int = 47365) -> bool:
    """Check if another instance of PhishGuard is already running.

    Args:
        port: The port number to check for an existing instance.

    Returns:
        bool: True if another instance is running, False otherwise.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('localhost', port))
        sock.listen(1)
        sock.close()
        return False
    except (socket.error, OSError) as e:
        logger.debug("Socket bind error: %s", e)
        return True

def _enum_windows_callback(hwnd: Hwnd, app_name: str) -> bool:
    """Callback function for window enumeration to find and activate the app window.

    Args:
        hwnd: Window handle.
        app_name: Name of the application to find.

    Returns:
        bool: True to continue enumeration, False to stop.
    """
    if not win32gui.IsWindowVisible(hwnd):
        return True

    window_text = win32gui.GetWindowText(hwnd)
    if app_name not in window_text:
        return True

    # Restore the window if minimized
    if win32gui.IsIconic(hwnd):
        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
    
    # Bring the window to the front
    win32gui.SetForegroundWindow(hwnd)
    return False  # Stop enumeration

def activate_existing_instance(app_name: str = "PhishGuard") -> None:
    """Find and activate the existing PhishGuard window.

    Args:
        app_name: Name of the application to find in window titles.
    """
    win32gui.EnumWindows(_enum_windows_callback, app_name)

def setup_application() -> tuple[QApplication, MainWindow, BrowserMonitor, PhishingDetector]:
    """Initialize and configure the PhishGuard application components.

    Returns:
        tuple: A tuple containing (app, main_window, browser_monitor, phishing_detector)
    """
    app = QApplication(sys.argv)
    app.setApplicationName("PhishGuard")
    
    # Set application icon
    icon_path = _get_resource_path('icon.svg')
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    else:
        logger.warning("Application icon not found at: %s", icon_path)
    
    # Initialize core components
    phishing_detector = PhishingDetector()
    browser_monitor = BrowserMonitor(phishing_detector)
    main_window = MainWindow(browser_monitor, phishing_detector)
    
    return app, main_window, browser_monitor, phishing_detector

def _get_resource_path(resource_name: str) -> str:
    """Get the absolute path to a resource file.
    
    Args:
        resource_name: Name of the resource file.
        
    Returns:
        str: Absolute path to the resource file.
    """
    if getattr(sys, 'frozen', False):
        # Running as compiled executable
        base_path = os.path.dirname(sys.executable)
    else:
        # Running as script
        base_path = os.path.dirname(os.path.abspath(__file__))
    
    return os.path.join(base_path, 'resources', resource_name)

def handle_unhandled_exception(exc_type, exc_value, exc_traceback):
    """Handle any unhandled exceptions.
    
    This function is set as the excepthook to catch and log all unhandled exceptions.
    """
    if issubclass(exc_type, KeyboardInterrupt):
        # Allow keyboard interrupts to work normally
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    
    logger.critical(
        "Unhandled exception",
        exc_info=(exc_type, exc_value, exc_traceback)
    )
    
    # Show error message if possible
    if QApplication.instance() is not None:
        error_msg = f"An unhandled exception occurred:\n\n{exc_value}"
        QMessageBox.critical(
            None,
            "PhishGuard - Unhandled Exception",
            error_msg
        )

def main() -> int:
    """Initialize and run the PhishGuard application.
    
    This is the main entry point that sets up the application, checks for
    existing instances, initializes the GUI, and starts monitoring services.
    
    Returns:
        int: Exit code (0 for success, non-zero for errors)
    """
    # Set up global exception handling
    sys.excepthook = handle_unhandled_exception
    
    # Set up logging first
    setup_logging()
    logger.info("Starting PhishGuard application")

    try:
        # Check if another instance is already running
        if is_already_running():
            logger.info("Existing instance found, activating it")
            activate_existing_instance()
            return 0
        
        # Set up and initialize the application
        app, main_window, browser_monitor, _ = setup_application()
        
        try:
            # Parse command line arguments
            start_minimized = "--minimized" in sys.argv
            
            if start_minimized:
                logger.info("Starting minimized to system tray")
            else:
                main_window.show()
            
            # Start monitoring
            browser_monitor.start()
            
            # Start the application event loop
            return app.exec_()
            
        except Exception as e:
            logger.exception("Error in main application loop")
            QMessageBox.critical(
                None,
                "PhishGuard - Fatal Error",
                f"A fatal error occurred in the application:\n\n{str(e)}"
            )
            return 1
            
    except Exception as e:
        logger.exception("Failed to initialize application")
        if QApplication.instance() is None:
            app = QApplication(sys.argv)
            
        QMessageBox.critical(
            None,
            "PhishGuard - Initialization Error",
            f"Failed to initialize PhishGuard:\n\n{str(e)}"
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())