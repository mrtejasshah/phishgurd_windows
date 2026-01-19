#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Browser Monitor Module

This module contains the BrowserMonitor class which is responsible for
monitoring browser activity and detecting URL navigation.
"""

import os
import time
import logging
import threading
import re
import traceback
import win32gui
import win32process
import win32con
from PyQt5.QtCore import QObject, pyqtSignal

logger = logging.getLogger('PhishGuard.BrowserMonitor')


class BrowserMonitor(QObject):
    """Class for monitoring browser activity and detecting URL navigation"""
    
    # Define signals for browser events
    url_detected = pyqtSignal(str)
    phishing_detected = pyqtSignal(dict)
    analysis_completed = pyqtSignal(dict)
    
    def __init__(self, phishing_detector):
        """
        Initialize the BrowserMonitor
        
        Args:
            phishing_detector: An instance of PhishingDetector for URL analysis
        """
        super().__init__()
        self.phishing_detector = phishing_detector
        self.running = False
        self.monitor_thread = None
        self.last_analyzed_url = None  # Initialize the last analyzed URL
        self.known_browsers = {
            'chrome.exe': 'Google Chrome',
            'firefox.exe': 'Mozilla Firefox',
            'msedge.exe': 'Microsoft Edge',
            'iexplore.exe': 'Internet Explorer',
            'opera.exe': 'Opera',
            'brave.exe': 'Brave',
            'safari.exe': 'Safari',
            'vivaldi.exe': 'Vivaldi',
            'chromium.exe': 'Chromium',
            'dragon.exe': 'Comodo Dragon',
            'maxthon.exe': 'Maxthon',
            'torch.exe': 'Torch',
            'yandex.exe': 'Yandex Browser',
            'seamonkey.exe': 'SeaMonkey',
            'palemoon.exe': 'Pale Moon',
            'waterfox.exe': 'Waterfox',
        }
        self.url_check_interval = 0.5  # seconds
        
        logger.info("BrowserMonitor initialized")
    
    @property
    def is_running(self):
        """Property to check if the monitor is running"""
        return self.running
    
    def start(self):
        """Start the browser monitoring thread"""
        if self.running:
            logger.warning("Browser monitor is already running")
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Browser monitor started")
    
    def stop(self):
        """Stop the browser monitoring thread"""
        if not self.running:
            logger.warning("Browser monitor is not running")
            return
        
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
        logger.info("Browser monitor stopped")
    
    def _monitor_loop(self):
        """
        Main monitoring loop that checks for browser windows and extracts URLs
        """
        logger.info("Browser monitoring loop started")
        try:
            while self.running:
                try:
                    # Get all browser windows
                    browser_windows = self._get_browser_windows()
                    logger.debug(f"Found {len(browser_windows)} browser windows")
                    
                    # Process each browser window
                    for window in browser_windows:
                        logger.debug(f"Processing window: {window['browser_name']} - '{window['title']}'")
                        
                        # Extract URL from window title
                        url = self._extract_url_from_title(window['title'], window['browser_name'])
                        
                        if url:
                            logger.debug(f"Extracted URL: {url}")
                            
                            # Skip if this is the same URL we just analyzed
                            if url == self.last_analyzed_url:
                                logger.debug(f"Skipping duplicate URL: {url}")
                                continue
                                
                            # Update last analyzed URL
                            self.last_analyzed_url = url
                            
                            # Emit the URL detected signal
                            logger.info(f"Emitting URL detected signal: {url}")
                            self.url_detected.emit(url)
                            
                            # Analyze URL for phishing
                            logger.debug(f"Analyzing URL for phishing: {url}")
                            is_phishing = self.phishing_detector.analyze_url(url)
                            logger.debug(f"Phishing analysis result: {is_phishing}")

                            # Always emit analysis result for UI
                            result = self.phishing_detector.get_last_analysis_result() or {
                                'url': url,
                                'threat_score': 0,
                                'reasons': ['No analysis available']
                            }
                            logger.debug(f"Emitting analysis_completed: {result}")
                            self.analysis_completed.emit(result)

                            # If phishing detected, emit phishing alert
                            if is_phishing:
                                logger.warning(f"Phishing detected: {url}")
                                self.phishing_detected.emit(result)
                        else:
                            logger.debug(f"No URL extracted from window title: '{window['title']}'")
                    
                    # Sleep to reduce CPU usage
                    time.sleep(self.url_check_interval)
                    
                except Exception as e:
                    logger.error(f"Error in browser monitoring loop: {str(e)}")
                    logger.debug(f"Exception details: {traceback.format_exc()}")
                    time.sleep(1)  # Sleep longer on error
                    
        except Exception as e:
            logger.error(f"Fatal error in browser monitoring loop: {str(e)}")
            logger.debug(f"Exception details: {traceback.format_exc()}")
            
        logger.info("Browser monitoring loop stopped")
    
    def _get_browser_windows(self):
        """
        Get a list of all browser windows currently open
        
        Returns:
            list: List of dictionaries with window info
        """
        browser_windows = []
        
        def enum_window_callback(hwnd, _):
            # Skip invisible windows
            if not win32gui.IsWindowVisible(hwnd):
                return True
                
            # Get window title
            try:
                title = win32gui.GetWindowText(hwnd)
            except Exception:
                title = ""
                
            # Skip windows with empty titles or system windows
            if not title or title in ["Program Manager", "Windows Shell Experience Host"]:
                return True
                
            # Get process ID
            try:
                _, process_id = win32process.GetWindowThreadProcessId(hwnd)
                process_name = self._get_process_name(process_id)
                
                # Check if this is a known browser
                if process_name and process_name.lower() in self.known_browsers:
                    browser_name = self.known_browsers[process_name.lower()]
                    browser_windows.append({
                        "hwnd": hwnd,
                        "title": title,
                        "process_id": process_id,
                        "process_name": process_name,
                        "browser_name": browser_name
                    })
                    logger.debug(f"Found browser window: {browser_name} - {title}")
            except Exception as e:
                logger.error(f"Error getting process info: {e}")
                
            return True
            
        try:
            win32gui.EnumWindows(enum_window_callback, None)
        except Exception as e:
            logger.error(f"Error enumerating windows: {e}")
            
        return browser_windows
    
    def _get_process_name(self, pid):
        """
        Get process name from process ID
        
        Args:
            pid (int): Process ID
            
        Returns:
            str: Process name or None if not found
        """
        try:
            import psutil
            process = psutil.Process(pid)
            process_name = process.name().lower()
            logger.debug(f"Process ID {pid} is {process_name}")
            return process_name
        except Exception as e:
            logger.error(f"Error getting process name for PID {pid}: {e}")
            return None
    
    def _extract_url_from_title(self, title, browser_name):
        """
        Extract URL from browser window title with improved detection
        
        Args:
            title (str): Browser window title
            browser_name (str): Name of the browser
            
        Returns:
            str: Extracted URL or None if not found
        """
        # Log the input for debugging
        logger.debug(f"Extracting URL from title: '{title}' for browser: '{browser_name}'")
        
        # Skip empty titles or browser startup pages
        if not title or title == browser_name or 'New Tab' in title or 'Start Page' in title:
            logger.debug("Skipping empty title or browser startup page")
            return None
        
        # Special case for Chrome/Edge when the title is just "Browser Name"
        if title == browser_name:
            logger.debug(f"Title is just the browser name: {browser_name}")
            return None
            
        # Handle special case for Chrome where title might be "Page - Google Chrome"
        if browser_name in title:
            # Extract the part before the browser name
            parts = title.split(f" - {browser_name}")
            if len(parts) > 0:
                title = parts[0].strip()
                logger.debug(f"Extracted title part: '{title}'")

        # Handle search engine result titles, e.g., "example.com - Google Search"
        search_suffixes = [
            ' - Google Search',
            ' - Bing',
            ' - Yahoo Search',
            ' - DuckDuckGo',
            ' - Startpage',
            ' - Ecosia'
        ]
        for suffix in search_suffixes:
            if title.endswith(suffix):
                title = title[: -len(suffix)].strip()
                logger.debug(f"Stripped search suffix '{suffix}', now: '{title}'")
                break
        
        # Direct URL detection - highest priority
        url_direct_pattern = r'https?://([\w.-]+)([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?'
        direct_match = re.search(url_direct_pattern, title)
        if direct_match:
            url = direct_match.group(0).strip()
            logger.debug(f"Direct URL match: {url}")
            return url
        
        # Try to extract from address bar (this is a placeholder - actual implementation would depend on browser APIs)
        # For demonstration, we'll use a more aggressive approach to extract domains from titles
        
        # Browser-specific title patterns
        if browser_name == 'Google Chrome' or browser_name == 'Microsoft Edge' or browser_name == 'Brave':
            # Chrome/Edge/Brave format: "Page Title - Domain"
            parts = title.split(' - ')
            if len(parts) > 1:
                domain_part = parts[-1].strip()
                # Check if the last part looks like a domain
                if '.' in domain_part and not domain_part.startswith('http'):
                    # Ensure it's not just a file extension
                    if len(domain_part.split('.')[-1]) >= 2 and not domain_part.endswith('.exe') and not domain_part.endswith('.dll'):
                        return 'https://' + domain_part
        
        elif browser_name == 'Mozilla Firefox' or browser_name == 'Waterfox' or browser_name == 'Pale Moon':
            # Firefox format: "Page Title — Domain"
            parts = title.split(' — ')
            if len(parts) > 1:
                domain_part = parts[-1].strip()
                # Check if the last part looks like a domain
                if '.' in domain_part and not domain_part.startswith('http'):
                    # Ensure it's not just a file extension
                    if len(domain_part.split('.')[-1]) >= 2 and not domain_part.endswith('.exe') and not domain_part.endswith('.dll'):
                        return 'https://' + domain_part
        
        # Domain pattern detection - fallback
        domain_pattern = r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        domain_match = re.search(domain_pattern, title)
        if domain_match:
            domain = domain_match.group(0)
            # Verify it's likely a domain and not just a word with a period
            tlds = ['.com', '.org', '.net', '.edu', '.gov', '.io', '.co', '.uk', '.ca', '.au',
                   '.de', '.jp', '.cn', '.ru', '.br', '.in', '.fr', '.it', '.nl', '.es']
            if any(domain.lower().endswith(tld) for tld in tlds):
                return 'https://' + domain
        
        # If we couldn't extract a URL, return None
        logger.debug("Could not extract URL from title")
        return None