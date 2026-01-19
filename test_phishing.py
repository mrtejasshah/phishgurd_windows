# #!/usr/bin/env python
# # -*- coding: utf-8 -*-

# """
# PhishGuard Test Script

# This script tests the phishing detection and alert system by simulating
# navigation to known phishing URLs.
# """

# import sys
# import time
# import logging
# from PyQt5.QtWidgets import QApplication
# from PyQt5.QtCore import QTimer

# from core.phishing_detector import PhishingDetector
# from core.browser_monitor import BrowserMonitor
# from gui.main_window import MainWindow

# # Configure logging
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
# )

# logger = logging.getLogger('PhishGuard.Test')

# # Test URLs (mix of legitimate and phishing-like URLs)
# TEST_URLS = [
#     # Legitimate URLs
#     "https://www.google.com",
#     "https://www.microsoft.com",
#     # Suspicious URLs
#     "http://googgle.com",  # Typosquatting
#     "http://paypal-secure.phishing-example.com",  # Suspicious keywords
#     "http://login.bank-secure-verify.tk",  # Suspicious TLD
#     "http://192.168.1.1/login.php",  # IP address URL
#     "http://bit.ly/3xyzabc",  # URL shortener
#     "http://secure-banking-login.com/verify.php"  # Multiple suspicious elements
# ]

# class PhishGuardTester:
#     """Class for testing PhishGuard functionality"""
    
#     def __init__(self):
#         """Initialize the tester"""
#         self.app = QApplication(sys.argv)
        
#         # Initialize components
#         self.phishing_detector = PhishingDetector()
#         self.browser_monitor = BrowserMonitor(self.phishing_detector)
#         self.main_window = MainWindow(self.browser_monitor, self.phishing_detector)
        
#         # Connect signals for testing
#         self.browser_monitor.url_detected.connect(self.on_url_detected)
#         self.browser_monitor.phishing_detected.connect(self.on_phishing_detected)
        
#         # Show the main window
#         self.main_window.show()
        
#         # Set up test timer
#         self.test_timer = QTimer()
#         self.test_timer.timeout.connect(self.run_next_test)
#         self.current_test_index = 0
        
#         logger.info("PhishGuardTester initialized")
    
#     def start_tests(self):
#         """Start the tests"""
#         logger.info("Starting tests")
#         self.browser_monitor.start()
#         self.test_timer.start(5000)  # Run a test every 5 seconds
#         self.run_next_test()  # Run the first test immediately
    
#     def run_next_test(self):
#         """Run the next test"""
#         if self.current_test_index < len(TEST_URLS):
#             url = TEST_URLS[self.current_test_index]
#             logger.info(f"Testing URL: {url}")
            
#             # Simulate browser navigation by directly triggering URL detection
#             self.simulate_browser_navigation(url)
            
#             self.current_test_index += 1
#         else:
#             logger.info("All tests completed")
#             self.test_timer.stop()
    
#     def simulate_browser_navigation(self, url):
#         """Simulate browser navigation to a URL"""
#         # This directly triggers the URL detection signal
#         # In a real scenario, this would be detected by monitoring browser windows
#         self.browser_monitor.url_detected.emit(url)
        
#         # Analyze the URL and emit phishing_detected signal if it's a phishing site
#         result = self.phishing_detector.analyze_url(url)
#         if result['risk_level'] == 'high' or result['risk_level'] == 'medium':
#             # Convert to the format expected by the UI
#             ui_result = {
#                 'url': url,
#                 'is_phishing': True,
#                 'threat_score': int(result['score'] * 100),  # Convert 0-1 to 0-100
#                 'reasons': result['reasons']
#             }
#             self.browser_monitor.phishing_detected.emit(ui_result)
    
#     def on_url_detected(self, url):
#         """Handle URL detected event"""
#         logger.info(f"URL detected: {url}")
    
#     def on_phishing_detected(self, result):
#         """Handle phishing detected event"""
#         logger.warning(f"Phishing detected: {result['url']} with score {result['threat_score']}")
    
#     def run(self):
#         """Run the application"""
#         # Start the tests after a short delay
#         QTimer.singleShot(1000, self.start_tests)
        
#         # Run the application
#         return self.app.exec_()


# if __name__ == "__main__":
#     tester = PhishGuardTester()
#     sys.exit(tester.run())