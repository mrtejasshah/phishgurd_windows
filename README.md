# PhishGuard

PhishGuard is a Windows application that helps protect you from phishing websites by monitoring your web browsers and alerting you when it detects a potential phishing site. It uses advanced detection techniques to identify suspicious URLs and provides real-time alerts to keep you safe while browsing.

## Features

- **Real-time Browser Monitoring**: Continuously monitors all major web browsers (Chrome, Firefox, Edge, Opera, etc.) to detect URL navigation in real-time
- **Advanced Phishing Detection**: Uses multiple indicators and algorithms to identify potential phishing sites including:
  - Suspicious domain analysis
  - URL pattern matching
  - Known phishing site database
  - Typosquatting detection
  - Suspicious TLD identification
  - URL shortener detection
- **User-friendly Interface**: Clean, intuitive interface with detailed threat information
- **Alert System**: Displays prominent alerts when potential phishing sites are detected
- **System Tray Integration**: Runs efficiently in the background with easy access via system tray
- **Detailed Logging**: Comprehensive logging of all detected URLs and analysis results
- **Whitelist Management**: Ability to whitelist trusted domains
- **Debug Mode**: Optional debug mode for testing and development
- **Easy Installation**: Simple installer for Windows with minimal configuration required

## Installation

### Prerequisites

- Windows 10 or later
- Python 3.8 or later (if installing from source)
- Administrator privileges (for system tray integration and startup configuration)

### Installing from Source

1. Clone the repository or download the source code
2. Run the installation script to install all dependencies:
   ```
   python install.py
   ```
   Or manually install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Run the application:
   ```
   python main.py
   ```

### Using the Pre-built Executable

If you prefer not to install from source:

1. Download the latest release from the releases page
2. Run the PhishGuard.exe executable
3. The application will start automatically and add itself to system startup

### Creating Your Own Installer

To create a standalone Windows executable:

1. Make sure all dependencies are installed:
   ```
   pip install -r requirements.txt
   ```
2. Run the build script:
   ```
   python -m PyInstaller PhishGuard.spec
   ```
   Or use the installer utility:
   ```
   python utils/installer.py
   ```
3. The executable will be created in the `dist` directory

## Usage

1. Launch PhishGuard from the Start menu or desktop shortcut
2. The application will run in the background and monitor your web browsers
3. When a potential phishing site is detected, an alert will be displayed with detailed threat information
4. You can access the main interface by clicking on the PhishGuard icon in the system tray
5. The main interface provides:
   - A history of detected URLs
   - Detailed threat analysis for each URL
   - Options to configure the application
   - Ability to whitelist trusted domains

## How It Works

PhishGuard uses a comprehensive multi-layered approach to detect potential phishing websites:

1. **Browser Monitoring**: Continuously monitors all open browser windows to detect URL navigation
2. **URL Analysis**: 
   - Examines URLs for suspicious patterns, keywords, and structures
   - Identifies URL shorteners that might hide malicious destinations
   - Detects IP-based URLs which are commonly used in phishing attacks
3. **Domain Analysis**: 
   - Checks for typosquatting (slight misspellings of legitimate domains)
   - Identifies suspicious TLDs (top-level domains) commonly used in phishing
   - Evaluates domain age and reputation
4. **Content Analysis**: 
   - Analyzes webpage content for phishing indicators
   - Detects login forms on suspicious domains
   - Identifies brand impersonation attempts
5. **Database Comparison**:
   - Compares against known phishing domains database
   - Maintains a whitelist of legitimate domains
   - Uses pattern matching to identify new variants of known phishing attempts

## Development

### Project Structure

```
PhishGuard/
├── core/                 # Core functionality
│   ├── __init__.py
│   ├── browser_monitor.py  # Browser monitoring module - detects URLs from browser windows
│   └── phishing_detector.py  # Phishing detection module - analyzes URLs for phishing indicators
├── database/             # Phishing detection databases
│   ├── known_phishing.json  # Database of known phishing domains and patterns
│   ├── suspicious_domains.json  # Lists of suspicious TLDs, keywords, and URL shorteners
│   └── whitelist.json    # Whitelist of trusted domains
├── gui/                  # User interface
│   ├── __init__.py
│   ├── alert_dialog.py     # Phishing alert dialog - displays warnings to users
│   └── main_window.py      # Main application window - primary user interface
├── resources/            # Application resources
│   ├── icon.svg           # Application icon
│   └── logo.svg           # Application logo
├── utils/                # Utility modules
│   ├── __init__.py
│   └── installer.py       # Installer creation utility
├── .vscode/              # VS Code configuration
│   └── settings.json      # Editor settings
├── build/                # Build artifacts
├── dist/                 # Distribution files
├── install.py           # Installation script for dependencies
├── main.py              # Application entry point
├── phishguard.log       # Application log file
├── PhishGuard.spec      # PyInstaller specification file
├── requirements.txt     # Python dependencies
├── test_phishing.py     # Test script for phishing detection (for development only)
└── README.md           # This file
```

### Key Components

#### Core Modules

- **browser_monitor.py**: Monitors browser windows to detect URL navigation. It extracts URLs from browser window titles and emits signals when new URLs are detected.

- **phishing_detector.py**: Analyzes URLs for phishing indicators using multiple detection techniques including pattern matching, domain analysis, and database comparison.

#### GUI Components

- **main_window.py**: The primary user interface that displays detected URLs, threat analysis, and application settings.

- **alert_dialog.py**: Displays alerts when potential phishing sites are detected, showing detailed threat information and recommendations.

#### Database Files

- **known_phishing.json**: Contains a database of known phishing domains and patterns.

- **suspicious_domains.json**: Contains lists of suspicious TLDs, keywords, and URL shorteners used in phishing detection.

- **whitelist.json**: Contains a list of trusted domains that should not trigger phishing alerts.

#### Utility Scripts

- **install.py**: Installs the required dependencies for PhishGuard.

- **test_phishing.py**: A test script for development purposes that simulates browser navigation to test the phishing detection system. This file is commented out by default and should only be used for testing.

### Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

PhishGuard is provided as-is without any guarantees or warranty. While the application aims to detect phishing websites, it may not detect all phishing attempts. Users should always exercise caution when browsing the internet and never enter sensitive information on websites they don't trust.