#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
PhishGuard Installation Script

This script installs the required dependencies for PhishGuard.
"""

import os
import sys
import subprocess
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger('PhishGuard.Install')


def install_dependencies():
    """Install the required dependencies for PhishGuard"""
    try:
        logger.info("Installing dependencies...")
        
        # Get the project root directory
        project_root = os.path.dirname(os.path.abspath(__file__))
        
        # Install dependencies using pip
        requirements_file = os.path.join(project_root, 'requirements.txt')
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', requirements_file], check=True)
        
        logger.info("Dependencies installed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error installing dependencies: {e}")
        return False


def main():
    """Main function"""
    print("PhishGuard Installation")
    print("=======================")
    print("This script will install the required dependencies for PhishGuard.")
    print("Please make sure you have Python 3.8 or later installed.")
    print()
    
    # Check Python version
    python_version = sys.version_info
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 8):
        print("Error: PhishGuard requires Python 3.8 or later.")
        print(f"You are using Python {python_version.major}.{python_version.minor}.{python_version.micro}")
        return 1
    
    # Install dependencies
    print("Installing dependencies...")
    success = install_dependencies()
    
    if success:
        print("\nInstallation completed successfully!")
        print("You can now run PhishGuard by executing 'python main.py'")
        return 0
    else:
        print("\nInstallation failed. Please check the error messages above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())