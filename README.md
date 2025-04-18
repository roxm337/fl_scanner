# Advanced Nmap Vulnerability Scanner

A complete network vulnerability scanning solution featuring a Flutter mobile app frontend and FastAPI backend. This tool provides both basic port scanning capabilities and advanced vulnerability detection using Nmap's powerful features.

## Project Structure

This project is divided into two main components:

1. **Flutter Mobile Application**: User-friendly interface for running scans
2. **FastAPI Backend**: Server-side component that executes Nmap commands and processes results

## Features

### Mobile App Features
- Clean, intuitive UI with tabbed interface
- Basic port scanning with custom Nmap options
- Advanced vulnerability scanning with configurable parameters
- Scan intensity level adjustment (1-5)
- Toggle switches for script scanning, OS detection, and version detection
- Real-time scan results display

### Backend Features
- RESTful API for executing Nmap commands
- Basic scan endpoint for port discovery
- Advanced vulnerability scanning endpoint
- XML output parsing for structured results
- CVE database checking for known vulnerabilities
- Automated remediation suggestions
- Security measures to prevent command injection

## Prerequisites

- Flutter SDK (3+)
- Dart (2.16.0+)
- Python (3.7+)
- Nmap (7.80+)
- FastAPI
- Uvicorn

## Installation & Setup

### Backend Setup

1. Clone the repository
   ```bash
   git clone https://github.com/roxm337/nmap-scanner.git
   cd nmap-scanner/backend
   ```

2. Create and activate a virtual environment
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```

4. Ensure Nmap is installed on your system
   - Linux: `sudo apt install nmap`
   - macOS: `brew install nmap`
   - Windows: Download and install from [nmap.org](https://nmap.org/download.html)

5. Start the FastAPI server
   ```bash
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

### Flutter App Setup

1. Navigate to the frontend directory
   ```bash
   cd fl_scanner/
   ```

2. Get Flutter dependencies
   ```bash
   flutter pub get
   ```

3. Update the API endpoint in `lib/main.dart` if needed
   - Default is set to `10.0.2.2:8000` which works for Android emulators
   - For physical devices, use the IP address of your backend server

4. Run the app
   ```bash
   flutter run
   ```

## Usage Guide

### Basic Scanning
1. Enter the target IP address or hostname
2. Optionally adjust Nmap options (default: `-sV`)
3. Tap "Run Basic Scan"
4. View results in the results panel

### Vulnerability Scanning
1. Switch to the "Vulnerability Scan" tab
2. Enter the target IP address or hostname
3. Adjust the scan intensity level (1-5):
   - Level 1: Quick scan (fewer ports)
   - Level 2: Default scan
   - Level 3: Moderate scan intensity
   - Level 4: Aggressive scan
   - Level 5: Intense scan (all ports, all scripts)
4. Toggle optional scan features:
   - Script Scanning: Enables NSE vulnerability detection scripts
   - OS Detection: Attempts to identify the operating system
   - Version Detection: Attempts to determine service versions
5. Tap "Run Vulnerability Scan"
6. View detailed vulnerability analysis in the results panel

## Security Considerations

- Always obtain proper authorization before scanning any network or system
- Be aware that high-intensity scans may trigger intrusion detection systems
- Consider the bandwidth and system impact of scans, especially at higher intensity levels
- This tool should only be used for legitimate security assessment purposes

## Legal Disclaimer

This tool is provided for educational and legitimate security assessment purposes only. Users are responsible for complying with all applicable laws and regulations. The developers assume no liability for misuse or for any damages resulting from the use of this tool.
pen a Pull Request
