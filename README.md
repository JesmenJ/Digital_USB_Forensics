# Digital_USB_Forensics

# Advanced USB Forensics Tool

## Overview
The **Advanced USB Forensics Tool** is a comprehensive forensic analysis tool designed to monitor, analyze, and track USB devices and file activity on a Windows system. It allows users to retrieve USB device history, perform real-time monitoring, detect anomalies, and track file system changes.

## Features
- **USB Device Registry Analysis**: Extracts USB device details from the Windows registry.
- **Real-Time USB Monitoring**: Tracks USB device connection and disconnection events.
- **File Tracking on USB Drives**: Monitors file operations (creation, modification, deletion) on a specified USB path.
- **Anomaly Detection**: Detects rapid USB connect/disconnect activities.
- **Report Export**: Saves USB forensic data to a CSV file for further analysis.
- **Graphical User Interface (GUI)**: Provides an intuitive and user-friendly interface using Tkinter.

## Installation
### Prerequisites
Ensure you have the following installed on your system:
- Python 3.x
- Required dependencies:

```sh
pip install wmi watchdog
```

## Usage
1. **Run the script**:
   ```sh
   python usb_forensics.py
   ```
2. **USB Registry Analysis**:
   - Click on **"Scan USB Devices"** to retrieve the USB history from the Windows registry.
3. **Real-Time USB Monitoring**:
   - Click on **"Start Monitoring"** to track USB connection and disconnection events.
4. **File Tracking**:
   - Enter the **USB drive letter (e.g., E:\)** and click **"Start File Tracking"** to monitor file operations on that drive.
5. **Export Report**:
   - Click on **"Export Report"** to save forensic data in a CSV file.
6. **Clear Logs**:
   - Click on **"Clear All"** to reset all logs.

## File Structure
```
├── usb_forensics.py       # Main script
├── usb_forensics_report.csv # Exported forensic report (generated)
└── README.md              # Documentation
```

## Potential Use Cases
- **Digital Forensics Investigations**: Track USB activities for forensic analysis.
- **Enterprise Security**: Monitor unauthorized USB usage in an organization.
- **Incident Response**: Detect anomalies in USB connections and file access.

## Limitations
- This tool is **Windows-only**, as it relies on Windows Registry and WMI.
- Requires **Administrator privileges** to access certain registry keys.
- The **real-time monitoring** feature may have minor delays due to system limitations.



## Contributing
Feel free to contribute by submitting pull requests or reporting issues.

## Author
Developed by **Jesmen**.

