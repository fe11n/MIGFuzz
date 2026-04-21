#!/usr/bin/env python3
"""
Script to attempt registering a virtual IIDC device by enumerating video devices.
This will trigger the loading of IIDC.plugin and potentially start the IIDCVideoAssistant service.
"""

import sys
import time
import subprocess

def check_service_status():
    """Check if com.apple.cmio.IIDCVideoAssistant is running."""
    try:
        result = subprocess.run(['launchctl', 'list', 'com.apple.cmio.IIDCVideoAssistant'],
                                capture_output=True, text=True)
        if result.returncode == 0:
            return "running"
        else:
            return "not running"
    except Exception as e:
        print(f"Error checking service: {e}")
        return "unknown"

def enumerate_devices():
    """Attempt to enumerate video devices using AVFoundation via pyobjc."""
    try:
        # Import pyobjc modules
        from AVFoundation import AVCaptureDevice, AVMediaTypeVideo
        from Foundation import NSObject

        # Get all video devices
        devices = AVCaptureDevice.devicesWithMediaType_(AVMediaTypeVideo)
        print(f"Found {len(devices)} video devices:")
        for device in devices:
            print(f"  - {device.localizedName()} (ID: {device.uniqueID()})")

        return True
    except ImportError:
        print("pyobjc not installed. Install with: pip install pyobjc-framework-AVFoundation")
        return False
    except Exception as e:
        print(f"Error enumerating devices: {e}")
        return False

def main():
    print("Attempting to register virtual IIDC device by enumerating video devices...")
    print("This may trigger the IIDCVideoAssistant service to start.")

    # Check initial service status
    initial_status = check_service_status()
    print(f"Initial service status: {initial_status}")

    # Attempt to enumerate devices
    if enumerate_devices():
        print("Device enumeration completed.")
    else:
        print("Failed to enumerate devices.")
        sys.exit(1)

    # Wait a bit for service to start
    time.sleep(2)

    # Check service status after enumeration
    final_status = check_service_status()
    print(f"Final service status: {final_status}")

    if initial_status != "running" and final_status == "running":
        print("Service was started by device enumeration!")
    elif final_status == "running":
        print("Service was already running.")
    else:
        print("Service did not start. Enumeration may not have triggered IIDC plugin.")

if __name__ == "__main__":
    main()