import winreg
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import wmi
import threading
import time
from datetime import datetime, timedelta
import os
import csv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Convert Windows FILETIME to readable datetime
def convert_filetime(filetime):
    try:
        epoch_start = datetime(1601, 1, 1)
        seconds = filetime / 10_000_000
        return epoch_start + timedelta(seconds=seconds)
    except:
        return "Unknown"

# Retrieve USB device information from the registry
def get_usb_devices():
    usb_info = []
    try:
        key_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as usb_key:
            num_subkeys = winreg.QueryInfoKey(usb_key)[0]
            for i in range(num_subkeys):
                device_name = winreg.EnumKey(usb_key, i)
                device_key_path = f"{key_path}\\{device_name}"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, device_key_path) as device_key:
                    num_instances = winreg.QueryInfoKey(device_key)[0]
                    for j in range(num_instances):
                        instance_name = winreg.EnumKey(device_key, j)
                        instance_key_path = f"{device_key_path}\\{instance_name}"
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, instance_key_path) as instance_key:
                            friendly_name = winreg.QueryValueEx(instance_key, "FriendlyName")[0] if "FriendlyName" in [winreg.EnumValue(instance_key, k)[0] for k in range(winreg.QueryInfoKey(instance_key)[1])] else "Unknown"
                            properties_key_path = f"{instance_key_path}\\Properties"
                            try:
                                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, properties_key_path) as props_key:
                                    with winreg.OpenKey(props_key, "{83da6326-97a6-4088-9453-a1923f573b29}\\0064") as time_key:
                                        with winreg.OpenKey(time_key, "00000000") as data_key:
                                            last_connected = convert_filetime(winreg.QueryValueEx(data_key, "Data")[0])
                                    with winreg.OpenKey(props_key, "{83da6326-97a6-4088-9453-a1923f573b29}\\0065") as time_key:
                                        with winreg.OpenKey(time_key, "00000000") as data_key:
                                            first_installed = convert_filetime(winreg.QueryValueEx(data_key, "Data")[0])
                            except:
                                last_connected = first_installed = "Unknown"
                            usb_info.append({
                                "Device Name": device_name,
                                "Serial Number": instance_name,
                                "Friendly Name": friendly_name,
                                "First Installed": str(first_installed),
                                "Last Connected": str(last_connected)
                            })
    except Exception as e:
        usb_info.append({"Error": f"Failed to retrieve USB data: {str(e)}"})
    return usb_info

# File system event handler for tracking file operations
class USBFileHandler(FileSystemEventHandler):
    def __init__(self, log_func):
        self.log_func = log_func

    def on_created(self, event):
        self.log_func(f"File Created: {event.src_path} at {datetime.now()}")

    def on_modified(self, event):
        self.log_func(f"File Modified: {event.src_path} at {datetime.now()}")

    def on_deleted(self, event):
        self.log_func(f"File Deleted: {event.src_path} at {datetime.now()}")

# Real-time USB monitoring using WMI
def monitor_usb_devices(log_func):
    c = wmi.WMI()
    watcher = c.Win32_USBControllerDevice.watch_for()
    while True:
        try:
            usb_event = watcher()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if usb_event:
                log_func(f"USB Event at {timestamp}: {usb_event.Dependent.Caption} {'connected' if usb_event.__EVENT_TYPE__ == 'Creation' else 'disconnected'}")
                # Check for anomalies (e.g., rapid connect/disconnect)
                check_anomaly(usb_event, timestamp, log_func)
        except Exception as e:
            log_func(f"Monitoring Error: {str(e)}")
        time.sleep(1)

# Anomaly detection (example: rapid connect/disconnect)
last_event_time = None
def check_anomaly(event, timestamp, log_func):
    global last_event_time
    current_time = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    if last_event_time and (current_time - last_event_time).seconds < 5:
        log_func(f"ANOMALY DETECTED: Rapid USB activity at {timestamp}")
    last_event_time = current_time

# Export data to CSV
def export_to_csv(data, filename="usb_forensics_report.csv"):
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ["Timestamp", "Device Name", "Serial Number", "Friendly Name", "First Installed", "Last Connected", "Event"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for entry in data:
            writer.writerow({**{"Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}, **entry})

# GUI Application
class AdvancedUSBForensicsApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced USB Forensics Tool")
        self.root.geometry("1000x700")

        # Title
        tk.Label(root, text="Advanced USB Forensics", font=("Arial", 16, "bold")).pack(pady=10)

        # Tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(pady=5, expand=True)

        # Registry Tab
        self.registry_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.registry_frame, text="Registry Analysis")
        self.registry_text = scrolledtext.ScrolledText(self.registry_frame, width=110, height=30, font=("Arial", 10))
        self.registry_text.pack(pady=10)
        tk.Button(self.registry_frame, text="Scan USB Devices", command=self.scan_usb, bg="green", fg="white").pack(pady=5)

        # Real-Time Monitoring Tab
        self.monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.monitor_frame, text="Real-Time Monitoring")
        self.monitor_text = scrolledtext.ScrolledText(self.monitor_frame, width=110, height=30, font=("Arial", 10))
        self.monitor_text.pack(pady=10)
        tk.Button(self.monitor_frame, text="Start Monitoring", command=self.start_monitoring, bg="blue", fg="white").pack(pady=5)

        # File Tracking Tab
        self.file_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.file_frame, text="File Tracking")
        self.file_text = scrolledtext.ScrolledText(self.file_frame, width=110, height=30, font=("Arial", 10))
        self.file_text.pack(pady=10)
        tk.Label(self.file_frame, text="USB Drive Path (e.g., E:\\):").pack()
        self.path_entry = tk.Entry(self.file_frame, width=50)
        self.path_entry.pack()
        tk.Button(self.file_frame, text="Start File Tracking", command=self.start_file_tracking, bg="orange", fg="white").pack(pady=5)

        # Export Button
        tk.Button(root, text="Export Report", command=self.export_report, bg="purple", fg="white").pack(pady=5)
        tk.Button(root, text="Clear All", command=self.clear_all, bg="red", fg="white").pack(pady=5)

        self.monitoring = False
        self.file_observer = None
        self.log_data = []

    def log(self, message, text_widget):
        text_widget.insert(tk.END, f"{message}\n")
        text_widget.see(tk.END)
        self.log_data.append({"Event": message})

    def scan_usb(self):
        self.registry_text.delete(1.0, tk.END)
        usb_devices = get_usb_devices()
        for device in usb_devices:
            if "Error" in device:
                self.log(device["Error"], self.registry_text)
            else:
                output = (
                    f"Device Name: {device['Device Name']}\n"
                    f"Serial Number: {device['Serial Number']}\n"
                    f"Friendly Name: {device['Friendly Name']}\n"
                    f"First Installed: {device['First Installed']}\n"
                    f"Last Connected: {device['Last Connected']}\n"
                    "----------------------------------------\n"
                )
                self.log(output, self.registry_text)
                self.log_data.append(device)

    def start_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            threading.Thread(target=monitor_usb_devices, args=(lambda msg: self.log(msg, self.monitor_text),), daemon=True).start()
            self.log("Started real-time USB monitoring...", self.monitor_text)

    def start_file_tracking(self):
        path = self.path_entry.get()
        if not os.path.exists(path):
            messagebox.showerror("Error", "Invalid path!")
            return
        if self.file_observer:
            self.file_observer.stop()
        event_handler = USBFileHandler(lambda msg: self.log(msg, self.file_text))
        self.file_observer = Observer()
        self.file_observer.schedule(event_handler, path, recursive=True)
        self.file_observer.start()
        self.log(f"Started file tracking on {path}...", self.file_text)

    def export_report(self):
        export_to_csv(self.log_data)
        messagebox.showinfo("Success", "Report exported to usb_forensics_report.csv")

    def clear_all(self):
        self.registry_text.delete(1.0, tk.END)
        self.monitor_text.delete(1.0, tk.END)
        self.file_text.delete(1.0, tk.END)
        self.log_data.clear()
        if self.file_observer:
            self.file_observer.stop()
            self.file_observer = None

if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedUSBForensicsApp(root)
    root.mainloop()