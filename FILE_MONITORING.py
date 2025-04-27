import os
import time
import hashlib
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Telegram bot details
TELEGRAM_TOKEN = "YOUR TELEGRAM TOKEN"  # Replace with your Telegram Bot Token
CHAT_ID = "ID CHAT" # Replace with your Telegram Chat ID

# Directory to monitor
MONITORED_DIR = r"FILE_PATH" # Set your folder to monitor

# Function to calculate file hash
def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of the file"""
    hash_sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

# Send Telegram alert
def send_telegram_alert(message):
    """Send a message via Telegram Bot"""
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": message
    }
    requests.post(url, data=payload)

# Monitor file changes in directory
class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self):
        self.file_hashes = {}  # To store the hash of files for comparison

    def on_modified(self, event):
        """Trigger when any file in the monitored directory is modified"""
        if event.is_directory:
            return  # Skip directories

        file_path = event.src_path
        if file_path not in self.file_hashes:  # New file, store hash
            self.file_hashes[file_path] = calculate_file_hash(file_path)
            return

        current_hash = calculate_file_hash(file_path)
        if current_hash != self.file_hashes[file_path]:
            print(f"File Modified: {file_path}")
            send_telegram_alert(f"⚠️ ALERT: File modified: {file_path}")
            self.file_hashes[file_path] = current_hash

    def on_created(self, event):
        """Trigger when a new file is created"""
        if event.is_directory:
            return
        file_path = event.src_path
        self.file_hashes[file_path] = calculate_file_hash(file_path)
        print(f"New File Created: {file_path}")

    def on_deleted(self, event):
        """Trigger when a file is deleted"""
        if event.is_directory:
            return
        file_path = event.src_path
        if file_path in self.file_hashes:
            del self.file_hashes[file_path]
            print(f"File Deleted: {file_path}")
            send_telegram_alert(f"⚠️ ALERT: File deleted: {file_path}")

def monitor_directory():
    """Start the file monitoring system"""
    event_handler = FileMonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, MONITORED_DIR, recursive=False)
    observer.start()
    print(f"Monitoring changes in: {MONITORED_DIR}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    monitor_directory()
