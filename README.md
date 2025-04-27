# File-Integrity-Monitoring-and-Detection-System-with-Telegram-Alerts
This project monitors a specified directory for file changes (modification, creation, deletion). It calculates file hashes to detect modifications and sends real-time Telegram alerts for any detected changes, ensuring file integrity and security.
![cmd ](https://github.com/user-attachments/assets/d6330b35-9687-438a-8ed2-a8c0c2769485)
![telegram alert ](https://github.com/user-attachments/assets/af4bdea7-d8b0-4179-8e0c-e1eb4de65d56)
you can see telegram alert message
NOTE: REPLACE IN THE GIVEN CODE WITH YOURS TELGRAM TOKEN CHAT ID , FOLDER TO MONITOR
# Telegram bot details
TELEGRAM_TOKEN = "YOUR TELEGRAM TOKEN"  # Replace with your Telegram Bot Token
CHAT_ID = "ID CHAT" # Replace with your Telegram Chat ID

# Directory to monitor
MONITORED_DIR = r"FOLDER_PATH" # Set your folder to monitor

### **File Integrity Monitoring and Detection System with Telegram Alerts**

#### **Overview**
This project involves creating a file integrity monitoring and detection system that watches a specified directory for any changes (modifications, creations, or deletions) to files. Upon detecting a change, the system sends a Telegram notification to alert the user. It utilizes Python libraries such as `watchdog`, `hashlib`, and `requests` to monitor the directory and send notifications.

#### **Components:**

1. **File Monitoring System (Watchdog)**
   - `watchdog` is used to watch a specified directory for file system changes (creation, modification, deletion).
   - It triggers events (callbacks) when any of the above file operations occur.
   
2. **File Integrity Check (SHA-256 Hashing)**
   - Each file in the monitored directory is assigned a hash value (calculated using SHA-256) when it is first encountered or modified.
   - The hash is used to compare the file’s current state with its previous state to detect modifications.
   
3. **Telegram Bot Notification**
   - A Telegram bot is used to send notifications to the user whenever a file is modified, deleted, or created in the monitored directory.
   - The system sends a message to a pre-configured Telegram chat when an event occurs.

#### **Step-by-Step Breakdown**

1. **Importing Required Libraries**
   - **`os`**: For interacting with the operating system to handle file and directory paths.
   - **`time`**: To add delays and control the flow of the program.
   - **`hashlib`**: To compute SHA-256 hashes for files, ensuring integrity checks.
   - **`requests`**: To send HTTP requests to the Telegram Bot API for sending alerts.
   - **`watchdog.observers` and `watchdog.events`**: To observe directory changes and handle events when changes are detected.

2. **Defining the Telegram Bot Details**
   - The `TELEGRAM_TOKEN` is the unique token for the Telegram bot (which is used to authenticate API requests).
   - The `CHAT_ID` is the ID of the Telegram chat or group where the alerts will be sent.

```python
TELEGRAM_TOKEN = "7654403196:AAFXA6awlVLWRJG3r02SxvAXtZml8nwk378"  # Replace with your Telegram Bot Token
CHAT_ID = "1394740459"  # Replace with your Telegram Chat ID
```

3. **Directory to Monitor**
   - `MONITORED_DIR` specifies the directory path where the system will watch for file changes. 
   - In this case, it's a folder on the local machine: `"C:\Users\Deepak Kumar\Documents\test_folder"`.
   - **Note**: Use `r` before the string (`r"directory_path"`) to treat the backslashes as raw characters.

```python
MONITORED_DIR = r"C:\Users\Deepak Kumar\Documents\test_folder"  # Set your folder to monitor
```

4. **File Hash Calculation**
   - **Why hashing?** The SHA-256 hash uniquely represents the content of a file. When a file is modified, its hash changes, allowing us to detect changes.
   - **How it works**:
     - The file is opened and read in chunks of 4096 bytes.
     - SHA-256 hash is computed on each chunk of data.
     - The final hash is returned as a hexadecimal string.

```python
def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of the file"""
    hash_sha256 = hashlib.sha256()  # Initialize SHA-256 hashing algorithm
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):  # Read the file in chunks
            hash_sha256.update(chunk)  # Update the hash with the chunk of data
    return hash_sha256.hexdigest()  # Return the final SHA-256 hash as a hexadecimal string
```

5. **Sending Alerts via Telegram**
   - The `send_telegram_alert` function uses the Telegram Bot API to send messages to a Telegram chat whenever a file is modified, created, or deleted.
   - **How it works**:
     - A POST request is made to the Telegram Bot API endpoint using `requests.post`.
     - The bot token and chat ID are included in the payload.

```python
def send_telegram_alert(message):
    """Send a message via Telegram Bot"""
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"  # Telegram API endpoint
    payload = {
        "chat_id": CHAT_ID,  # Chat ID where the message is sent
        "text": message  # Message content
    }
    requests.post(url, data=payload)  # Send the POST request
```

6. **File Monitoring Event Handler**
   - **Watchdog's Role**: The `watchdog` library observes file system events in the monitored directory.
   - **FileMonitorHandler Class**:
     - It handles the events when files are modified, created, or deleted.
     - For each event (modification, creation, deletion), the system calculates the file hash and compares it with the previous hash stored in memory.
     - **Events Handled**:
       - **On modification**: The system compares the current hash with the stored hash. If they differ, an alert is sent.
       - **On creation**: The system calculates the hash of the new file and stores it.
       - **On deletion**: The system removes the file's hash from memory and sends a delete alert.

```python
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
```

7. **Monitoring the Directory**
   - **Observer**: An `Observer` instance from the `watchdog` library is used to monitor the directory.
   - **Event Handler**: The `FileMonitorHandler` instance listens for changes in the directory and triggers events.
   - The program runs indefinitely, monitoring changes, and you can exit by interrupting the process (Ctrl + C).

```python
def monitor_directory():
    """Start the file monitoring system"""
    event_handler = FileMonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, MONITORED_DIR, recursive=False)
    observer.start()
    print(f"Monitoring changes in: {MONITORED_DIR}")
    try:
        while True:
            time.sleep(1)  # Keep the program running
    except KeyboardInterrupt:
        observer.stop()  # Stop monitoring if user interrupts
    observer.join()  # Wait for the observer to finish
```

8. **Running the Program**
   - When you run the program (`python file_integrity_monitor.py`), it will continuously monitor the specified directory for file system changes.
   - **Output**: When a file is modified, created, or deleted, the system will output a message in the console and send a Telegram alert.

```python
if __name__ == "__main__":
    monitor_directory()  # Start monitoring the directory
```

### **Key Features**
- **Real-time Monitoring**: The system actively watches a specified directory for any file changes.
- **File Integrity Check**: The system uses SHA-256 hashes to check for file modifications and ensures that no unauthorized changes have been made.
- **Telegram Alerts**: Upon detecting a file modification, creation, or deletion, the system sends an alert to the user via Telegram, providing a real-time notification.

### **Conclusion**
This project is a robust solution for file integrity monitoring. It uses Python libraries (`watchdog` for monitoring, `hashlib` for hashing, `requests` for sending alerts) to create a secure file monitoring system. By integrating Telegram alerts, the user is instantly notified whenever there is an unauthorized or unexpected change to the monitored files.

