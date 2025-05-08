## 🛠️ `monitor_log_counter.sh`

This Bash script is designed to ensure the `log_monitor.py` script is always running. It is intended to be scheduled via `cron` to run periodically (e.g., every minute), acting as a lightweight watchdog process.

### 📁 Script Location

`/var/ossec/integrations/monitor_log_counter.sh`

---

### ⚙️ Functionality

* Checks whether the `log_monitor.py` script is running.
* If not, logs the incident and starts it using the specified Python interpreter.
* Redirects stdout and stderr of the Python script to the same log file.

---

### 🔧 Configuration

| Variable        | Description                                                     |
| --------------- | --------------------------------------------------------------- |
| `SCRIPT_NAME`   | Name of this watchdog script                                    |
| `LOG_FILE`      | Path to the log file for monitoring events                      |
| `TARGET_SCRIPT` | Name of the Python script to monitor                            |
| `PYTHON_PATH`   | Full path to the Python binary used to run the monitored script |
| `SCRIPT_PATH`   | Full path to the Python script to be monitored                  |
| `CATEGORY`      | Log category (default: `INFO`)                                  |
| `TIMESTAMP`     | Timestamp added to each log entry                               |

---

### 🕒 Example Crontab Entry

To run this watchdog every minute:

```bash
* * * * * /var/ossec/integrations/monitor_log_counter.sh
```

---

### 📋 Log Output Example

When the monitored script is not running:

```
2025/05/08 14:02:01 monitor_log_counter.sh: INFO - log_monitor.py not running. Starting...
```

---

### 📎 Notes

* This script uses `pgrep -f` to search for the script in the process list.
* `grep -v $$` avoids matching itself in the process list.
* `nohup` ensures the script stays running even after the cron job exits.

---
