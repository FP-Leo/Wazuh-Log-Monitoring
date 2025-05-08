#!/bin/bash

# Config
SCRIPT_NAME="monitor_log_counter.sh"
LOG_FILE="/var/ossec/integrations/log-files/log_monitoring.log"
TARGET_SCRIPT="log_monitor.py"
PYTHON_PATH="/var/ossec/integrations/venv/bin/python"
SCRIPT_PATH="/var/ossec/integrations/log_monitor.py"
TIMESTAMP=$(date "+%Y/%m/%d %H:%M:%S")
CATEGORY="INFO"

# By default crontab runs in the home directory of the user executing it
# Change to the directory where the script is located
cd /var/ossec/integrations/ || exit 1

# Check if rint_log_counter.py is running (ignore grep and this script itself)
if ! pgrep -f "$TARGET_SCRIPT" | grep -v $$ > /dev/null; then
    echo "$TIMESTAMP ${SCRIPT_NAME}: ${CATEGORY} - $TARGET_SCRIPT not running. Starting..." >> "$LOG_FILE"
    nohup "$PYTHON_PATH" "$SCRIPT_PATH" >> "$LOG_FILE" 2>&1 &
fi
