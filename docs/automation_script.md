# Integration Setup Script

This Bash script automates the setup of an integration environment, including checking dependencies, creating a Python virtual environment, installing necessary packages, and ensuring all required files and folders are present in a specified target directory.

## Features

- Prompts user for integration directory (default: `/var/ossec/integrations`)
- Checks for required tools: `python3`, `pip`, and `python3-venv`
- Automatically installs missing dependencies using the system's package manager
- Creates and configures a Python virtual environment
- Installs Python dependencies from `requirements.txt`
- Moves missing files and folders to the target integration directory with appropriate permissions
- Provides cleanup in case of failure or optional removal of the original setup directory

## Usage

1. **Clone the repository** and place the necessary files and folders into a single directory.

2. The directory should contain the following **folders**:
   - `env-files`
   - `log-files`
   - `extra-files`

   And the following **files**:
   - `custom_errors.py`
   - `env_handler.py`
   - `log_monitor.py`
   - `logger.py`
   - `slack_handler.py`
   - `smtp_handler.py`
   - `wazuh_api_handler.py`
   - `monitor_log_counter.sh`
   - `requirements.txt`
   - `setup_log_counter.sh` (this script)

3. **Transfer the directory** to your target machine, example for Linux machines you can use a tool like **WinSCP**.

4. On the Linux machine, make the script executable and run it:

```bash
chmod +x setup_log_counter.sh
sudo ./setup_log_counter.sh
```

## Post-Setup Cron Configuration

After the script finishes executing, configure the following cronjobs to automate agent list updates and script monitoring:

1. **Edit the crontab file:**

```bash
crontab -e
```

2. **Add the following lines to schedule tasks:**

```cron
# To refresh agent list every hour at minute 59
59 * * * * /var/ossec/bin/agent_control -l | grep -oP 'ID:\s*(\d+),\s*Name:\s*([^,]+)' | sed 's/ID:\s*\(.*\),\s*Name:\s*\(.*\)/\1,\2/' > /var/ossec/integrations/extra-files/agents.txt

# Run the log monitor script every 15 minutes
*/15 * * * * /var/ossec/integrations/monitor_log_counter.sh

# Run the log monitor script at system reboot
@reboot /var/ossec/integrations/monitor_log_counter.sh
```

---