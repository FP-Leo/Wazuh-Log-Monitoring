# Log Monitor - Agent Log Monitoring & Alerting System

## Overview

`log_monitor` is a standalone Python monitoring script that continuously checks whether Wazuh agents are actively sending logs. If an agent stops sending logs within a specified time frame, it triggers alerts via configured communication channels: **Slack** and **SMTP email**. It also logs all operations and issues using a custom logger.

This script is ideal for teams running security monitoring via Wazuh who need real-time visibility into agent inactivity or communication issues.

---

## Features

* 🔍 **Agent Log Monitoring** via Wazuh API
* 📤 **Alert Notifications** through Slack and/or Email
* 📋 **Dynamic Scheduling** using min-heap for efficient polling
* 🛠️ **Customizable Intervals** per-agent via `.env` variables
* 🗃️ **Configurable Agent List** via external file
* 🧪 **Environment-based Configuration** for deployment flexibility
* 📁 **Comprehensive Logging** using a custom logger
* ⛔ **Graceful Error Handling & Notifications** for missing configuration or runtime issues

---

## Architecture

![LogCounter Overview](assets/logcounter.png)

```
+-------------------+
|  LogCounter Class |
+---------+---------+
          |
          +--> Loads Env Vars (via EnvHandler)
          |
          +--> Initializes Logger (via Logger)
          |
          +--> Sets Up Slack (via SlackHandler)
          |
          +--> Sets Up SMTP (via MailHandler)
          |
          +--> Connects to Wazuh API (via WazuhAPIHandler)
          |
          +--> Loads Agent List from file
          |
          +--> Monitors agents using a scheduling heap
          |
          +--> Sends notifications when logs are missing
```

---

## Environment Configuration

Create an environment file (e.g. `env-files/log_counter.env`) with the following keys:

```ini
# Required
WAZUH_URL=https://your.wazuh.server
USERNAME=your_username
PASSWORD=your_password
VERIFICATION_FILE=cert.pem
AGENT_LIST_FILE=config/agents.csv

# Optional
DEFAULT_CHECK_INTERVAL=15         # in minutes (default is 15 mins)
AGENT_CHECK_INTERVALS=001:10,002:30  # agent_id:interval (in minutes)
LOG_FILE_PATH=log-files/log_monitoring.log
LOGGING_LEVEL=1
```

---

## Agent File Format

Specify agents in a CSV-like format (no header):

```
001,Firewall-A
002,Server-B
003,Proxy-C
```

Each line: `<agent_id>,<agent_label>`

---

## Usage

1. Make the script executable (if not already):

```bash
chmod +x log_monitor.py
```

2. Run the script:

```bash
./log_monitor.py
```

Or via Python:

```bash
python3 log_monitor.py
```

---

## How It Works

* **Startup**

  * Loads environment variables using `EnvHandler`.
  * Sets up logger, Slack, and SMTP clients.
  * Authenticates with the Wazuh API.
  * Loads agents from the file.

* **Monitoring Loop**

  * Uses a **min-heap** to schedule checks per agent.
  * Fetches log data from Wazuh for each agent using time-based queries.
  * If **no logs are received**, notifies via Slack or Email.
  * Uses exponential backoff logic to avoid spam.
  * Reschedules agents for the next check.

* **Failure Handling**

  * Logs all issues.
  * Notifies if any part of the setup fails.
  * Gracefully continues or exits when critical configurations are missing.

---

## Dependencies

Make sure these modules are available in your project:

* `logger.py` (custom Logger) — Custom logging utility for categorized logs.
* `slack_handler.py` (SlackHandler) — Sends Slack alerts via webhook.
* `smtp_handler.py` (MailHandler) — Sends alert emails via SMTP.
* `env_handler.py` (EnvHandler) — Loads environment variables from file.
* `wazuh_api_handler.py` (WazuhAPIHandler) — Handles authentication and queries to Wazuh API.
* `custom_errors.py` (Custom exceptions) — Contains custom exception classes for error handling.

For detailed documentation of each module and its methods, see [docs/modules.md](docs/modules.md).

---

## Installation

Install the required dependencies with:

```bash
pip install -r requirements.txt
```

---

## Notes

* All alerting logic falls back to email if Slack fails.
* Agent check frequency is flexible per agent.
* Designed for cron or daemonized use, though restart-based interval refresh is baked in (hourly loop reset).
* Make sure the Wazuh API is reachable and the cert file is valid.

---
