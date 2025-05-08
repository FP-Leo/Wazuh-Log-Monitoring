````markdown
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

Save the script as `setup.sh`, make it executable, and run it:

```bash
chmod +x setup.sh
sudo ./setup.sh
```

## Script Code

<details>
<summary>Click to expand full script</summary>

```bash
#!/bin/bash

# Set ORIGINAL_DIR to the directory the script is located in
ORIGINAL_DIR=$(dirname "$(realpath "$0")")

# Integration directory (will be set by user input)
INTEGRATIONS_DIR=""

# Lists to track added directories and files for cleanup
DIRS_ADDED=()
FILES_ADDED=()

# Flags to track installed components
PYTHON_INSTALLED=false
PIP_INSTALLED=false
VENV_INSTALLED=false
VENV_CREATED=false

# Function to get user input for the integration directory
get_input() {
    read -p "Enter the path of the directory you want to set up in [default - /var/ossec/integrations]: " USER_INPUT
    INTEGRATIONS_DIR="${USER_INPUT:-/var/ossec/integrations}"
}

# Function to check if the integration directory exists
check_integrations_dir() {
    if [ ! -d "$INTEGRATIONS_DIR" ]; then
        echo "$INTEGRATIONS_DIR does not exist. Exiting the script."
        exit 1
    fi

    if [ ! -w "$INTEGRATIONS_DIR" ]; then
        echo "Error: Cannot write to $INTEGRATIONS_DIR. Permission denied."
        exit 1
    fi
}

# Function to install a package using the appropriate package manager
install_package() {
    local package_name=$1

    # Detect and construct install command based on package manager
    if command -v apt >/dev/null 2>&1; then
        echo "Using apt package manager."
        INSTALL_COMMAND="apt install $package_name"
    elif command -v yum >/dev/null 2>&1; then
        echo "Using yum package manager."
        INSTALL_COMMAND="yum install $package_name"
    elif command -v dnf >/dev/null 2>&1; then
        echo "Using dnf package manager."
        INSTALL_COMMAND="dnf install $package_name"
    elif command -v zypper >/dev/null 2>&1; then
        echo "Using zypper package manager."
        INSTALL_COMMAND="zypper install $package_name"
    elif command -v brew >/dev/null 2>&1; then
        echo "Using brew package manager."
        INSTALL_COMMAND="brew install $package_name"
    else
        echo "No supported package manager found. Please install $package_name manually."
        exit 1
    fi

    echo "Installing $package_name..."
    if ! eval "$INSTALL_COMMAND"; then
        echo "Failed to install $package_name."
        cleanup
        exit 1
    else
        echo "$package_name installed successfully."
    fi
}

# (continued...)

# The rest of the script follows the same structure:
# - install_python
# - install_pip
# - install_venv
# - setup_venv
# - activate_and_install_requirements
# - move_missing_files
# - check_and_move_folder
# - check_required_folders
# - check_required_files
# - remove_installed
# - cleanup
# - post_setup_cleanup
# - main

# Entry point
main() {
    get_input
    check_integrations_dir
    install_python
    install_pip
    install_venv
    setup_venv
    activate_and_install_requirements
    check_required_folders
    check_required_files
    post_setup_cleanup
}

main
```

</details>

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
*/15 * * * * /var/ossec/integrations/monitor_rint_log_counter.sh

# Run the log monitor script at system reboot
@reboot /var/ossec/integrations/monitor_rint_log_counter.sh
```

---