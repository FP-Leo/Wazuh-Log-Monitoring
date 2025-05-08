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

# Function to install Python 3
install_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        echo "Python3 not found. Installing..."
        install_package python3
        PYTHON_INSTALLED=true
    else
        echo "Python3 is already installed."
    fi
}

# Function to install pip
install_pip() {
    if ! command -v pip3 >/dev/null 2>&1 && ! command -v pip >/dev/null 2>&1; then
        echo "pip not found. Installing..."
        install_package python3-pip
        PIP_INSTALLED=true
    else
        echo "pip is already installed."
    fi
}

# Function to install python3-venv
install_venv() {
    if ! python3 -m venv --help >/dev/null 2>&1; then
        echo "python3-venv not found. Installing..."
        install_package python3-venv
        VENV_INSTALLED=true
    else
        echo "python3-venv is already available."
    fi
}

# Function to set up the virtual environment
setup_venv() {
    echo "Setting up virtual environment in $INTEGRATIONS_DIR/venv..."

    if ! python3 -m venv "$INTEGRATIONS_DIR/venv"; then
        echo "Failed to create virtual environment."
        cleanup
        exit 1
    fi

    VENV_CREATED=true
    DIRS_ADDED+=("$INTEGRATIONS_DIR/venv")  # Track the created directory
    echo "Virtual environment created successfully."
}

# Function to activate venv and install requirements
activate_and_install_requirements() {
    VENV_PATH="$INTEGRATIONS_DIR/venv"

    if [ ! -d "$VENV_PATH" ]; then
        echo "Virtual environment not found."
        cleanup
        exit 1
    fi

    source "$VENV_PATH/bin/activate"
    echo "Virtual environment activated."

    if ! command -v pip &> /dev/null; then
        echo "pip not found in venv. Downloading get-pip.py..."
        curl -sS https://bootstrap.pypa.io/get-pip.py -o get-pip.py
        if [ ! -f get-pip.py ]; then
            echo "Download failed."
            deactivate
            cleanup
            exit 1
        fi

        echo "Installing pip..."
        python get-pip.py
        rm get-pip.py
    fi

    echo "pip is available in venv."

    if [ -f "$ORIGINAL_DIR/requirements.txt" ]; then
        echo "Installing dependencies from requirements.txt..."
        if ! pip install -r "$ORIGINAL_DIR/requirements.txt"; then
            echo "Dependency installation failed."
            deactivate
            cleanup
            exit 1
        fi
    else
        echo "No requirements.txt found. Skipping installation."
    fi

    deactivate
}

# Function to check and move missing files from the original directory to the integration directory
move_missing_files() {
    original_folder="$1"
    integration_folder="$2"

    echo "Checking for missing files in $integration_folder compared to $original_folder..."

    for file in "$original_folder"/*; do
        filename=$(basename "$file")

        if [ ! -f "$integration_folder/$filename" ]; then
            echo "File $filename is missing in $integration_folder. Moving it from original directory..."
            mv "$file" "$integration_folder/"

            # Apply chmod 600 to the file
            chmod 600 "$integration_folder/$filename"
            # Set ownership to root:root
            chmod root:root "$integration_folder/$filename"  

            FILES_ADDED+=("$integration_folder/$filename")  # Track the created file
        fi
    done

    echo "File check and move complete."
}

# Helper function to check and move folders
check_and_move_folder() {
    original_folder="$1"
    integration_folder="$2"
    folder_name="$3"

    if [ ! -d "$integration_folder" ]; then
        echo "$folder_name folder not found in $INTEGRATIONS_DIR. Moving from original directory..."
        mv "$original_folder" "$INTEGRATIONS_DIR/"
        DIRS_ADDED+=("$INTEGRATIONS_DIR/$folder_name")  # Track the created directory
        echo "Moved $folder_name to $INTEGRATIONS_DIR"

        # Apply chmod 600 to all files inside the newly moved folder
        find "$INTEGRATIONS_DIR/$folder_name" -type f -exec chmod 600 {} \;
        # Set ownership to root:root
        chown -R root:root "$INTEGRATIONS_DIR/$folder_name"
    else
        echo "Found: $folder_name"
        move_missing_files "$original_folder" "$integration_folder"

        # Ensure all files inside the folder have the correct permissions
        find "$integration_folder" -type f -exec chmod 600 {} \;
    fi
}

# Function to check for required folders in the original directory
check_required_folders() {
    echo "Checking for required folders in $INTEGRATIONS_DIR..."

    for folder in "$ORIGINAL_DIR"/*/; do
        folder_name=$(basename "$folder")

        # Skip the setup directory if needed
        if [[ "$folder_name" == "$(basename "$SCRIPT_DIR")" ]]; then
            continue
        fi

        src="$ORIGINAL_DIR/$folder_name"
        dest="$INTEGRATIONS_DIR/$folder_name"

        check_and_move_folder "$src" "$dest" "$folder_name"
    done

    echo "Folder check complete."
}

check_required_files() {
    echo "Checking for integration files in $ORIGINAL_DIR..."

    for FILE_PATH in "$ORIGINAL_DIR"/*; do
        FILE_NAME=$(basename "$FILE_PATH")

        # Skip if it's the setup script itself
        if [[ "$FILE_NAME" == "$(basename "$0")" ]]; then
            continue
        fi

        # Skip requirements.txt file
        if [[ "$FILE_NAME" == "requirements.txt" ]]; then
            continue
        fi

        # Skip non-files (e.g., directories)
        if [[ ! -f "$FILE_PATH" ]]; then
            continue
        fi

        TARGET_PATH="$INTEGRATIONS_DIR/$FILE_NAME"

        # Move the file if it doesn't already exist in the target directory
        if [[ ! -f "$TARGET_PATH" ]]; then
            echo "Moving $FILE_NAME to $INTEGRATIONS_DIR..."
            mv "$FILE_PATH" "$TARGET_PATH"

            # Apply special permissions if the file name contains "log_counter"
            if [[ "$FILE_NAME" == *log_counter* ]]; then
                chmod 740 "$TARGET_PATH"
            else
                chmod 640 "$TARGET_PATH"
            fi

            FILES_ADDED+=("$TARGET_PATH")  # Track moved file for cleanup
        else
            echo "$FILE_NAME already exists in $INTEGRATIONS_DIR"
        fi
    done
}


remove_installed() {
    local package_name=$1
    local installed_flag=$2

    if [[ "${!installed_flag}" == true ]]; then
        echo "Removing installed package: $package_name"

        if command -v apt >/dev/null 2>&1; then
            apt remove "$package_name"
        elif command -v yum >/dev/null 2>&1; then
            yum remove "$package_name"
        elif command -v dnf >/dev/null 2>&1; then
            dnf remove "$package_name"
        elif command -v zypper >/dev/null 2>&1; then
            zypper remove "$package_name"
        elif command -v brew >/dev/null 2>&1; then
            brew uninstall "$package_name"
        else
            echo "No supported package manager found. Cannot uninstall $package_name automatically."
        fi
    fi
}


# Function to clean up all added directories and files
cleanup() {
    echo "Cleanup process started."

    # Clean up directories
    for DIR in "${DIRS_ADDED[@]}"; do
        echo "Removing directory: $DIR"
        rm -r "$DIR"
    done

    # Clean up files
    for FILE in "${FILES_ADDED[@]}"; do
        echo "Removing file: $FILE"
        rm "$FILE"
    done

    # Remove python, pip and env if they were installed by this script
    remove_installed python3 PYTHON_INSTALLED # too dangerous to remove python3
    remove_installed pip PIP_INSTALLED
    remove_installed python3-venv VENV_INSTALLED

    echo "Cleanup complete."
    exit 1
}

# Function to remove the original directory after setup
post_setup_cleanup() {
    echo "Post-setup cleanup:"

    read -r -p "Do you want to remove the original directory \"$ORIGINAL_DIR\"? [Y/n] " response
    response=${response:-Y}
    if [[ "$response" =~ ^[Yy]$ ]]; then
        rm -r "$ORIGINAL_DIR"
        echo "Original directory removed."
    else
        echo "Original directory not removed."
    fi
}

# Run the setup process
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
