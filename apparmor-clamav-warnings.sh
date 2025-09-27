#!/bin/bash

# ==============================================================================
# SCRIPT CONFIGURATION
# ==============================================================================

# ANSI color codes for readable output
RED='\033[0;31m'
GREEN='\033;32m'
YELLOW='\033;0;33m'
BLUE='\033;34m'
NC='\033[0m' # No Color

# Path to the ClamAV log files
CLAMD_LOG="/var/log/clamav/clamd.log"
CLAMSCAN_LOG="/var/log/clamav/clamscan.log"

# Path to the service and timer files
SERVICE_FILE="/etc/systemd/system/apparmor-clamav-warnings.service"
TIMER_FILE="/etc/systemd/system/apparmor-clamav-warnings.timer"

# User for notifications and scans
USER="ppk"

# Paths to monitor
MONITORED_PATHS=(
    "/home/ppk"
    "/srv"
    "/var/www/html"
)

# EICAR test file path
EICAR_PATH="/home/$USER/script/eicar_test.txt"

# ==============================================================================
# FUNCTIONS
# ==============================================================================

# Function to check for and install a package
install_package() {
    local pkg_name="$1"
    echo -e "${YELLOW}The '$pkg_name' command is not found. Attempting to install it...${NC}"
    if [ -f /etc/arch-release ]; then
        sudo pacman -S --noconfirm "$pkg_name" || { echo -e "${RED}Failed to install $pkg_name!${NC}"; return 1; }
    elif [ -f /etc/debian_version ]; then
        sudo apt-get update && sudo apt-get install -y "$pkg_name" || { echo -e "${RED}Failed to install $pkg_name!${NC}"; return 1; }
    elif [ -f /etc/redhat-release ]; then
        sudo yum install -y "$pkg_name" || { echo -e "${RED}Failed to install $pkg_name!${NC}"; return 1; }
    else
        echo -e "${RED}ERROR: Unable to determine the package manager. Please install '$pkg_name' manually.${NC}"
        return 1
    fi
    echo -e "${GREEN}'$pkg_name' has been installed successfully.${NC}"
    return 0
}

# Function to send a desktop notification
send_notification() {
    local title="$1"
    local message="$2"
    echo -e "${BLUE}Sending notification: $title - $message${NC}"
    if ! command -v dunstify &> /dev/null; then
        echo -e "${RED}ERROR: dunstify is not installed. Cannot send notification.${NC}"
        return 1
    fi
    sudo -u "$USER" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u "$USER")/bus dunstify -u critical -t 15000 "$title" "$message" || {
        echo -e "${RED}ERROR: Failed to send notification. Check dunst service and user session.${NC}"
        return 1
    }
}

# Function to check if a package is installed and optionally install it
check_and_install_package() {
    local package_name="$1"
    if ! command -v "$package_name" &> /dev/null; then
        echo -e "${YELLOW}The '$package_name' command is not found. Do you want to install it now? (Y/n)${NC}"
        read -r -t 15 -e -i "Y" user_response
        user_response=${user_response:-"Y"}

        if [[ "$user_response" =~ ^[Yy]$ ]]; then
            install_package "$package_name" || {
                echo -e "${RED}Failed to install $package_name. Exiting.${NC}"
                exit 1
            }
        else
            echo -e "${YELLOW}User chose not to install $package_name. Continuing without it.${NC}"
        fi
    fi
}

# Function to set up the systemd service and timer
setup_systemd() {
    echo -e "${BLUE}Setting up systemd service and timer for weekly execution...${NC}"
    sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=AppArmor and ClamAV Warning Checker and Weekly Scan
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash $(realpath "$0")
User=$USER
EOF

    sudo tee "$TIMER_FILE" > /dev/null <<EOF
[Unit]
Description=Run AppArmor and ClamAV warning checker and scan weekly

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
EOF

    sudo systemctl daemon-reload || { echo -e "${RED}Failed to reload systemd daemon!${NC}"; return 1; }
    sudo systemctl enable --now apparmor-clamav-warnings.timer || { echo -e "${RED}Failed to enable timer!${NC}"; return 1; }
    echo -e "${GREEN}Systemd service and timer have been set up and activated for weekly execution.${NC}"
}

# Function to configure ClamAV monitored paths
configure_monitored_paths() {
    echo -e "${YELLOW}Configuring ClamAV monitored paths in /etc/clamav/clamd.conf...${NC}"
    if [ -f /etc/clamav/clamd.conf ]; then
        # Remove existing OnAccessMountPath entries
        sudo sed -i '/^OnAccessMountPath/d' /etc/clamav/clamd.conf
        # Add monitored paths
        for path in "${MONITORED_PATHS[@]}"; do
            if findmnt "$path" > /dev/null; then
                echo -e "${RED}Warning: $path is a mountpoint and cannot be monitored by fanotify. Skipping.${NC}"
            elif [ ! -d "$path" ]; then
                echo -e "${RED}Warning: $path does not exist. Skipping.${NC}"
            else
                echo "OnAccessMountPath $path" | sudo tee -a /etc/clamav/clamd.conf > /dev/null
                echo -e "${GREEN}Added $path to on-access scanning.${NC}"
                # Set ACLs for clamav user
                sudo setfacl -R -m u:clamav:rx "$path" || { echo -e "${RED}Failed to set ACLs for $path!${NC}"; return 1; }
            fi
        done

        # Add the necessary exclusion for the clamav user to prevent infinite loops
        if ! grep -q "^OnAccessExcludeUname clamav" /etc/clamav/clamd.conf; then
            echo "OnAccessExcludeUname clamav" | sudo tee -a /etc/clamav/clamd.conf > /dev/null
            echo -e "${GREEN}Added OnAccessExcludeUname for 'clamav' user to prevent scanning loops.${NC}"
        fi

        # Ensure OnAccessPrevention is enabled
        if ! grep -q "^OnAccessPrevention yes" /etc/clamav/clamd.conf; then
            sudo sed -i 's/^#OnAccessPrevention/OnAccessPrevention yes/' /etc/clamav/clamd.conf || echo "OnAccessPrevention yes" | sudo tee -a /etc/clamav/clamd.conf > /dev/null
        fi
        # Enable verbose logging for debugging
        if ! grep -q "^LogVerbose yes" /etc/clamav/clamd.conf; then
            sudo sed -i 's/^#LogVerbose/LogVerbose yes/' /etc/clamav/clamd.conf || echo "LogVerbose yes" | sudo tee -a /etc/clamav/clamd.conf > /dev/null
        fi
        # Ensure LogFile is set
        if ! grep -q "^LogFile /var/log/clamav/clamd.log" /etc/clamav/clamd.conf; then
            sudo sed -i 's|^#LogFile.*|LogFile /var/log/clamav/clamd.log|' /etc/clamav/clamd.conf
        fi
        # Restart services
        sudo systemctl restart clamav-daemon.service || { echo -e "${RED}Failed to restart clamav-daemon!${NC}"; return 1; }
        sudo systemctl restart clamav-clamonacc.service || { echo -e "${RED}Failed to restart clamav-clamonacc!${NC}"; return 1; }
        # Ensure log file permissions
        sudo mkdir -p /var/log/clamav
        sudo touch "$CLAMD_LOG" "$CLAMSCAN_LOG"
        sudo chown clamav:clamav "$CLAMD_LOG"
        sudo chown $USER:clamav "$CLAMSCAN_LOG" # Allow ppk to write for clamscan
        sudo chmod 660 "$CLAMD_LOG" "$CLAMSCAN_LOG"
    else
        echo -e "${RED}ERROR: clamd.conf not found at /etc/clamav/clamd.conf!${NC}"
        send_notification "ClamAV Error" "clamd.conf not found. Check ClamAV configuration."
        return 1
    fi
}

# Function to check monitored paths
check_monitored_paths() {
    echo -e "${YELLOW}Checking monitored paths in /etc/clamav/clamd.conf...${NC}"
    if [ -f /etc/clamav/clamd.conf ]; then
        grep -i "OnAccessMountPath" /etc/clamav/clamd.conf > /tmp/clamav_monitored_paths.log
        if [ -s /tmp/clamav_monitored_paths.log ]; then
            echo -e "${GREEN}Monitored paths:${NC}"
            cat /tmp/clamav_monitored_paths.log
        else
            echo -e "${RED}No OnAccessMountPath entries found in clamd.conf!${NC}"
            send_notification "ClamAV Error" "No monitored paths configured in clamd.conf. On-access scanning may not work."
        fi
        rm -f /tmp/clamav_monitored_paths.log
    else
        echo -e "${RED}ERROR: clamd.conf not found at /etc/clamav/clamd.conf!${NC}"
        send_notification "ClamAV Error" "clamd.conf not found. Check ClamAV configuration."
    fi
}

# Function to update ClamAV database
update_clamav_database() {
    echo -e "${YELLOW}Updating ClamAV virus database...${NC}"
    if ! command -v freshclam &> /dev/null; then
        echo -e "${RED}ERROR: freshclam not found. Install clamav package.${NC}"
        return 1
    fi
    sudo freshclam || { echo -e "${RED}ERROR: Failed to update ClamAV database!${NC}"; send_notification "ClamAV Error" "Failed to update virus database."; return 1; }
    echo -e "${GREEN}INFO: ClamAV database updated successfully.${NC}"
}

# Function to run daily ClamAV scan on monitored paths
daily_clamav_scan() {
    echo -e "${YELLOW}Running daily ClamAV scan on monitored paths...${NC}"
    if [ -f /etc/clamav/clamd.conf ]; then
        # Read monitored paths from clamd.conf
        mapfile -t paths < <(grep -i "^OnAccessMountPath" /etc/clamav/clamd.conf | awk '{print $2}')
        if [ ${#paths[@]} -eq 0 ]; then
            echo -e "${RED}ERROR: No OnAccessMountPath entries found in clamd.conf!${NC}"
            send_notification "ClamAV Error" "No monitored paths configured for daily scan."
            return 1
        fi

        # Get exclude paths from clamd.conf
        mapfile -t exclude_paths < <(grep -i "^OnAccessExcludePath" /etc/clamav/clamd.conf | awk '{print $2}')
        exclude_args=""
        for exclude_path in "${exclude_paths[@]}"; do
            exclude_args="$exclude_args --exclude-dir=$exclude_path"
        done

        # Run clamscan on each monitored path
        for path in "${paths[@]}"; do
            if [ -d "$path" ]; then
                echo -e "${YELLOW}Scanning $path...${NC}"
                sudo -u clamav clamscan -r --debug --verbose --log="$CLAMSCAN_LOG" --max-filesize=100M --max-scansize=400M --max-recursion=15 $exclude_args "$path" > /tmp/clamscan_output.log 2>&1
                if grep -q "FOUND" /tmp/clamscan_output.log; then
                    send_notification "ClamAV Daily Scan Detection" "Malicious files found in $path. Check $CLAMSCAN_LOG for details."
                    echo -e "${RED}ALERT: ClamAV found threats in $path!${NC}"
                    cat /tmp/clamscan_output.log | sudo tee -a "$CLAMSCAN_LOG"
                elif grep -q "ERROR" /tmp/clamscan_output.log; then
                    send_notification "ClamAV Scan Error" "Errors occurred while scanning $path. Check $CLAMSCAN_LOG for details."
                    echo -e "${RED}ERROR: ClamAV scan encountered errors in $path!${NC}"
                    cat /tmp/clamscan_output.log | sudo tee -a "$CLAMSCAN_LOG"
                else
                    echo -e "${GREEN}INFO: No threats found in $path.${NC}"
                    echo "No threats found in $path" | sudo tee -a "$CLAMSCAN_LOG"
                fi
            else
                echo -e "${RED}Warning: $path does not exist or is not a directory. Skipping.${NC}"
            fi
        done
        rm -f /tmp/clamscan_output.log
    else
        echo -e "${RED}ERROR: clamd.conf not found at /etc/clamav/clamd.conf!${NC}"
        send_notification "ClamAV Error" "clamd.conf not found. Daily scan cannot proceed."
        return 1
    fi
}

# ==============================================================================
# MAIN SCRIPT EXECUTION
# ==============================================================================

# Short description at the start
echo -e "\n${GREEN}This script monitors AppArmor and ClamAV logs for security events such as warnings, detected threats, or blocked actions, and then notifies the user.${NC}\n"

# Check for setup flag
if [ "$1" == "setup" ]; then
    echo -e "${BLUE}Beginning setup process...${NC}"
    check_and_install_package "dunst"
    check_and_install_package "apparmor"
    check_and_install_package "aa-status"
    check_and_install_package "clamav"

    if ! ldconfig -p | grep -q libnotify; then
        echo -e "${RED}ERROR: libnotify is not found. Install it with: sudo pacman -S libnotify${NC}"
        exit 1
    fi
    echo -e "${GREEN}libnotify is correctly installed.${NC}"
    if ! sudo -u "$USER" systemctl --user is-active --quiet dunst.service; then
        echo -e "${YELLOW}Dunst service is not active. Attempting to start it...${NC}"
        sudo -u "$USER" systemctl --user start dunst.service
        sudo -u "$USER" systemctl --user enable dunst.service
    fi
    echo -e "${GREEN}Dunst service is active.${NC}"
    setup_systemd
    configure_monitored_paths

    echo -e "${GREEN}Verifying ClamAV services are running...${NC}"
    sudo systemctl status clamav-daemon.service | grep 'Active:'
    sudo systemctl status clamav-clamonacc.service | grep 'Active:'

    exit 0
fi

# ==============================================================================
# LOG CHECKING AND DAILY SCAN
# ==============================================================================

echo -e "${BLUE}Checking logs for warnings and detections...${NC}"

# Check for required commands
if ! command -v journalctl &> /dev/null; then
    send_notification "AppArmor Error" "journalctl not found, unable to read AppArmor logs"
    echo -e "${RED}ERROR: journalctl command not found.${NC}"
    exit 1
fi

# Check AppArmor logs
echo -e "${YELLOW}Checking AppArmor logs from the last 24 hours...${NC}"
journalctl -k --since "24 hours ago" | grep -i "apparmor.*DENIED" > /tmp/apparmor_denials.log
if [ -s /tmp/apparmor_denials.log ]; then
    send_notification "AppArmor Block" "AppArmor denials detected. Check /tmp/apparmor_denials.log for details."
    echo -e "${RED}ALERT: AppArmor denials detected!${NC}"
else
    send_notification "AppArmor Info" "No AppArmor DENIED entries found in journalctl for the last 24 hours."
    echo -e "${GREEN}INFO: No AppArmor denials found.${NC}"
fi

# Check ClamAV logs for detections
echo -e "${YELLOW}Checking ClamAV logs for detections...${NC}"
if [ -f "$CLAMD_LOG" ]; then
    sudo grep -i "FOUND" "$CLAMD_LOG" > /tmp/clamd_detections.log
    if [ -s /tmp/clamd_detections.log ]; then
        send_notification "ClamAV Virus Detection" "ClamAV found threats. Check /tmp/clamd_detections.log for details."
        echo -e "${RED}ALERT: ClamAV virus found!${NC}"
        cat /tmp/clamd_detections.log
    else
        send_notification "ClamAV Info" "No ClamAV detections found in $CLAMD_LOG."
        echo -e "${GREEN}INFO: No ClamAV detections found.${NC}"
    fi
else
    send_notification "ClamAV Error" "ClamAV log file $CLAMD_LOG not found."
    echo -e "${RED}ERROR: ClamAV log file '$CLAMD_LOG' not found.${NC}"
fi

# Run daily ClamAV scan
daily_clamav_scan

# Check monitored paths
check_monitored_paths

# Clean up temporary files
rm -f /tmp/apparmor_denials.log /tmp/clamd_detections.log

echo -e "${GREEN}Log checking and daily scan complete. Check notifications for results.${NC}"
