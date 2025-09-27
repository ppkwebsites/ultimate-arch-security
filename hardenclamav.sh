#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Define color codes for a more readable output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Debug log file with timestamp to avoid overwriting
DEBUG_LOG="/home/$SUDO_USER/tmp/clamav_hardening_debug_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "/home/$SUDO_USER/tmp"
echo "ClamAV Hardening Script started at $(date)" > "$DEBUG_LOG"

echo -e "${YELLOW}Starting ClamAV hardening script...${NC}"

# Check if running with sudo and SUDO_USER is set
if [ -z "$SUDO_USER" ]; then
    echo -e "${RED}Error: This script must be run with sudo by a non-root user (SUDO_USER not set). Exiting.${NC}" | tee -a "$DEBUG_LOG"
    exit 1
fi

# Function to prompt for user input with strict validation
prompt_user() {
    local prompt_message="$1"
    local reply_var_name="$2"
    local reply
    echo -e "\n${RED}*** ATTENTION: SCRIPT REQUIRES INPUT ***${NC}" | tee -a "$DEBUG_LOG"
    while true; do
        read -p "$prompt_message" -n 1 -r reply
        echo "" # Move to a new line
        echo "User input for '$prompt_message': $reply" >> "$DEBUG_LOG"
        if [[ -z "$reply" ]]; then
            reply="y"
            echo "y" # Echo default choice for clarity
        fi
        if [[ $reply =~ ^[YyNn]$ ]]; then
            break
        else
            echo -e "${RED}Invalid input. Please enter 'y' or 'n'.${NC}" | tee -a "$DEBUG_LOG"
        fi
    done
    printf -v "$reply_var_name" "%s" "$reply"
}

# Function to log debug messages
log_debug() {
    echo "[DEBUG] $1" >> "$DEBUG_LOG"
}

# --- Step 1: Update the system ---
echo -e "\n${YELLOW}Step 1: Updating system packages...${NC}" | tee -a "$DEBUG_LOG"
prompt_user "Do you want to update the system packages? (Y/n): " update_reply
if [[ $update_reply =~ ^[Yy]$ ]]; then
    sudo pacman -Syu || { echo -e "${RED}Error: System update failed. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
    log_debug "System update completed successfully."
else
    echo -e "${YELLOW}Skipping system update.${NC}" | tee -a "$DEBUG_LOG"
fi

# --- Step 2: Check for and install Yay if needed ---
echo -e "\n${YELLOW}Step 2: Checking for Yay (AUR helper)...${NC}" | tee -a "$DEBUG_LOG"
if ! command -v yay &> /dev/null; then
    echo -e "${YELLOW}Yay not found. Installing it for future use.${NC}" | tee -a "$DEBUG_LOG"
    prompt_user "Do you want to install Yay? (Y/n): " yay_install_reply
    if [[ $yay_install_reply =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}Proceeding with Yay installation...${NC}" | tee -a "$DEBUG_LOG"
        sudo pacman -S --needed git base-devel || { echo -e "${RED}Error: Failed to install git and base-devel. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
        TEMP_DIR=$(mktemp -d)
        git clone https://aur.archlinux.org/yay.git "$TEMP_DIR" || { echo -e "${RED}Error: Failed to clone Yay repository. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
        cd "$TEMP_DIR" || { echo -e "${RED}Error: Failed to change to $TEMP_DIR. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
        sudo -u "$SUDO_USER" makepkg -si --noconfirm || { echo -e "${RED}Error: Failed to build and install Yay. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
        cd - || { echo -e "${RED}Error: Failed to return to original directory. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
        rm -rf "$TEMP_DIR"
        echo -e "${GREEN}Yay has been installed.${NC}" | tee -a "$DEBUG_LOG"
    else
        echo -e "${YELLOW}Skipping Yay installation.${NC}" | tee -a "$DEBUG_LOG"
    fi
else
    echo -e "${GREEN}Yay is already installed. Excellent!${NC}" | tee -a "$DEBUG_LOG"
fi

# --- Step 3: Install ClamAV and Fangfrisch ---
echo -e "\n${YELLOW}Step 3: Installing ClamAV and Fangfrisch...${NC}" | tee -a "$DEBUG_LOG"
prompt_user "Do you want to install ClamAV and Fangfrisch? (Y/n): " install_clamav_reply
if [[ $install_clamav_reply =~ ^[Yy]$ ]]; then
    # Install clamav from official repositories (requires sudo)
    sudo pacman -S --needed clamav || { echo -e "${RED}Error: Failed to install ClamAV. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
    # Install python-fangfrisch from AUR (run as non-root user)
    sudo -u "$SUDO_USER" yay -S --needed --noconfirm python-fangfrisch || { echo -e "${RED}Error: Failed to install Fangfrisch. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
    # Check if ClamAV is installed
    if ! command -v clamd &>/dev/null; then
        echo -e "${RED}Error: ClamAV not installed properly. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"
        exit 1
    fi
    # Check if clamonacc is available
    if ! command -v clamonacc &>/dev/null; then
        echo -e "${RED}Error: clamonacc binary not found. On-access scanning is not supported. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"
        exit 1
    fi
    # Check if Fangfrisch is installed
    fangfrisch_installed=0
    if command -v fangfrisch &>/dev/null; then
        fangfrisch_installed=1
        log_debug "python-fangfrisch installed."
    else
        echo -e "${RED}Error: Fangfrisch not installed properly. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"
        exit 1
    fi
else
    echo -e "${YELLOW}Skipping ClamAV and Fangfrisch installation. Exiting script.${NC}" | tee -a "$DEBUG_LOG"
    exit 0
fi

# --- Step 4: Configure Fangfrisch ---
if [[ $fangfrisch_installed -eq 1 ]]; then
    echo -e "\n${YELLOW}Step 4: Configuring Fangfrisch...${NC}" | tee -a "$DEBUG_LOG"
    # Create Fangfrisch configuration directory
    sudo mkdir -p /etc/fangfrisch || { echo -e "${RED}Error: Failed to create /etc/fangfrisch. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
    # Create config file only if it doesn't exist
    if [[ ! -f /etc/fangfrisch/fangfrisch.conf ]]; then
        sudo tee /etc/fangfrisch/fangfrisch.conf > /dev/null <<EOF
[DEFAULT]
db_path = /var/lib/clamav
log_path = /var/log/fangfrisch.log
enabled = yes
check_interval = 5400

[sanesecurity]
enabled = yes
url = https://sanesecurity1.clamav.net
EOF
        log_debug "Fangfrisch configuration file created."
    else
        echo -e "${YELLOW}Fangfrisch configuration file already exists, skipping creation.${NC}" | tee -a "$DEBUG_LOG"
    fi
    # Set permissions for Fangfrisch
    sudo touch /var/log/fangfrisch.log
    sudo chown -R clamav:clamav /var/lib/clamav /var/log/fangfrisch.log || { echo -e "${RED}Error: Failed to set ownership for Fangfrisch files. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
    sudo chmod 750 /var/lib/clamav || { echo -e "${RED}Error: Failed to set permissions for /var/lib/clamav. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
    sudo chmod 640 /var/log/fangfrisch.log || { echo -e "${RED}Error: Failed to set permissions for /var/log/fangfrisch.log. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
    # Add user to clamav group
    sudo usermod -a -G clamav "$SUDO_USER" || { echo -e "${RED}Error: Failed to add user to clamav group. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
    # Initialize Fangfrisch database if not already initialized
    if ! sudo -u clamav fangfrisch --conf /etc/fangfrisch/fangfrisch.conf initdb 2>/dev/null; then
        echo -e "${YELLOW}Fangfrisch database already initialized, skipping initdb.${NC}" | tee -a "$DEBUG_LOG"
    else
        log_debug "Fangfrisch database initialized."
    fi
    # Run initial Fangfrisch update
    sudo -u clamav fangfrisch --conf /etc/fangfrisch/fangfrisch.conf refresh || { echo -e "${RED}Error: Fangfrisch initial update failed. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
    # Enable and start Fangfrisch timer
    if ! systemctl is-enabled --quiet fangfrisch.timer; then
        sudo systemctl enable --now fangfrisch.timer || { echo -e "${RED}Error: Failed to enable/start fangfrisch.timer. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
        log_debug "fangfrisch.timer enabled and started."
    else
        echo -e "${GREEN}fangfrisch.timer already enabled.${NC}" | tee -a "$DEBUG_LOG"
    fi
    if ! systemctl is-active --quiet fangfrisch.timer; then
        echo -e "${RED}Error: fangfrisch.timer is not active. Check 'sudo systemctl status fangfrisch.timer' and $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"
        exit 1
    fi
    log_debug "Fangfrisch configured and timer enabled for automatic updates."
else
    echo -e "${YELLOW}Skipping Fangfrisch configuration (package not installed).${NC}" | tee -a "$DEBUG_LOG"
fi

# --- Step 5: Configure and start ClamAV services ---
echo -e "\n${YELLOW}Step 5: Configuring and starting ClamAV services...${NC}" | tee -a "$DEBUG_LOG"
# Ensure log directory and file permissions
sudo mkdir -p /var/log/clamav || { echo -e "${RED}Error: Failed to create /var/log/clamav. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
sudo chown clamav:clamav /var/log/clamav || { echo -e "${RED}Error: Failed to set ownership for /var/log/clamav. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
sudo chmod 750 /var/log/clamav || { echo -e "${RED}Error: Failed to set permissions for /var/log/clamav. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
sudo touch /var/log/clamav/freshclam.log /var/log/clamav/clamd.log /var/log/clamav/clamonacc.log || { echo -e "${RED}Error: Failed to create log files. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
sudo chown clamav:clamav /var/log/clamav/{freshclam.log,clamd.log,clamonacc.log} || { echo -e "${RED}Error: Failed to set ownership for log files. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
sudo chmod 640 /var/log/clamav/{freshclam.log,clamd.log,clamonacc.log} || { echo -e "${RED}Error: Failed to set permissions for log files. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
echo -e "${YELLOW}Log directory and files setup complete:${NC}" | tee -a "$DEBUG_LOG"
ls -l /var/log/clamav/{freshclam.log,clamd.log,clamonacc.log} >> "$DEBUG_LOG"

# Setup logrotate for ClamAV logs
echo -e "${YELLOW}Configuring logrotate for ClamAV logs...${NC}" | tee -a "$DEBUG_LOG"
sudo mkdir -p /etc/logrotate.d || { echo -e "${RED}Error: Failed to create /etc/logrotate.d. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
# Check if logrotate config is sufficient
if [[ ! -f /etc/logrotate.d/clamav ]] || ! grep -q "clamonacc.log" /etc/logrotate.d/clamav; then
    sudo tee /etc/logrotate.d/clamav > /dev/null <<EOF
/var/log/clamav/clamd.log {
    rotate 12
    weekly
    compress
    delaycompress
    missingok
    notifempty
    create 640 clamav clamav
    postrotate
        /bin/kill -HUP \`cat /run/clamav/clamd.pid 2>/dev/null\` 2> /dev/null || true
    endscript
}
/var/log/clamav/freshclam.log {
    rotate 12
    weekly
    compress
    delaycompress
    missingok
    notifempty
    create 640 clamav clamav
    postrotate
        /bin/kill -HUP \`cat /run/clamav/freshclam.pid 2>/dev/null\` 2> /dev/null || true
    endscript
}
/var/log/clamav/clamonacc.log {
    rotate 12
    weekly
    compress
    delaycompress
    missingok
    notifempty
    create 640 clamav clamav
    postrotate
        /bin/kill -HUP \`cat /run/clamav/clamd.pid 2>/dev/null\` 2> /dev/null || true
    endscript
}
EOF
    log_debug "logrotate configuration created for ClamAV logs."
else
    echo -e "${GREEN}Existing logrotate configuration for ClamAV includes clamonacc.log, skipping creation.${NC}" | tee -a "$DEBUG_LOG"
fi
sudo chmod 644 /etc/logrotate.d/clamav || { echo -e "${RED}Error: Failed to set permissions for /etc/logrotate.d/clamav. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }

# Get clamav user UID
CLAMAV_UID=$(id -u clamav 2>/dev/null || echo "unknown")
if [[ "$CLAMAV_UID" == "unknown" ]]; then
    echo -e "${RED}Error: clamav user not found. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"
    exit 1
fi
log_debug "ClamAV UID: $CLAMAV_UID"

# Write clamd.conf (always overwrite)
echo -e "${YELLOW}Writing a clean clamd.conf file...${NC}" | tee -a "$DEBUG_LOG"
scan_path="/home/$SUDO_USER"
if [[ ! -d "$scan_path" ]]; then
    echo -e "${RED}Error: Directory '$scan_path' does not exist. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"
    exit 1
fi
sudo tee /etc/clamav/clamd.conf > /dev/null <<EOF
# This file was generated by hardenclamav.sh
LogFile /var/log/clamav/clamd.log
LogTime yes
LogVerbose yes
ExtendedDetectionInfo yes
PidFile /run/clamav/clamd.pid
TemporaryDirectory /tmp
DatabaseDirectory /var/lib/clamav
LocalSocket /run/clamav/clamd.ctl
LocalSocketGroup clamav
LocalSocketMode 660
User clamav
OnAccessPrevention yes
OnAccessIncludePath $scan_path
OnAccessExcludePath $scan_path/.cache
OnAccessExcludePath $scan_path/.config
OnAccessExcludeUID $CLAMAV_UID
$(if [ -d "/var/www/html" ]; then echo "OnAccessIncludePath /var/www/html"; else echo "# OnAccessIncludePath /var/www/html (directory not found)"; fi)
EOF
log_debug "clamd.conf written with scan_path=$scan_path and OnAccessExcludeUID=$CLAMAV_UID"

# Start and enable freshclam service
if ! systemctl is-enabled --quiet clamav-freshclam.service; then
    sudo systemctl enable --now clamav-freshclam.service || { echo -e "${RED}Error: clamav-freshclam.service failed to start. Check $DEBUG_LOG and 'sudo systemctl status clamav-freshclam.service'.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
    log_debug "clamav-freshclam.service enabled and started."
else
    echo -e "${GREEN}clamav-freshclam.service already enabled.${NC}" | tee -a "$DEBUG_LOG"
fi
if ! systemctl is-active --quiet clamav-freshclam.service; then
    echo -e "${RED}Error: clamav-freshclam.service is not active. Check $DEBUG_LOG and 'sudo systemctl status clamav-freshclam.service'.${NC}" | tee -a "$DEBUG_LOG"
    exit 1
fi
log_debug "clamav-freshclam.service started successfully."
echo -e "${YELLOW}Running a manual signature update...${NC}" | tee -a "$DEBUG_LOG"
sudo freshclam || { echo -e "${RED}Error: freshclam update failed. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
log_debug "freshclam update completed."

# Start and enable clamd service
if ! systemctl is-enabled --quiet clamav-daemon.service; then
    sudo systemctl enable --now clamav-daemon.service || { echo -e "${RED}Error: clamav-daemon.service failed to start. Check $DEBUG_LOG and 'sudo systemctl status clamav-daemon.service'.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
    log_debug "clamav-daemon.service enabled and started."
else
    echo -e "${GREEN}clamav-daemon.service already enabled.${NC}" | tee -a "$DEBUG_LOG"
fi
if ! systemctl is-active --quiet clamav-daemon.service; then
    echo -e "${RED}Error: clamav-daemon.service is not active. Check $DEBUG_LOG and 'sudo systemctl status clamav-daemon.service'.${NC}" | tee -a "$DEBUG_LOG"
    exit 1
fi
log_debug "clamav-daemon.service started successfully."

# Ensure /run/clamav directory and socket permissions
sudo mkdir -p /run/clamav || { echo -e "${RED}Error: Failed to create /run/clamav. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
sudo chown clamav:clamav /run/clamav || { echo -e "${RED}Error: Failed to set ownership for /run/clamav. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
sudo chmod 755 /run/clamav || { echo -e "${RED}Error: Failed to set permissions for /run/clamav. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
log_debug "/run/clamav created for PIDFile and socket."

# Wait for clamd to initialize and create socket
echo -e "${YELLOW}Waiting for clamd to initialize socket...${NC}" | tee -a "$DEBUG_LOG"
for i in {1..30}; do
    if [ -S /run/clamav/clamd.ctl ]; then
        sudo chown clamav:clamav /run/clamav/clamd.ctl || { echo -e "${RED}Error: Failed to set ownership for /run/clamav/clamd.ctl. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
        sudo chmod 660 /run/clamav/clamd.ctl || { echo -e "${RED}Error: Failed to set permissions for /run/clamav/clamd.ctl. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
        log_debug "Socket /run/clamav/clamd.ctl exists and permissions set."
        break
    fi
    sleep 1
done
if [ ! -S /run/clamav/clamd.ctl ]; then
    echo -e "${RED}Error: Clamd socket /run/clamav/clamd.ctl not created. Check 'sudo systemctl status clamav-daemon.service' and $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"
    exit 1
fi

# --- Step 6: Enable on-access scanning ---
echo -e "\n${YELLOW}Step 6: Enabling On-Access Scanning...${NC}" | tee -a "$DEBUG_LOG"
# Check kernel compatibility with fanotify
echo -e "${YELLOW}Checking kernel compatibility with fanotify...${NC}" | tee -a "$DEBUG_LOG"
if ! command -v zcat &>/dev/null; then
    echo -e "${RED}Error: zcat not available. Cannot check kernel config. Exiting.${NC}" | tee -a "$DEBUG_LOG"
    exit 1
fi
FANOTIFY_CONFIG=$(zcat /proc/config.gz | grep CONFIG_FANOTIFY 2>/dev/null || echo "CONFIG_FANOTIFY not found")
log_debug "Kernel config check: $FANOTIFY_CONFIG"
if [[ ! "$FANOTIFY_CONFIG" =~ ^CONFIG_FANOTIFY=y ]]; then
    echo -e "${RED}Error: System is not compatible with fanotify (CONFIG_FANOTIFY is not enabled). On-access scanning requires fanotify.${NC}" | tee -a "$DEBUG_LOG"
    echo -e "${YELLOW}Kernel: $(uname -r). Install a kernel with CONFIG_FANOTIFY=y (e.g., linux-lts or linux-zen).${NC}" | tee -a "$DEBUG_LOG"
    exit 1
fi
echo -e "${GREEN}Kernel is compatible with fanotify (CONFIG_FANOTIFY=y).${NC}" | tee -a "$DEBUG_LOG"

# Ensure libcap is installed for setcap
echo -e "${YELLOW}Checking for libcap to grant fanotify capabilities...${NC}" | tee -a "$DEBUG_LOG"
if ! command -v setcap &>/dev/null; then
    echo -e "${YELLOW}Installing libcap for setcap...${NC}" | tee -a "$DEBUG_LOG"
    sudo pacman -S --needed libcap || { echo -e "${RED}Error: Failed to install libcap. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
    log_debug "libcap installed successfully."
else
    echo -e "${GREEN}libcap is already installed.${NC}" | tee -a "$DEBUG_LOG"
fi

# Grant CAP_SYS_ADMIN to clamonacc for fanotify
echo -e "${YELLOW}Granting CAP_SYS_ADMIN to clamonacc for fanotify support...${NC}" | tee -a "$DEBUG_LOG"
sudo setcap cap_sys_admin+ep /usr/bin/clamonacc 2>> "$DEBUG_LOG" || { echo -e "${RED}Error: Failed to set CAP_SYS_ADMIN on /usr/bin/clamonacc. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
log_debug "CAP_SYS_ADMIN set on /usr/bin/clamonacc."
getcap /usr/bin/clamonacc >> "$DEBUG_LOG"

# Ensure ClamAV user has permissions for on-access scanning
echo -e "${YELLOW}Ensuring ClamAV user has permissions for on-access scanning...${NC}" | tee -a "$DEBUG_LOG"
sudo chgrp -R clamav "/home/$SUDO_USER" || { echo -e "${RED}Error: Failed to change group ownership for '/home/$SUDO_USER'. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
sudo chmod -R g+rX "/home/$SUDO_USER" || { echo -e "${RED}Error: Failed to set group permissions for '/home/$SUDO_USER'. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
echo -e "${GREEN}ClamAV user now has proper permissions on /home/$SUDO_USER.${NC}" | tee -a "$DEBUG_LOG"
log_debug "Permissions checked and fixed for OnAccessIncludePath as clamav user."

# Create clamav-onacc.service (always overwrite)
echo -e "${YELLOW}Creating clamav-onacc.service (foreground mode)...${NC}" | tee -a "$DEBUG_LOG"
sudo tee /etc/systemd/system/clamav-onacc.service > /dev/null <<EOF
[Unit]
Description=ClamAV On-Access Scanning Daemon
Requires=clamav-daemon.service
After=clamav-daemon.service
StartLimitIntervalSec=500
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/usr/bin/clamonacc --foreground --config-file=/etc/clamav/clamd.conf /home/$SUDO_USER $(if [ -d "/var/www/html" ]; then echo "/var/www/html"; fi)
Restart=on-failure
RestartSec=5
TimeoutStartSec=300
User=clamav
Group=clamav
StandardOutput=append:/var/log/clamav/clamonacc.log
StandardError=append:/var/log/clamav/clamonacc.log

[Install]
WantedBy=multi-user.target
EOF
log_debug "clamav-onacc.service created with Type=simple (foreground mode)."

# Start and enable clamav-onacc.service
sudo systemctl daemon-reload || { echo -e "${RED}Error: Failed to reload systemd daemon. Check $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
if ! systemctl is-enabled --quiet clamav-onacc.service; then
    sudo systemctl enable --now clamav-onacc.service || { echo -e "${RED}Error: Failed to start clamav-onacc.service. Check $DEBUG_LOG and 'sudo systemctl status clamav-onacc.service'.${NC}" | tee -a "$DEBUG_LOG"; exit 1; }
    log_debug "clamav-onacc.service enabled and started."
else
    echo -e "${GREEN}clamav-onacc.service already enabled.${NC}" | tee -a "$DEBUG_LOG"
fi
if ! systemctl is-active --quiet clamav-onacc.service; then
    echo -e "${RED}Error: clamav-onacc.service is not active. Check $DEBUG_LOG and 'sudo systemctl status clamav-onacc.service'.${NC}" | tee -a "$DEBUG_LOG"
    # Test clamonacc manually
    echo -e "${YELLOW}Running clamonacc command to diagnose issue:${NC}" | tee -a "$DEBUG_LOG"
    if ! sudo -u clamav /usr/bin/clamonacc --foreground --config-file=/etc/clamav/clamd.conf "/home/$SUDO_USER" 2>&1 | tee -a /tmp/clamonacc_error.log; then
        echo -e "${RED}Error: clamonacc failed to run. Check /tmp/clamonacc_error.log and $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"
    fi
    while read -r path; do
        if ! sudo -u clamav test -r "$path" || ! sudo -u clamav test -x "$path"; then
            echo -e "${RED}Permission Error: ClamAV user cannot access '$path'.${NC}" | tee -a "$DEBUG_LOG"
            echo -e "${YELLOW}Fix manually with 'sudo chmod 755 $path' or group access and check 'ls -ld $path'.${NC}" | tee -a "$DEBUG_LOG"
        fi
    done < <(grep '^OnAccessIncludePath' /etc/clamav/clamd.conf | awk '{print $2}')
    echo -e "${YELLOW}Check clamd.conf with 'cat /etc/clamav/clamd.conf'.${NC}" | tee -a "$DEBUG_LOG"
    exit 1
fi
log_debug "clamav-onacc.service started successfully."

# Test clamonacc monitoring
echo -e "${YELLOW}Testing clamonacc file monitoring...${NC}" | tee -a "$DEBUG_LOG"
test_file="/home/$SUDO_USER/clamav_test_$(date +%s).txt"
touch "$test_file" 2>/dev/null && echo "Test file created for clamonacc monitoring test." >> "$DEBUG_LOG"
sleep 2
if grep -q "OnAccess.*$test_file" /var/log/clamav/clamd.log 2>/dev/null; then
    echo -e "${GREEN}Success: clamonacc detected file creation at $test_file.${NC}" | tee -a "$DEBUG_LOG"
else
    echo -e "${RED}Warning: clamonacc may not be monitoring file actions. Check /var/log/clamav/clamd.log and $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"
    cat /var/log/clamav/clamd.log | tail -10 >> "$DEBUG_LOG"
    log_debug "Last 10 lines of clamd.log appended for debugging."
fi
rm -f "$test_file" 2>/dev/null && log_debug "Test file $test_file removed."

# --- Step 7: Verify all services ---
echo -e "\n${YELLOW}Step 7: Verifying ClamAV and Fangfrisch services...${NC}" | tee -a "$DEBUG_LOG"
for service in clamav-freshclam.service clamav-daemon.service clamav-onacc.service; do
    if systemctl is-active --quiet "$service"; then
        echo -e "${GREEN}$service is active.${NC}" | tee -a "$DEBUG_LOG"
    else
        echo -e "${RED}Error: $service is not active. Check 'sudo systemctl status $service' and $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"
        exit 1
    fi
done
if [[ $fangfrisch_installed -eq 1 ]]; then
    if systemctl is-active --quiet fangfrisch.timer; then
        echo -e "${GREEN}fangfrisch.timer is active for automatic updates.${NC}" | tee -a "$DEBUG_LOG"
    else
        echo -e "${RED}Error: fangfrisch.timer is not active. Check 'sudo systemctl status fangfrisch.timer' and $DEBUG_LOG.${NC}" | tee -a "$DEBUG_LOG"
        exit 1
    fi
fi

# --- Final Summary ---
echo -e "\n${GREEN}--- Hardening Script Summary ---${NC}" | tee -a "$DEBUG_LOG"
if [[ $update_reply =~ ^[Yy]$ ]]; then
    echo -e "${GREEN}System Update:${NC} Your system packages were updated." | tee -a "$DEBUG_LOG"
else
    echo -e "${YELLOW}System Update:${NC} Skipped as per your choice." | tee -a "$DEBUG_LOG"
fi
if [[ $install_clamav_reply =~ ^[Yy]$ ]]; then
    echo -e "${GREEN}ClamAV Installation:${NC} ClamAV is now installed on your system." | tee -a "$DEBUG_LOG"
else
    echo -e "${YELLOW}ClamAV Installation:${NC} Skipped as per your choice." | tee -a "$DEBUG_LOG"
fi
if [[ $fangfrisch_installed -eq 1 ]]; then
    echo -e "${GREEN}Fangfrisch:${NC} Configured for Sanesecurity with automatic updates via fangfrisch.timer." | tee -a "$DEBUG_LOG"
else
    echo -e "${YELLOW}Fangfrisch:${NC} Skipped (not installed)." | tee -a "$DEBUG_LOG"
fi
echo -e "${GREEN}On-Access Scanning:${NC} Real-time scanning enabled on /home/$SUDO_USER (foreground mode)." | tee -a "$DEBUG_LOG"
echo -e "${GREEN}Automatic Updates:${NC} clamav-freshclam.service and fangfrisch.timer are enabled for official and third-party signatures." | tee -a "$DEBUG_LOG"
echo -e "${GREEN}Log Management:${NC} Log rotation configured for /var/log/clamav/*.log to prevent unbounded growth." | tee -a "$DEBUG_LOG"

echo -e "\n${GREEN}Hardening script complete. Your system is more secure with automatic updates and log management.${NC}" | tee -a "$DEBUG_LOG"
echo -e "${YELLOW}Debug log saved to $DEBUG_LOG for troubleshooting.${NC}" | tee -a "$DEBUG_LOG"
