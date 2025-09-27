#!/bin/bash

# Arch Linux Hardening Script with Kicksecure-inspired security features
# Integrates check-update.sh for weekly update reminders
# Modified to prompt for ClamAV hardening at the end

# Define colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global arrays to track status
DECLARED_FEATURES=()
INSTALLED_FEATURES=()
SKIPPED_FEATURES=()
FAILED_FEATURES=()
UNIMPLEMENTED_FEATURES=()

# Function to display a section header
print_header() {
    echo -e "\n${BLUE}================================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}================================================================${NC}\n"
}

# Function to display an explanation
print_explanation() {
    echo -e "${YELLOW}Explanation:${NC} $1\n"
}

# Function for user confirmation with a default 'yes'
confirm_action() {
    while true; do
        read -rp "$(echo -e "${GREEN}$1 (Y/n): ${NC}")" yn
        yn=${yn:-y}
        case $yn in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) echo -e "${RED}Please answer yes or no.${NC}";;
        esac
    done
}

# Function to handle errors
handle_error() {
    local feature_name="$1"
    local error_message="$2"
    echo -e "${RED}Error for ${feature_name}: ${error_message}${NC}"
    FAILED_FEATURES+=("$feature_name (Error: $error_message)")
    if confirm_action "Do you want to continue despite this error for ${feature_name}?"; then
        echo -e "${YELLOW}Continuing as requested.${NC}"
    else
        echo -e "${YELLOW}Skipping further actions for ${feature_name} as requested, but continuing script execution.${NC}"
    fi
}

# Function to check if a package is installed
is_package_installed() {
    pacman -Q "$1" &>/dev/null
}

# Function to check if a service is enabled and active
is_service_running() {
    systemctl is-active --quiet "$1" && systemctl is-enabled --quiet "$1"
}

# Function to check if a specific sysctl setting is active
is_sysctl_set() {
    sysctl -n "$1" 2>/dev/null | grep -q "$2"
}

# Function to check for specific GRUB parameters
has_grub_param() {
    grep -q "GRUB_CMDLINE_LINUX_DEFAULT=.*$1" /etc/default/grub 2>/dev/null
}

# Function to detect the bootloader type
detect_bootloader() {
    if command -v bootctl &>/dev/null && [ -d "/boot/loader/entries" ]; then
        echo "systemd-boot"
        return
    fi
    if [ -f "/etc/default/grub" ] && command -v grub-mkconfig &>/dev/null; then
        echo "grub"
        return
    fi
    echo "unknown"
}

# Function to prompt the user for their bootloader choice
get_bootloader_choice() {
    local selected_bootloader=""
    echo -e "${YELLOW}The script could not automatically detect your bootloader.${NC}"
    while [ -z "$selected_bootloader" ]; do
        echo -e "${GREEN}Please choose your bootloader:${NC}"
        echo -e "  1) grub"
        echo -e "  2) systemd-boot"
        read -rp "Enter your choice (1 or 2): " choice
        case "$choice" in
            1) selected_bootloader="grub";;
            2) selected_bootloader="systemd-boot";;
            *) echo -e "${RED}Invalid choice. Please enter '1' or '2'.${NC}";;
        esac
    done
    echo "$selected_bootloader"
}

# Function to check if PAM Faillock is configured
is_pam_faillock_configured() {
    local configured=false
    if [ -f "/etc/pam.d/system-auth" ]; then
        if grep -qE "^\s*(auth|account)\s+.*pam_faillock.so" "/etc/pam.d/system-auth"; then
            configured=true
        fi
    fi
    if [ -f "/etc/pam.d/password-auth" ] && [ "$(readlink -f /etc/pam.d/password-auth)" != "$(readlink -f /etc/pam.d/system-auth)" ]; then
        if grep -qE "^\s*(auth|account)\s+.*pam_faillock.so" "/etc/pam.d/password-auth"; then
            configured=true
        fi
    fi
    if $configured; then
        return 0
    else
        return 1
    fi
}

echo -e "${BLUE}Welcome to the Arch Linux Hardening Script!${NC}"
echo -e "${BLUE}This script will help you implement Kicksecure-inspired security features on your Arch Linux system.${NC}"
echo -e "${BLUE}All prompts now default to 'yes' (just press Enter).${NC}"

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root. Please use sudo.${NC}"
    exit 1
fi

CURRENT_USER=$(logname)

# --- Initial System Update ---
print_header "Initial System Update"
echo -e "${YELLOW}Running a full system update and cleaning the package cache...${NC}"
pacman -Syu --noconfirm
pacman -Sc --noconfirm
echo -e "${GREEN}System update and cache clean completed.${NC}"

echo -e "\n${YELLOW}Starting hardening process...${NC}"

# --- Pre-Checks: Install Yay and List Existing Features ---
print_header "Pre-Checks: Installing Yay and Detecting Existing Features"

if ! command -v yay &> /dev/null; then
    echo -e "${YELLOW}AUR helper 'yay' not found. Installing it now.${NC}"
    DECLARED_FEATURES+=("AUR Helper (yay)")
    if confirm_action "Do you want to install 'yay' now?"; then
        echo -e "${GREEN}Installing yay...${NC}"
        if ! pacman -S --noconfirm --needed base-devel git; then
            handle_error "AUR Helper (yay)" "Failed to install base-devel or git."
        else
            if [ -d "/tmp/yay_install" ]; then
                rm -rf "/tmp/yay_install"
            fi
            if ! sudo -u "$CURRENT_USER" git clone https://aur.archlinux.org/yay.git /tmp/yay_install; then
                handle_error "AUR Helper (yay)" "Failed to clone yay repository."
            elif ! sudo -u "$CURRENT_USER" sh -c "cd /tmp/yay_install && makepkg -si --noconfirm"; then
                handle_error "AUR Helper (yay)" "Failed to build and install yay."
            else
                rm -rf "/tmp/yay_install"
                echo -e "${GREEN}yay installed successfully.${NC}"
                INSTALLED_FEATURES+=("AUR Helper (yay)")
            fi
        fi
    else
        SKIPPED_FEATURES+=("AUR Helper (yay)")
    fi
else
    echo -e "${GREEN}AUR helper 'yay' is already installed.${NC}"
    INSTALLED_FEATURES+=("AUR Helper (yay)")
fi

# Detect existing security features
echo -e "\n${YELLOW}Detecting currently installed/configured security features...${NC}"

if is_package_installed "ufw" && is_service_running "ufw.service" && ufw status | grep -q "Status: active"; then
    INSTALLED_FEATURES+=("Firewall (UFW)")
else
    DECLARED_FEATURES+=("Firewall (UFW)")
fi

if is_pam_faillock_configured; then
    INSTALLED_FEATURES+=("PAM Faillock Configuration")
else
    DECLARED_FEATURES+=("PAM Faillock Configuration")
fi

if grep -q "if \[ \"\$EUID\" -eq 0 \]; then umask 077; else umask 027; fi" /etc/profile; then
    INSTALLED_FEATURES+=("Umask Hardening (027/077)")
else
    DECLARED_FEATURES+=("Umask Hardening")
fi

if is_package_installed "linux-hardened"; then
    INSTALLED_FEATURES+=("Linux-hardened Kernel")
else
    DECLARED_FEATURES+=("Linux-hardened Kernel")
fi

if [ -f "/etc/sysctl.d/99-security-hardening.conf" ] && is_sysctl_set "kernel.kptr_restrict" "2" && is_sysctl_set "kernel.yama.ptrace_scope" "2" && is_sysctl_set "kernel.randomize_kstack_offset" "1"; then
    INSTALLED_FEATURES+=("Sysctl Hardening")
else
    DECLARED_FEATURES+=("Sysctl Hardening")
fi

BOOTLOADER=$(detect_bootloader)
if [ "$BOOTLOADER" == "grub" ]; then
    if has_grub_param "random.trust_cpu=on" && has_grub_param "apparmor=1 security=apparmor"; then
        INSTALLED_FEATURES+=("GRUB Kernel Parameters")
    else
        DECLARED_FEATURES+=("GRUB Kernel Parameters")
    fi
elif [ "$BOOTLOADER" == "systemd-boot" ]; then
    DECLARED_FEATURES+=("systemd-boot Kernel Parameters")
else
    DECLARED_FEATURES+=("Bootloader Kernel Parameters (unknown type)")
fi

if is_package_installed "lkrg-dkms" && is_service_running "lkrg@default.service"; then
    INSTALLED_FEATURES+=("Linux Kernel Runtime Guard (LKRG)")
else
    DECLARED_FEATURES+=("Linux Kernel Runtime Guard (LKRG)")
fi

if is_package_installed "apparmor" && is_service_running "apparmor.service" && aa-enabled &>/dev/null; then
    INSTALLED_FEATURES+=("AppArmor Profiles")
else
    DECLARED_FEATURES+=("AppArmor Profiles")
fi

if is_package_installed "firejail"; then
    INSTALLED_FEATURES+=("Application Sandboxing (Firejail)")
else
    DECLARED_FEATURES+=("Application Sandboxing (Firejail)")
fi

if is_package_installed "chrony" && is_service_running "chronyd.service" && grep -q "nts" /etc/chrony.conf; then
    INSTALLED_FEATURES+=("Secure Time Synchronization (chrony with NTS)")
else
    DECLARED_FEATURES+=("Secure Time Synchronization (chrony with NTS)")
fi

if [ "$BOOTLOADER" == "grub" ]; then
    if grep -q "password_pbkdf2" /etc/grub.d/40_custom 2>/dev/null; then
        INSTALLED_FEATURES+=("Boot Loader Password (GRUB)")
    else
        DECLARED_FEATURES+=("Boot Loader Password (GRUB)")
    fi
elif [ "$BOOTLOADER" == "systemd-boot" ]; then
    DECLARED_FEATURES+=("Boot Loader Password (systemd-boot - Not Applicable)")
else
    DECLARED_FEATURES+=("Boot Loader Password (unknown bootloader)")
fi

if is_package_installed "haveged" && is_service_running "haveged.service"; then
    INSTALLED_FEATURES+=("Entropy Enhancement (haveged)")
else
    DECLARED_FEATURES+=("Entropy Enhancement (haveged)")
fi

if [ -f "/etc/securetty" ] && [ ! -s "/etc/securetty" ]; then
    INSTALLED_FEATURES+=("Console Lockdown (Restrict Root Login on TTYs)")
else
    DECLARED_FEATURES+=("Console Lockdown (Restrict Root Login on TTYs)")
fi

if grep -q "export TMOUT=" /etc/profile; then
    INSTALLED_FEATURES+=("Automatic Terminal Logout")
else
    DECLARED_FEATURES+=("Automatic Terminal Logout")
fi

if is_package_installed "audit" && is_service_running "auditd.service"; then
    INSTALLED_FEATURES+=("Auditd")
else
    DECLARED_FEATURES+=("Auditd")
fi

if is_package_installed "rkhunter" && is_package_installed "chkrootkit"; then
    INSTALLED_FEATURES+=("Rootkit Detection (rkhunter, chkrootkit)")
else
    DECLARED_FEATURES+=("Rootkit Detection (rkhunter, chkrootkit)")
fi

if is_package_installed "timeshift"; then
    INSTALLED_FEATURES+=("System Snapshots (Timeshift)")
else
    DECLARED_FEATURES+=("System Snapshots (Timeshift)")
fi

if is_package_installed "clamav" && is_service_running "clamav-onacc.service"; then
    INSTALLED_FEATURES+=("Real-Time Antivirus Scanning (ClamAV)")
else
    DECLARED_FEATURES+=("Real-Time Antivirus Scanning (ClamAV)")
fi

if [ -f "/home/$CURRENT_USER/.config/systemd/user/check-update.service" ] && [ -f "/home/$CURRENT_USER/.config/systemd/user/check-update.timer" ] && sudo -u "$CURRENT_USER" XDG_RUNTIME_DIR=/run/user/$(id -u "$CURRENT_USER") DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u "$CURRENT_USER")/bus systemctl --user is-enabled --quiet check-update.timer; then
    INSTALLED_FEATURES+=("Update Reminder (check-update.sh)")
else
    DECLARED_FEATURES+=("Update Reminder (check-update.sh)")
fi

echo -e "\n${BLUE}--- Detected Existing Security Features ---${NC}"
if [ ${#INSTALLED_FEATURES[@]} -eq 0 ]; then
    echo -e "${YELLOW}  No significant security features detected.${NC}"
else
    for feature in "${INSTALLED_FEATURES[@]}"; do
        echo -e "${GREEN}  ✔ $feature${NC}"
    done
fi
echo -e "\n${BLUE}--- Features Targeted for Installation/Configuration ---${NC}"
if [ ${#DECLARED_FEATURES[@]} -eq 0 ]; then
    echo -e "${YELLOW}  All features identified as installable are already present.${NC}"
else
    for feature in "${DECLARED_FEATURES[@]}"; do
        if ! [[ " ${INSTALLED_FEATURES[@]} " =~ " ${feature} " ]]; then
            echo -e "${BLUE}  ? $feature${NC}"
        fi
    done
fi
echo -e "${BLUE}------------------------------------------------------${NC}\n"

# --- Immediate Installations ---
print_header "Immediate Installations"

print_header "System Snapshots (Timeshift)"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " System Snapshots (Timeshift) " ]]; then
    echo -e "${GREEN}Timeshift is already installed. Skipping installation.${NC}"
else
    print_explanation "Timeshift creates incremental snapshots of your system..."
    if confirm_action "Do you want to install Timeshift for system snapshots?"; then
        echo -e "${GREEN}Installing timeshift...${NC}"
        if ! pacman -S --noconfirm --needed timeshift; then
            handle_error "System Snapshots (Timeshift)" "Failed to install Timeshift."
        else
            echo -e "${GREEN}Timeshift installed successfully.${NC}"
            echo -e "${YELLOW}Launch Timeshift via 'sudo timeshift-gtk' to configure snapshots.${NC}"
            INSTALLED_FEATURES+=("System Snapshots (Timeshift)")
        fi
    else
        SKIPPED_FEATURES+=("System Snapshots (Timeshift)")
    fi
fi

print_header "Application Sandboxing (Firejail)"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " Application Sandboxing (Firejail) " ]]; then
    echo -e "${GREEN}Firejail is already installed. Skipping this step.${NC}"
else
    print_explanation "Firejail creates isolated sandboxes for applications..."
    if confirm_action "Do you want to install Firejail for application sandboxing?"; then
        echo -e "${GREEN}Installing firejail...${NC}"
        if ! pacman -S --noconfirm --needed firejail; then
            handle_error "Application Sandboxing (Firejail)" "Failed to install Firejail."
        else
            echo -e "${GREEN}Firejail installed successfully.${NC}"
            echo -e "${YELLOW}Use 'firejail <application>' (e.g., 'firejail firefox').${NC}"
            INSTALLED_FEATURES+=("Application Sandboxing (Firejail)")
        fi
    else
        SKIPPED_FEATURES+=("Application Sandboxing (Firejail)")
    fi
fi

# --- Core System Hardening ---
print_header "I. Core System Hardening"

print_header "1. Firewall (UFW)"
UFW_INSTALLED_PKG=$(is_package_installed "ufw")
UFW_ACTIVE_SERVICE=$(systemctl is-active --quiet "ufw.service")
UFW_STATUS_ACTIVE=$(ufw status &>/dev/null && ufw status | grep -q "Status: active")

if $UFW_INSTALLED_PKG && $UFW_ACTIVE_SERVICE && $UFW_STATUS_ACTIVE; then
    echo -e "${GREEN}UFW is already installed and active. Skipping configuration.${NC}"
    echo -e "${BLUE}Current UFW status:${NC}"
    ufw status verbose
elif $UFW_INSTALLED_PKG && (! $UFW_ACTIVE_SERVICE || ! $UFW_STATUS_ACTIVE); then
    echo -e "${YELLOW}UFW is installed but inactive.${NC}"
    if confirm_action "Do you want to enable and configure UFW now?"; then
        echo -e "${GREEN}Enabling and configuring ufw...${NC}"
        systemctl enable ufw.service
        systemctl start ufw.service
        ufw default deny incoming
        ufw default allow outgoing
        ufw enable
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}UFW enabled and configured successfully.${NC}"
            echo -e "${YELLOW}Open specific ports if needed (e.g., 'sudo ufw allow ssh').${NC}"
            echo -e "${BLUE}Current UFW status:${NC}"
            ufw status verbose
            INSTALLED_FEATURES+=("Firewall (UFW)")
        else
            handle_error "Firewall (UFW)" "Failed to enable/configure UFW."
            SKIPPED_FEATURES+=("Firewall (UFW) (failed to activate)")
        fi
    else
        SKIPPED_FEATURES+=("Firewall (UFW) (user opted out)")
    fi
else
    echo -e "${YELLOW}UFW is not installed.${NC}"
    if confirm_action "Do you want to install and configure UFW?"; then
        echo -e "${GREEN}Installing ufw and iptables-nft...${NC}"
        if ! pacman -S --noconfirm --needed ufw iptables-nft; then
            handle_error "Firewall (UFW)" "Failed to install ufw and iptables-nft."
            SKIPPED_FEATURES+=("Firewall (UFW) (installation failed)")
        else
            echo -e "${GREEN}Enabling and configuring ufw...${NC}"
            systemctl enable ufw.service
            systemctl start ufw.service
            ufw default deny incoming
            ufw default allow outgoing
            ufw enable
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}UFW installed and configured successfully.${NC}"
                echo -e "${YELLOW}Open specific ports if needed (e.g., 'sudo ufw allow ssh').${NC}"
                echo -e "${BLUE}Current UFW status:${NC}"
                ufw status verbose
                INSTALLED_FEATURES+=("Firewall (UFW)")
            else
                handle_error "Firewall (UFW)" "Failed to configure UFW."
                SKIPPED_FEATURES+=("Firewall (UFW) (configuration failed)")
            fi
        fi
    else
        SKIPPED_FEATURES+=("Firewall (UFW) (user opted out)")
    fi
fi

print_header "2. Least Privilege & User Account Separation"
print_explanation "Using a non-root user for daily tasks and 'sudo' for administrative actions..."
if ! id -nG "$CURRENT_USER" | grep -qw "wheel"; then
    echo -e "${RED}User '$CURRENT_USER' is not in the 'wheel' group.${NC}"
    if confirm_action "Do you want to add '$CURRENT_USER' to the 'wheel' group?"; then
        usermod -aG wheel "$CURRENT_USER"
        echo -e "${GREEN}'$CURRENT_USER' added to 'wheel' group. Log out and back in for this to take effect.${NC}"
    else
        echo -e "${YELLOW}Skipping adding user to wheel group.${NC}"
    fi
else
    echo -e "${GREEN}User '$CURRENT_USER' is already in the 'wheel' group.${NC}"
fi

print_header "PAM Faillock Configuration"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " PAM Faillock Configuration " ]]; then
    echo -e "${GREEN}PAM Faillock is already configured. Skipping.${NC}"
else
    print_explanation "PAM faillock locks out users after failed login attempts..."
    if confirm_action "Do you want to configure PAM faillock for brute-force defense?"; then
        PAM_AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
        FAILLOCK_AUTH_PRE="auth        required      pam_faillock.so preauth silent audit deny=3 unlock_time=600"
        FAILLOCK_AUTH_FAIL="auth        [default=die] pam_faillock.so authfail audit deny=3 unlock_time=600"
        FAILLOCK_ACCOUNT="account     required      pam_faillock.so"
        PAM_MODIFIED=false
        for pam_file in "${PAM_AUTH_FILES[@]}"; do
            if [ -f "$pam_file" ]; then
                echo -e "${YELLOW}Modifying $pam_file...${NC}"
                if ! grep -qF "$FAILLOCK_AUTH_PRE" "$pam_file"; then
                    sed -i "/^auth\s*sufficient\s*pam_unix.so/i $FAILLOCK_AUTH_PRE" "$pam_file"
                    PAM_MODIFIED=true
                fi
                if ! grep -qF "$FAILLOCK_AUTH_FAIL" "$pam_file"; then
                    sed -i "/^auth\s*sufficient\s*pam_unix.so/a $FAILLOCK_AUTH_FAIL" "$pam_file"
                    PAM_MODIFIED=true
                fi
                if ! grep -qF "$FAILLOCK_ACCOUNT" "$pam_file"; then
                    sed -i "/^account\s*required\s*pam_unix.so/a $FAILLOCK_ACCOUNT" "$pam_file"
                    PAM_MODIFIED=true
                fi
            else
                echo -e "${RED}Warning: PAM file not found: $pam_file. Skipping.${NC}"
            fi
        done
        if [ "$PAM_MODIFIED" = true ]; then
            echo -e "${GREEN}PAM faillock configuration complete.${NC}"
            INSTALLED_FEATURES+=("PAM Faillock Configuration")
        else
            echo -e "${YELLOW}PAM faillock configuration was already in place.${NC}"
            INSTALLED_FEATURES+=("PAM Faillock Configuration")
        fi
    else
        SKIPPED_FEATURES+=("PAM Faillock Configuration")
    fi
fi

print_header "3. Data Protection"
print_header "Umask Hardening"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " Umask Hardening (027/077) " ]]; then
    echo -e "${GREEN}Umask hardening is already configured. Skipping.${NC}"
else
    print_explanation "Umask determines default permissions for new files..."
    if confirm_action "Do you want to set a stricter default umask (027 for users, 077 for root)?"; then
        echo -e "${YELLOW}Modifying /etc/profile for umask settings...${NC}"
        cp /etc/profile /etc/profile.bak_hardening
        if ! grep -q "if \[ \"\$EUID\" -eq 0 \]; then umask 077; else umask 027; fi" /etc/profile; then
            echo "if [ \"\$EUID\" -eq 0 ]; then umask 077; else umask 027; fi" >> /etc/profile
            echo -e "${GREEN}Umask hardening applied successfully.${NC}"
            echo -e "${YELLOW}Changes will take effect on next login.${NC}"
            INSTALLED_FEATURES+=("Umask Hardening (027/077)")
        else
            echo -e "${YELLOW}Umask hardening lines already exist. Skipping.${NC}"
            INSTALLED_FEATURES+=("Umask Hardening (027/077)")
        fi
    else
        SKIPPED_FEATURES+=("Umask Hardening")
    fi
fi

# --- Kernel Hardening ---
print_header "II. Kernel Hardening"

print_header "1. Linux-hardened Kernel"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " Linux-hardened Kernel " ]]; then
    echo -e "${GREEN}The linux-hardened kernel is already installed. Skipping.${NC}"
else
    print_explanation "The Linux-hardened kernel includes security patches..."
    if confirm_action "Do you want to install the linux-hardened kernel?"; then
        echo -e "${GREEN}Installing linux-hardened...${NC}"
        if ! pacman -S --noconfirm --needed linux-hardened linux-hardened-headers; then
            handle_error "Linux-hardened Kernel" "Failed to install linux-hardened."
        else
            echo -e "${GREEN}Linux-hardened kernel installed successfully.${NC}"
            echo -e "${YELLOW}Reboot to use the new kernel. Keep the old kernel as a fallback.${NC}"
            INSTALLED_FEATURES+=("Linux-hardened Kernel")
        fi
    else
        SKIPPED_FEATURES+=("Linux-hardened Kernel")
    fi
fi

print_header "2. Sysctl Hardening"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " Sysctl Hardening " ]]; then
    echo -e "${GREEN}Sysctl hardening is already configured. Skipping.${NC}"
else
    print_explanation "Sysctl modifies kernel parameters for security..."
    if confirm_action "Do you want to apply sysctl hardening?"; then
        echo -e "${YELLOW}Writing to /etc/sysctl.d/99-security-hardening.conf...${NC}"
        cat <<EOF > /etc/sysctl.d/99-security-hardening.conf
# Security hardening based on Kicksecure recommendations
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=2048
net.ipv4.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv4.tcp_timestamps=0
kernel.perf_event_paranoid=3
kernel.randomize_va_space=2
kernel.yama.ptrace_scope=2
kernel.kptr_restrict=2
net.ipv4.ip_forward=0
net.ipv6.conf.all.forwarding=0
net.ipv6.conf.default.forwarding=0
fs.protected_hardlinks=1
fs.protected_symlinks=1
kernel.randomize_kstack_offset=1
EOF
        sysctl -p /etc/sysctl.d/99-security-hardening.conf
        echo -e "${GREEN}Sysctl hardening applied. Reboot recommended.${NC}"
        INSTALLED_FEATURES+=("Sysctl Hardening")
    else
        SKIPPED_FEATURES+=("Sysctl Hardening")
    fi
fi

print_header "3. Bootloader Kernel Parameters"
BOOTLOADER_TO_CONFIGURE=$(detect_bootloader)
if [ "$BOOTLOADER_TO_CONFIGURE" == "unknown" ]; then
    BOOTLOADER_TO_CONFIGURE=$(get_bootloader_choice)
fi

if [[ " ${INSTALLED_FEATURES[@]} " =~ " GRUB Kernel Parameters " ]] || [[ " ${INSTALLED_FEATURES[@]} " =~ " systemd-boot Kernel Parameters " ]]; then
    echo -e "${GREEN}Bootloader kernel parameters are already configured. Skipping.${NC}"
elif [ "$BOOTLOADER_TO_CONFIGURE" == "grub" ]; then
    print_explanation "Adding security kernel parameters to GRUB..."
    if confirm_action "Do you want to add security kernel parameters to GRUB?"; then
        GRUB_FILE="/etc/default/grub"
        cp "$GRUB_FILE" "$GRUB_FILE.bak"
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 random.trust_cpu=on apparmor=1 security=apparmor"/' "$GRUB_FILE"
        grub-mkconfig -o /boot/grub/grub.cfg
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}GRUB configuration updated.${NC}"
            INSTALLED_FEATURES+=("GRUB Kernel Parameters")
        else
            handle_error "GRUB Kernel Parameters" "Failed to update GRUB configuration."
        fi
    else
        SKIPPED_FEATURES+=("GRUB Kernel Parameters")
    fi
elif [ "$BOOTLOADER_TO_CONFIGURE" == "systemd-boot" ]; then
    print_explanation "Adding security kernel parameters to systemd-boot..."
    if confirm_action "Do you want to add security kernel parameters to systemd-boot?"; then
        ENTRY_FILE=$(find /boot/loader/entries/ -type f -name "*.conf" | head -n 1)
        if [ -n "$ENTRY_FILE" ]; then
            sed -i 's/^options /options random.trust_cpu=on apparmor=1 security=apparmor /' "$ENTRY_FILE"
            echo -e "${GREEN}Systemd-boot parameters updated in $ENTRY_FILE.${NC}"
            INSTALLED_FEATURES+=("systemd-boot Kernel Parameters")
        else
            handle_error "Bootloader Kernel Parameters" "Could not find systemd-boot entry file."
        fi
    else
        SKIPPED_FEATURES+=("systemd-boot Kernel Parameters")
    fi
else
    echo -e "${RED}Unknown bootloader. Cannot configure kernel parameters.${NC}"
    UNIMPLEMENTED_FEATURES+=("Bootloader Kernel Parameters")
fi

print_header "4. Linux Kernel Runtime Guard (LKRG)"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " Linux Kernel Runtime Guard (LKRG) " ]]; then
    echo -e "${GREEN}LKRG is already installed and active. Skipping.${NC}"
else
    print_explanation "LKRG performs runtime integrity checks on the kernel..."
    if confirm_action "Do you want to install and enable LKRG?"; then
        echo -e "${GREEN}Installing lkrg-dkms from the AUR...${NC}"
        if ! sudo -u "$CURRENT_USER" yay -S --noconfirm --needed lkrg-dkms; then
            handle_error "Linux Kernel Runtime Guard (LKRG)" "Failed to install lkrg-dkms."
            SKIPPED_FEATURES+=("Linux Kernel Runtime Guard (LKRG)")
        else
            echo -e "${GREEN}lkrg-dkms installed successfully.${NC}"
            if systemctl enable --now lkrg@default.service; then
                echo -e "${GREEN}LKRG enabled successfully.${NC}"
                INSTALLED_FEATURES+=("Linux Kernel Runtime Guard (LKRG)")
            else
                handle_error "Linux Kernel Runtime Guard (LKRG)" "Failed to enable lkrg@default.service."
                SKIPPED_FEATURES+=("Linux Kernel Runtime Guard (LKRG) (failed to activate)")
            fi
        fi
    else
        SKIPPED_FEATURES+=("Linux Kernel Runtime Guard (LKRG)")
    fi
fi

print_header "5. AppArmor Profiles"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " AppArmor Profiles " ]]; then
    echo -e "${GREEN}AppArmor is already installed and active. Skipping.${NC}"
else
    print_explanation "AppArmor confines programs to limited resources..."
    if confirm_action "Do you want to install and configure AppArmor?"; then
        echo -e "${GREEN}Installing apparmor...${NC}"
        if ! pacman -S --noconfirm --needed apparmor; then
            handle_error "AppArmor Profiles" "Failed to install apparmor."
        else
            echo -e "${GREEN}AppArmor package installed successfully.${NC}"
            BOOTLOADER=$(detect_bootloader)
            if [ "$BOOTLOADER" == "unknown" ]; then
                BOOTLOADER=$(get_bootloader_choice)
            fi
            if [ "$BOOTLOADER" == "grub" ]; then
                cp /etc/default/grub /etc/default/grub.bak
                sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 apparmor=1 security=apparmor"/' /etc/default/grub
                echo -e "${GREEN}GRUB configuration updated. Run 'sudo grub-mkconfig -o /boot/grub/grub.cfg' after the script.${NC}"
            elif [ "$BOOTLOADER" == "systemd-boot" ]; then
                ENTRY_FILE=$(find /boot/loader/entries/ -type f -name "*.conf" -not -name "*autodetect.conf" | head -n 1)
                if [ -n "$ENTRY_FILE" ]; then
                    sed -i 's/^options /options apparmor=1 security=apparmor /' "$ENTRY_FILE"
                    echo -e "${GREEN}Systemd-boot parameters updated in $ENTRY_FILE.${NC}"
                else
                    handle_error "AppArmor Profiles" "Could not find systemd-boot entry file."
                fi
            else
                handle_error "AppArmor Profiles" "Unrecognized bootloader."
            fi
            MOUNT_UNIT_PATH="/etc/systemd/system/sys-kernel-security-apparmor.mount"
            if [ ! -f "$MOUNT_UNIT_PATH" ]; then
                echo "[Unit]
Description=AppArmor security filesystem
[Mount]
What=apparmorfs
Where=/sys/kernel/security/apparmor
Type=apparmorfs
[Install]
WantedBy=sysinit.target" | tee "$MOUNT_UNIT_PATH" > /dev/null
                if systemctl enable sys-kernel-security-apparmor.mount; then
                    echo -e "${GREEN}AppArmor filesystem mount unit created and enabled.${NC}"
                else
                    handle_error "AppArmor Profiles" "Failed to enable AppArmor filesystem mount."
                fi
            fi
            if systemctl enable --now apparmor.service; then
                echo -e "${GREEN}AppArmor Profiles enabled successfully.${NC}"
                INSTALLED_FEATURES+=("AppArmor Profiles")
            else
                handle_error "AppArmor Profiles" "Failed to enable apparmor.service."
            fi
        fi
    else
        SKIPPED_FEATURES+=("AppArmor Profiles")
    fi
fi

print_header "Update Reminder Setup"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " Update Reminder (check-update.sh) " ]]; then
    echo -e "${GREEN}Update reminder is already set up (check-update.service and check-update.timer are active). Skipping.${NC}"
else
    print_explanation "The update reminder script (check-update.sh) checks for system updates weekly and notifies you via a desktop notification. It requires dunst for notifications and sets up a user-level systemd timer."
    if confirm_action "Do you want to set up a weekly update reminder using check-update.sh?"; then
        echo -e "${GREEN}Checking for check-update.sh...${NC}"
        if [ -f "./check-update.sh" ]; then
            if [ -x "./check-update.sh" ] || chmod +x ./check-update.sh; then
                echo -e "${GREEN}Executing check-update.sh as user $CURRENT_USER...${NC}"
                if sudo -u "$CURRENT_USER" XDG_RUNTIME_DIR=/run/user/$(id -u "$CURRENT_USER") DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u "$CURRENT_USER")/bus ./check-update.sh setup; then
                    echo -e "${GREEN}Update reminder set up successfully. It will run weekly.${NC}"
                    INSTALLED_FEATURES+=("Update Reminder (check-update.sh)")
                else
                    handle_error "Update Reminder (check-update.sh)" "Failed to execute check-update.sh setup."
                    SKIPPED_FEATURES+=("Update Reminder (check-update.sh) (execution failed)")
                fi
            else
                handle_error "Update Reminder (check-update.sh)" "Failed to make check-update.sh executable."
                SKIPPED_FEATURES+=("Update Reminder (check-update.sh) (not executable)")
            fi
        else
            handle_error "Update Reminder (check-update.sh)" "check-update.sh script not found in the current directory."
            SKIPPED_FEATURES+=("Update Reminder (check-update.sh) (script missing)")
        fi
    else
        SKIPPED_FEATURES+=("Update Reminder (check-update.sh)")
    fi
fi

# --- ClamAV Hardening (Moved to End) ---
print_header "Real-Time Antivirus Scanning (ClamAV)"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " Real-Time Antivirus Scanning (ClamAV) " ]]; then
    echo -e "${GREEN}ClamAV and on-access scanning are already active. Skipping.${NC}"
else
    print_explanation "This installs and configures ClamAV for real-time scanning using hardenclamav.sh..."
    if confirm_action "Do you want to install and configure ClamAV for real-time antivirus scanning?"; then
        echo -e "${GREEN}Checking for hardenclamav.sh...${NC}"
        if [ -f "./hardenclamav.sh" ]; then
            if [ -x "./hardenclamav.sh" ] || chmod +x ./hardenclamav.sh; then
                echo -e "${GREEN}Executing hardenclamav.sh as root...${NC}"
                if ./hardenclamav.sh; then
                    echo -e "${GREEN}hardenclamav.sh completed successfully.${NC}"
                    INSTALLED_FEATURES+=("Real-Time Antivirus Scanning (ClamAV)")
                else
                    handle_error "Real-Time Antivirus Scanning (ClamAV)" "The hardenclamav.sh script failed."
                    SKIPPED_FEATURES+=("Real-Time Antivirus Scanning (ClamAV) (execution failed)")
                fi
            else
                handle_error "Real-Time Antivirus Scanning (ClamAV)" "Failed to make hardenclamav.sh executable."
                SKIPPED_FEATURES+=("Real-Time Antivirus Scanning (ClamAV) (not executable)")
            fi
        else
            handle_error "Real-Time Antivirus Scanning (ClamAV)" "hardenclamav.sh script not found in the current directory."
            SKIPPED_FEATURES+=("Real-Time Antivirus Scanning (ClamAV) (script missing)")
        fi
    else
        SKIPPED_FEATURES+=("Real-Time Antivirus Scanning (ClamAV)")
    fi
fi

# --- Final Summary ---
print_header "Security Hardening Summary"
echo -e "${BLUE}--- Installed Features ---${NC}"
if [ ${#INSTALLED_FEATURES[@]} -eq 0 ]; then
    echo -e "${YELLOW}  None.${NC}"
else
    for feature in "${INSTALLED_FEATURES[@]}"; do
        echo -e "${GREEN}  ✓ $feature${NC}"
    done
fi

echo -e "\n${BLUE}--- Skipped Features ---${NC}"
if [ ${#SKIPPED_FEATURES[@]} -eq 0 ]; then
    echo -e "${GREEN}  None.${NC}"
else
    for feature in "${SKIPPED_FEATURES[@]}"; do
        echo -e "${YELLOW}  • $feature${NC}"
    done
fi

echo -e "\n${BLUE}--- Failed Features ---${NC}"
if [ ${#FAILED_FEATURES[@]} -eq 0 ]; then
    echo -e "${GREEN}  None.${NC}"
else
    for feature in "${FAILED_FEATURES[@]}"; do
        echo -e "${RED}  ✘ $feature${NC}"
    done
fi

echo -e "\n${BLUE}--------------------------------------------------------------------------${NC}\n"

echo -e "${BLUE}Most Kicksecure security features have been adapted for your Arch Linux system.${NC}"
echo -e "${BLUE}Please review the summary for any errors or manual steps required.${NC}"

if confirm_action "A reboot is highly recommended to apply all changes. Do you want to reboot now?"; then
    echo -e "${GREEN}Rebooting system... Goodbye!${NC}"
    reboot
else
    echo -e "${YELLOW}Please reboot manually to ensure all changes take effect.${NC}"
    FINAL_BOOTLOADER_CHECK=$(detect_bootloader)
    if [ "$FINAL_BOOTLOADER_CHECK" == "grub" ]; then
        echo -e "${YELLOW}Run 'sudo grub-mkconfig -o /boot/grub/grub.cfg' if GRUB changes were made.${NC}"
    elif [ "$FINAL_BOOTLOADER_CHECK" == "systemd-boot" ]; then
        echo -e "${YELLOW}No 'mkconfig' needed for systemd-boot. Changes will take effect on reboot.${NC}"
    fi
fi
