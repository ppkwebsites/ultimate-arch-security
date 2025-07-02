#!/bin/bash

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
UNIMPLEMENTED_FEATURES=() # For features that cannot be fully automated or require manual firmware interaction

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

# Function for user confirmation
confirm_action() {
    while true; do
        read -rp "$(echo -e "${GREEN}$1 (y/n): ${NC}")" yn
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
        echo -e "${RED}Exiting script. Please address the error and try again.${NC}"
        exit 1
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

# Function to check if a systemd unit file exists (used for services that might not be running but are installed)
unit_file_exists() {
    # systemctl list-unit-files is slow, checking common paths directly is faster
    # Check /usr/lib/systemd/system and /etc/systemd/system
    if [ -f "/usr/lib/systemd/system/$1" ] || [ -f "/etc/systemd/system/$1" ]; then
        return 0
    else
        return 1
    fi
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
    # 1. Check for systemd-boot using bootctl status directly (most reliable for systemd-boot)
    if command -v bootctl &>/dev/null && bootctl status 2>/dev/null | grep -qi "current boot loader:.*systemd-boot"; then
        echo "systemd-boot"
        return
    fi

    # 2. Check for GRUB
    if [ -f "/etc/default/grub" ] && command -v grub-mkconfig &>/dev/null && [ -f "/boot/grub/grub.cfg" ]; then
        echo "grub"
        return
    fi

    echo "unknown" # Fallback if neither found
}

# Function to check if PAM Faillock is configured more robustly
is_pam_faillock_configured() {
    local configured=false

    # Check system-auth
    if [ -f "/etc/pam.d/system-auth" ]; then
        if grep -qE "^\s*(auth|account)\s+.*pam_faillock.so" "/etc/pam.d/system-auth"; then
            configured=true
        fi
    fi

    # Check password-auth if it exists and is not a symlink to system-auth
    if [ -f "/etc/pam.d/password-auth" ] && [ "$(readlink -f /etc/pam.d/password-auth)" != "$(readlink -f /etc/pam.d/system-auth)" ]; then
        if grep -qE "^\s*(auth|account)\s+.*pam_faillock.so" "/etc/pam.d/password-auth"; then
            configured=true
        fi
    fi

    if $configured; then
        return 0 # True
    else
        return 1 # False
    fi
}


echo -e "${BLUE}Welcome to the Arch Linux Hardening Script!${NC}"
echo -e "${BLUE}This script will help you implement Kicksecure-inspired security features on your Arch Linux system.${NC}"
echo -e "${BLUE}Please read each prompt carefully.${NC}"

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root. Please use sudo.${NC}"
   exit 1
fi

CURRENT_USER=$(logname)

echo -e "\n${YELLOW}Starting hardening process...${NC}"

# --- Pre-Checks: Install Yay and List Existing Features ---

print_header "Pre-Checks: Installing Yay and Detecting Existing Features"

# Install Yay AUR helper first
if ! command -v yay &> /dev/null; then
    echo -e "${YELLOW}AUR helper 'yay' not found. Installing it now.${NC}"
    DECLARED_FEATURES+=("AUR Helper (yay)")
    if confirm_action "Do you want to install 'yay' now? (It's an AUR helper, not a Kicksecure feature)"; then
        echo -e "${GREEN}Installing yay...${NC}"
        if ! pacman -S --noconfirm --needed base-devel git; then
            handle_error "AUR Helper (yay)" "Failed to install base-devel or git."
        else
            # Ensure yay is built as the current user, not root
            if [ -d "/tmp/yay_install" ]; then
                rm -rf "/tmp/yay_install"
            fi
            if ! sudo -u "$CURRENT_USER" git clone https://aur.archlinux.org/yay.git /tmp/yay_install; then
                handle_error "AUR Helper (yay)" "Failed to clone yay repository."
            elif ! sudo -u "$CURRENT_USER" sh -c "cd /tmp/yay_install && makepkg -si --noconfirm"; then
                handle_error "AUR Helper (yay)" "Failed to build and install yay. Check permissions or missing dependencies."
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

echo -e "\n${YELLOW}Detecting currently installed/configured security features...${NC}"

# UFW check
if is_package_installed "ufw" && is_service_running "ufw.service" && ufw status | grep -q "Status: active"; then
    INSTALLED_FEATURES+=("Firewall (UFW)")
else
    DECLARED_FEATURES+=("Firewall (UFW)")
fi

# PAM Faillock check (UPDATED)
if is_pam_faillock_configured; then
    INSTALLED_FEATURES+=("PAM Faillock Configuration")
else
    DECLARED_FEATURES+=("PAM Faillock Configuration")
fi

# Home Folder Permissions check (simplified)
if [ -d "/home/$CURRENT_USER" ] && [ "$(stat -c %a /home/$CURRENT_USER)" == "700" ]; then
    INSTALLED_FEATURES+=("Home Folder Permissions (700)")
else
    DECLARED_FEATURES+=("Home Folder Permissions")
fi

# Umask Hardening check
if grep -q "if \[ \"\$EUID\" -eq 0 \]; then umask 077; else umask 027; fi" /etc/profile; then
    INSTALLED_FEATURES+=("Umask Hardening (027/077)")
else
    DECLARED_FEATURES+=("Umask Hardening")
fi

# Linux-hardened Kernel check
if is_package_installed "linux-hardened"; then
    INSTALLED_FEATURES+=("Linux-hardened Kernel")
else
    DECLARED_FEATURES+=("Linux-hardened Kernel")
fi

# Sysctl Hardening check
if [ -f "/etc/sysctl.d/99-security-hardening.conf" ] && grep -q "kernel.kptr_restrict = 1" /etc/sysctl.d/99-security-hardening.conf; then
    INSTALLED_FEATURES+=("Sysctl Hardening")
else
    DECLARED_FEATURES+=("Sysctl Hardening")
fi

# GRUB Kernel Parameters check (now conditional on bootloader)
BOOTLOADER=$(detect_bootloader)
if [ "$BOOTLOADER" == "grub" ]; then
    if [ -f "/etc/default/grub" ] && has_grub_param "random.trust_cpu=on" && has_grub_param "apparmor=1 security=apparmor"; then
        INSTALLED_FEATURES+=("GRUB Kernel Parameters")
    else
        DECLARED_FEATURES+=("GRUB Kernel Parameters")
    fi
elif [ "$BOOTLOADER" == "systemd-boot" ]; then
    # This check is more complex, might not perfectly reflect all params
    # For simplicity, if systemd-boot is detected, we assume the feature is "available"
    # and let the script attempt to apply it.
    DECLARED_FEATURES+=("systemd-boot Kernel Parameters")
else
    DECLARED_FEATURES+=("Bootloader Kernel Parameters (unknown type)")
fi


# LKRG check (UPDATED)
if is_package_installed "lkrg-dkms" && is_service_running "lkrg@default.service"; then
    INSTALLED_FEATURES+=("Linux Kernel Runtime Guard (LKRG)")
else
    DECLARED_FEATURES+=("Linux Kernel Runtime Guard (LKRG)")
fi

# AppArmor check (UPDATED)
if is_package_installed "apparmor" && is_service_running "apparmor.service" && aa-enabled &>/dev/null; then
    INSTALLED_FEATURES+=("AppArmor Profiles")
else
    DECLARED_FEATURES+=("AppArmor Profiles")
fi

# Firejail check
if is_package_installed "firejail"; then
    INSTALLED_FEATURES+=("Application Sandboxing (Firejail)")
else
    DECLARED_FEATURES+=("Application Sandboxing (Firejail)")
fi

# Chrony NTS check
if is_package_installed "chrony" && is_service_running "chronyd.service" && grep -q "nts" /etc/chrony.conf; then
    INSTALLED_FEATURES+=("Secure Time Synchronization (chrony with NTS)")
else
    DECLARED_FEATURES+=("Secure Time Synchronization (chrony with NTS)")
fi

# GRUB Boot Loader Password check (now conditional on bootloader)
if [ "$BOOTLOADER" == "grub" ]; then
    if grep -q "password_pbkdf2" /etc/grub.d/40_custom 2>/dev/null; then
        INSTALLED_FEATURES+=("Boot Loader Password (GRUB)")
    else
        DECLARED_FEATURES+=("Boot Loader Password (GRUB)")
    fi
elif [ "$BOOTLOADER" == "systemd-boot" ]; then
    # systemd-boot doesn't have a direct "password" feature like GRUB
    # This feature becomes "unimplemented" or "skipped" for systemd-boot users.
    # For now, we'll declare it and mark as unimplemented if chosen.
    DECLARED_FEATURES+=("Boot Loader Password (systemd-boot - Not Applicable)")
else
    DECLARED_FEATURES+=("Boot Loader Password (unknown bootloader)")
fi


# Entropy Enhancement (haveged) check (UPDATED)
if is_package_installed "haveged" && is_service_running "haveged.service"; then
    INSTALLED_FEATURES+=("Entropy Enhancement (haveged)")
else
    DECLARED_FEATURES+=("Entropy Enhancement (haveged)")
fi

# Console Lockdown (Restrict Root Login on TTYs) check
if [ -f "/etc/securetty" ] && [ ! -s "/etc/securetty" ]; then # File exists and is empty
    INSTALLED_FEATURES+=("Console Lockdown (Restrict Root Login on TTYs)")
else
    DECLARED_FEATURES+=("Console Lockdown (Restrict Root Login on TTYs)")
fi

# Automatic Terminal Logout check
if grep -q "export TMOUT=" /etc/profile; then
    INSTALLED_FEATURES+=("Automatic Terminal Logout")
else
    DECLARED_FEATURES+=("Automatic Terminal Logout")
fi

# Auditd check (UPDATED)
if is_package_installed "audit" && is_service_running "auditd.service"; then
    INSTALLED_FEATURES+=("Auditd")
else
    DECLARED_FEATURES+=("Auditd")
fi

# Rkhunter and Chkrootkit check (UPDATED)
if is_package_installed "rkhunter" && is_package_installed "chkrootkit"; then
    INSTALLED_FEATURES+=("Rootkit Detection (rkhunter, chkrootkit)")
else
    DECLARED_FEATURES+=("Rootkit Detection (rkhunter, chkrootkit)")
fi

# Timeshift check
if is_package_installed "timeshift"; then
    INSTALLED_FEATURES+=("System Snapshots (Timeshift)")
else
    DECLARED_FEATURES+=("System Snapshots (Timeshift)")
fi

echo -e "\n${BLUE}--- Detected Existing Security Features ---${NC}"
if [ ${#INSTALLED_FEATURES[@]} -eq 0 ]; then
    echo -e "${YELLOW}  No significant security features detected as already installed or configured by this script.${NC}"
else
    for feature in "${INSTALLED_FEATURES[@]}"; do
        echo -e "${GREEN}  ✔ $feature${NC}"
    done
fi
echo -e "${BLUE}-------------------------------------------${NC}\n"

echo -e "\n${BLUE}--- Features Targeted for Installation/Configuration ---${NC}"
if [ ${#DECLARED_FEATURES[@]} -eq 0 ]; then
    echo -e "${YELLOW}  All features identified as installable are already present.${NC}"
else
    for feature in "${DECLARED_FEATURES[@]}"; do
        if ! [[ " ${INSTALLED_FEATURES[@]} " =~ " ${feature} " ]]; then
            echo -e "${BLUE}  ○ $feature${NC}"
        fi
    done
fi
echo -e "${BLUE}------------------------------------------------------${NC}\n"

# --- Immediate Installations (Timeshift, Firejail) ---
# Moved these up to install immediately after prompt
print_header "Immediate Installations"

# Timeshift Installation
print_header "System Snapshots (Timeshift)"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " System Snapshots (Timeshift) " ]]; then
    echo -e "${GREEN}Timeshift is already installed. Skipping installation.${NC}"
else
    print_explanation "Timeshift creates incremental snapshots of your system, which can be invaluable for reverting to a stable state after problematic updates or configurations. This helps maintain system integrity."
    if confirm_action "Do you want to install Timeshift for system snapshots?"; then
        echo -e "${GREEN}Installing timeshift...${NC}"
        if ! pacman -S --noconfirm --needed timeshift; then
            handle_error "System Snapshots (Timeshift)" "Failed to install Timeshift. Skipping Timeshift setup."
        else
            echo -e "${GREEN}Timeshift installed successfully.${NC}"
            echo -e "${YELLOW}You can now launch Timeshift from your application menu or via 'sudo timeshift-gtk' to configure your snapshot schedule and locations.${NC}"
            echo -e "${YELLOW}It is highly recommended to store snapshots on a separate partition or external drive.${NC}"
            INSTALLED_FEATURES+=("System Snapshots (Timeshift)")
        fi
    else
        SKIPPED_FEATURES+=("System Snapshots (Timeshift)")
    fi
fi

# Firejail Installation
print_header "Application Sandboxing (Firejail)"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " Application Sandboxing (Firejail) " ]]; then
    echo -e "${GREEN}Firejail is already installed. Skipping this step.${NC}"
else
    print_explanation "Firejail creates isolated sandboxes for applications, significantly limiting their access to your system resources and files, thereby reducing the impact of potential vulnerabilities."
    if confirm_action "Do you want to install Firejail for application sandboxing?"; then
        echo -e "${GREEN}Installing firejail...${NC}"
        # Corrected: Removed 'firejail-profiles' as it's not a separate package on Arch
        if ! pacman -S --noconfirm --needed firejail; then
            handle_error "Application Sandboxing (Firejail)" "Failed to install Firejail."
        else
            echo -e "${GREEN}Firejail installed successfully.${NC}"
            echo -e "${YELLOW}To use Firejail, simply prepend 'firejail' to your application command (e.g., 'firejail firefox').${NC}"
            echo -e "${YELLOW}You can also configure Firejail to automatically sandbox applications by default (see 'firecfg' command).${NC}"
            INSTALLED_FEATURES+=("Application Sandboxing (Firejail)")
        fi
    else
        SKIPPED_FEATURES+=("Application Sandboxing (Firejail)")
    fi
fi


# --- Core System Hardening ---

print_header "I. Core System Hardening"

# 1. Firewall (UFW)
print_header "1. Firewall (UFW)"
print_explanation "UFW (Uncomplicated Firewall) is a user-friendly interface for iptables/nftables, making it easier to manage firewall rules. It will be configured to block all incoming connections by default and allow all outgoing connections, minimizing the attack surface."

# Check UFW status first
UFW_INSTALLED_PKG=$(is_package_installed "ufw")
UFW_ACTIVE_SERVICE=$(systemctl is-active --quiet "ufw.service")
UFW_STATUS_ACTIVE=$(ufw status &>/dev/null && ufw status | grep -q "Status: active") # Added &>/dev/null to suppress ufw status errors if not active

if $UFW_INSTALLED_PKG && $UFW_ACTIVE_SERVICE && $UFW_STATUS_ACTIVE; then
    echo -e "${GREEN}UFW is already installed and active. Skipping further configuration for UFW.${NC}"
    echo -e "${BLUE}Current UFW status:${NC}"
    sudo ufw status verbose
    INSTALLED_FEATURES+=("Firewall (UFW)")
elif $UFW_INSTALLED_PKG && (! $UFW_ACTIVE_SERVICE || ! $UFW_STATUS_ACTIVE); then
    echo -e "${YELLOW}UFW is installed but currently inactive or not fully enabled.${NC}"
    if confirm_action "Do you want to enable and configure UFW now?"; then
        echo -e "${GREEN}Enabling and configuring ufw...${NC}"
        systemctl enable ufw.service
        systemctl start ufw.service
        ufw default deny incoming
        ufw default allow outgoing
        ufw enable
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}UFW enabled and configured successfully.${NC}"
            echo -e "${YELLOW}Remember to open specific ports if you run services (e.g., 'sudo ufw allow ssh').${NC}"
            echo -e "${BLUE}Current UFW status:${NC}"
            ufw status verbose
            INSTALLED_FEATURES+=("Firewall (UFW)")
        else
            handle_error "Firewall (UFW)" "Failed to enable/configure UFW. Check 'systemctl status ufw' for details. UFW might not be fully operational."
            SKIPPED_FEATURES+=("Firewall (UFW) (failed to activate)")
        fi
    else
        SKIPPED_FEATURES+=("Firewall (UFW) (user opted out of activation)")
    fi
else # UFW is not installed
    echo -e "${YELLOW}UFW is not installed on your system.${NC}"
    if confirm_action "Do you want to install and configure UFW?"; then
        echo -e "${GREEN}Attempting to install ufw and iptables-nft, allowing pacman to resolve iptables conflict...${NC}"

        if ! pacman -S --noconfirm --needed ufw iptables-nft; then
            handle_error "Firewall (UFW)" "Failed to install ufw and transition to iptables-nft. This often happens if other packages strongly depend on the legacy 'iptables' package which pacman couldn't replace. Please examine pacman's output and consider manually resolving the conflict (e.g., uninstalling dependent packages that explicitly need 'iptables' or forcing their replacement, then reinstalling them if needed). UFW setup will be skipped."
            SKIPPED_FEATURES+=("Firewall (UFW) (installation failed)")
        else
            if is_package_installed "ufw" && is_package_installed "iptables-nft"; then
                echo -e "${GREEN}Enabling and configuring ufw...${NC}"
                systemctl enable ufw.service
                systemctl start ufw.service
                ufw default deny incoming
                ufw default allow outgoing
                ufw enable
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}UFW installed, enabled, and configured successfully.${NC}"
                    echo -e "${YELLOW}Remember to open specific ports if you run services (e.g., 'sudo ufw allow ssh').${NC}"
                    echo -e "${BLUE}Current UFW status:${NC}"
                    ufw status verbose
                    INSTALLED_FEATURES+=("Firewall (UFW)")
                else
                    handle_error "Firewall (UFW)" "Failed to configure UFW after successful package installation. Check 'systemctl status ufw' for details. UFW might not be fully operational."
                    SKIPPED_FEATURES+=("Firewall (UFW) (configuration failed after install)")
                fi
            else
                handle_error "Firewall (UFW)" "UFW or iptables-nft packages were not successfully installed despite pacman command completing. This is unexpected. UFW setup will be skipped."
                SKIPPED_FEATURES+=("Firewall (UFW) (package verification failed)")
            fi
        fi
    else
        SKIPPED_FEATURES+=("Firewall (UFW) (user opted out of installation)")
    fi
fi


# 2. Least Privilege & User Account Separation
print_header "2. Least Privilege & User Account Separation"
print_explanation "Using a non-root user for daily tasks and only using 'sudo' for administrative actions is fundamental to security. This section ensures your user is in the 'wheel' group and strengthens PAM for login security."

# Check if user is in wheel group
if ! id -nG "$CURRENT_USER" | grep -qw "wheel"; then
    echo -e "${RED}Your current user ('$CURRENT_USER') is not in the 'wheel' group.${NC}"
    echo -e "${YELLOW}It is highly recommended for security to use a non-root user for daily tasks and grant sudo privileges via the 'wheel' group.${NC}"
    if confirm_action "Do you want to add '$CURRENT_USER' to the 'wheel' group?"; then
        usermod -aG wheel "$CURRENT_USER"
        echo -e "${GREEN}'$CURRENT_USER' added to 'wheel' group. You will need to log out and back in for this to take effect.${NC}"
        # This isn't a "feature installed" but a user action, so not added to INSTALLED_FEATURES
    else
        echo -e "${YELLOW}Skipping adding user to wheel group. Please ensure you understand the security implications.${NC}"
    fi
else
    echo -e "${GREEN}User '$CURRENT_USER' is already in the 'wheel' group.${NC}"
fi


# PAM faillock configuration
print_header "PAM (Pluggable Authentication Modules) Faillock Configuration"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " PAM Faillock Configuration " ]]; then
    echo -e "${GREEN}PAM Faillock is already configured. Skipping this step.${NC}"
else
    print_explanation "PAM faillock module locks out users after a specified number of failed login attempts, protecting against brute-force attacks. This will apply to console and SSH logins."
    if confirm_action "Do you want to configure PAM faillock for brute-force defense?"; then
        PAM_AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
        FAILLOCK_AUTH_PRE="auth        required      pam_faillock.so preauth silent audit deny=3 unlock_time=600"
        FAILLOCK_AUTH_FAIL="auth        [default=die] pam_faillock.so authfail audit deny=3 unlock_time=600"
        FAILLOCK_ACCOUNT="account     required      pam_faillock.so"

        PAM_MODIFIED=false
        for pam_file in "${PAM_AUTH_FILES[@]}"; do
            if [ -f "$pam_file" ]; then
                echo -e "${YELLOW}Modifying $pam_file...${NC}"
                # Add preauth and authfail lines if not present
                if ! grep -qF "$FAILLOCK_AUTH_PRE" "$pam_file"; then
                    sed -i "/^auth\s*sufficient\s*pam_unix.so/i $FAILLOCK_AUTH_PRE" "$pam_file"
                    PAM_MODIFIED=true
                else
                    echo -e "${YELLOW}pam_faillock preauth line already present in $pam_file.${NC}"
                fi
                if ! grep -qF "$FAILLOCK_AUTH_FAIL" "$pam_file"; then
                    sed -i "/^auth\s*sufficient\s*pam_unix.so/a $FAILLOCK_AUTH_FAIL" "$pam_file"
                    PAM_MODIFIED=true
                else
                    echo -e "${YELLOW}pam_faillock authfail line already present in $pam_file.${NC}"
                fi

                # Add account line if not present
                if ! grep -qF "$FAILLOCK_ACCOUNT" "$pam_file"; then
                    sed -i "/^account\s*required\s*pam_unix.so/a $FAILLOCK_ACCOUNT" "$pam_file"
                    PAM_MODIFIED=true
                else
                    echo -e "${YELLOW}pam_faillock account line already present in $pam_file.${NC}"
                fi
            else
                echo -e "${RED}Warning: PAM file not found: $pam_file. Skipping.${NC}"
            fi
        done
        if [ "$PAM_MODIFIED" = true ]; then
            echo -e "${GREEN}PAM faillock configuration complete.${NC}"
            echo -e "${YELLOW}Users will be locked out for 10 minutes after 3 failed login attempts.${NC}"
            INSTALLED_FEATURES+=("PAM Faillock Configuration")
        else
            echo -e "${YELLOW}PAM faillock configuration was already mostly in place.${NC}"
            INSTALLED_FEATURES+=("PAM Faillock Configuration") # Consider it "installed" if mostly there
        fi
    else
        SKIPPED_FEATURES+=("PAM Faillock Configuration")
    fi
fi

# 3. Data Protection
print_header "3. Data Protection"

# Home Folder Permissions
print_header "Home Folder Permissions"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " Home Folder Permissions (700) " ]]; then
    echo -e "${GREEN}Home directory permissions are already set to 700. Skipping this step.${NC}"
else
    print_explanation "Restricting permissions on your home directory prevents other local users from accessing your files. We'll set it to 700 (read, write, execute for owner only)."
    if confirm_action "Do you want to set stricter home directory permissions (chmod 700)?"; then
        HOMEDIR="/home/$CURRENT_USER"
        if [ -d "$HOMEDIR" ]; then
            chmod 700 "$HOMEDIR"
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}Permissions for $HOMEDIR set to 700.${NC}"
                INSTALLED_FEATURES+=("Home Folder Permissions (700)")
            else
                handle_error "Home Folder Permissions" "Failed to set permissions for $HOMEDIR."
            fi
        else
            handle_error "Home Folder Permissions" "Home directory $HOMEDIR not found."
        fi
    else
        SKIPPED_FEATURES+=("Home Folder Permissions")
    fi
fi

# Umask Hardening
print_header "Umask Hardening"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " Umask Hardening (027/077) " ]]; then
    echo -e "${GREEN}Umask hardening is already configured. Skipping this step.${NC}"
else
    print_explanation "Umask determines the default permissions for newly created files and directories. A stricter umask (e.g., 027) prevents new files from being world-readable or writable by default, reducing accidental data exposure."
    if confirm_action "Do you want to set a stricter default umask (027 for users, 077 for root)?"; then
        echo -e "${YELLOW}Modifying /etc/profile for umask settings...${NC}"
        # Backup existing /etc/profile
        cp /etc/profile /etc/profile.bak_hardening

        # Set umask for root and users
        if ! grep -q "if \[ \"\$EUID\" -eq 0 \]; then umask 077; else umask 027; fi" /etc/profile; then
            echo "" >> /etc/profile
            echo "if [ \"\$EUID\" -eq 0 ]; then umask 077; else umask 027; fi" >> /etc/profile
            echo -e "${GREEN}Umask rules added to /etc/profile.${NC}"
            INSTALLED_FEATURES+=("Umask Hardening (027/077)")
        else
            echo -e "${YELLOW}Umask rules already present in /etc/profile.${NC}"
            INSTALLED_FEATURES+=("Umask Hardening (027/077)")
        fi

        echo -e "${GREEN}Umask hardening configured. This will take effect on next login.${NC}"
    else
        SKIPPED_FEATURES+=("Umask Hardening")
    fi
fi

# 4. Kernel Hardening & Exploit Mitigation
print_header "4. Kernel Hardening & Exploit Mitigation"

# Linux-hardened kernel
print_header "Linux-hardened Kernel"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " Linux-hardened Kernel " ]]; then
    echo -e "${GREEN}The 'linux-hardened' kernel is already installed. Skipping this step.${NC}"
else
    print_explanation "The 'linux-hardened' kernel includes various security-enhancing patches and exploit mitigations, offering a stronger baseline than the default kernel."
    if confirm_action "Do you want to install the 'linux-hardened' kernel? (Recommended, may require reboot)"; then
        echo -e "${GREEN}Installing linux-hardened...${NC}"
        if ! pacman -S --noconfirm --needed linux-hardened linux-hardened-headers; then
            handle_error "Linux-hardened Kernel" "Failed to install linux-hardened. You might need to manually resolve package conflicts."
        else
            echo -e "${GREEN}linux-hardened kernel installed. You will need to reboot to use it.${NC}"
            INSTALLED_FEATURES+=("Linux-hardened Kernel")
        fi
    else
        SKIPPED_FEATURES+=("Linux-hardened Kernel")
    fi
fi

# Sysctl Hardening
print_header "Sysctl Hardening"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " Sysctl Hardening " ]]; then
    echo -e "${GREEN}Sysctl hardening parameters are already configured. Skipping this step.${NC}"
else
    print_explanation "Sysctl parameters allow fine-tuning of kernel behavior for increased security. This will apply a set of recommended hardening settings."
    if confirm_action "Do you want to apply common sysctl hardening parameters?"; then
        SYSCTL_CONF="/etc/sysctl.d/99-security-hardening.conf"
        echo -e "${GREEN}Creating $SYSCTL_CONF with hardening parameters...${NC}"

        cat << EOF > "$SYSCTL_CONF"
# Kernel Self Protection / Exploit Mitigation
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
kernel.unprivileged_userns_clone = 0 # May break Flatpak/Docker without further config
kernel.sysrq = 0
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16
vm.stack_shuffle = 1
fs.protected_fifos = 2
fs.protected_hardlinks = 1

# Network Hardening
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Restrict ptrace
kernel.yama.ptrace_scope = 1
EOF

        sysctl --system
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Sysctl hardening parameters applied and saved to $SYSCTL_CONF.${NC}"
            echo -e "${YELLOW}Note: 'kernel.unprivileged_userns_clone = 0' may affect applications using unprivileged user namespaces like Flatpak or Docker. Adjust if necessary.${NC}"
            INSTALLED_FEATURES+=("Sysctl Hardening")
        else
            handle_error "Sysctl Hardening" "Failed to apply sysctl parameters. Check the file for syntax errors."
        fi
    else
        SKIPPED_FEATURES+=("Sysctl Hardening")
    fi
fi

# GRUB/systemd-boot Kernel Parameters
print_header "Bootloader Kernel Parameters"
# Re-detect bootloader type just before this section for robustness
BOOTLOADER=$(detect_bootloader)

if confirm_action "Do you want to add recommended hardening parameters to your kernel command line?"; then
    HARDENING_PARAMS="random.trust_cpu=on slab_nomerge init_on_alloc=1 init_on_free=1 pti=on l1tf=full,force mds=full,nosmt"
    APPAMOR_GRUB_PARAMS="apparmor=1 security=apparmor" # Parameters for both GRUB and systemd-boot

    if [ "$BOOTLOADER" == "grub" ]; then
        if [[ " ${INSTALLED_FEATURES[@]} " =~ " GRUB Kernel Parameters " ]]; then
            echo -e "${GREEN}GRUB kernel parameters are already configured. Skipping this step for GRUB.${NC}"
        else
            print_explanation "Adding specific parameters to your GRUB configuration further hardens the kernel against various attacks and enables mitigations for hardware vulnerabilities."
            GRUB_CFG="/etc/default/grub"
            if [ -f "$GRUB_CFG" ]; then
                cp "$GRUB_CFG" "$GRUB_CFG.bak_hardening" # Backup

                CURRENT_GRUB_CMDLINE=$(grep "^GRUB_CMDLINE_LINUX_DEFAULT=" "$GRUB_CFG" | sed -E 's/GRUB_CMDLINE_LINUX_DEFAULT="(.*)"/\1/')
                UPDATED_GRUB_CMDLINE="$CURRENT_GRUB_CMDLINE"

                # Add hardening params if not present
                for param in $HARDENING_PARAMS; do
                    if ! echo "$UPDATED_GRUB_CMDLINE" | grep -qw "$param"; then
                        UPDATED_GRUB_CMDLINE+=" $param"
                    fi
                done

                # Add AppArmor params if not present
                for param in $APPAMOR_GRUB_PARAMS; do
                    if ! echo "$UPDATED_GRUB_CMDLINE" | grep -qw "$param"; then
                        UPDATED_GRUB_CMDLINE+=" $param"
                    fi
                done

                # Remove leading/trailing spaces and multiple spaces
                UPDATED_GRUB_CMDLINE=$(echo "$UPDATED_GRUB_CMDLINE" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g' | sed -E 's/[[:space:]]+/ /g')

                # Update the GRUB config file
                sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=\".*\"|GRUB_CMDLINE_LINUX_DEFAULT=\"$UPDATED_GRUB_CMDLINE\"|" "$GRUB_CFG"

                echo -e "${GREEN}Hardening and AppArmor parameters added/updated in GRUB_CMDLINE_LINUX_DEFAULT in $GRUB_CFG.${NC}"
                echo -e "${YELLOW}Remember to run 'sudo grub-mkconfig -o /boot/grub/grub.cfg' after this script completes and reboot.${NC}"
                INSTALLED_FEATURES+=("GRUB Kernel Parameters")
            else
                handle_error "GRUB Kernel Parameters" "GRUB configuration file not found at $GRUB_CFG. Is GRUB installed? Skipping GRUB hardening."
                UNIMPLEMENTED_FEATURES+=("GRUB Kernel Parameters (GRUB config file not found)")
            fi
        fi # End of GRUB specific configuration
    elif [ "$BOOTLOADER" == "systemd-boot" ]; then
        if [[ " ${INSTALLED_FEATURES[@]} " =~ " systemd-boot Kernel Parameters " ]]; then
            echo -e "${GREEN}systemd-boot kernel parameters are already configured. Skipping this step for systemd-boot.${NC}"
        else
            print_explanation "Adding specific parameters to your systemd-boot entry configuration further hardens the kernel against various attacks and enables mitigations for hardware vulnerabilities."

            # --- Dynamically find and mount ESP for systemd-boot ---
            ESP_DEV_PARTUUID=$(bootctl show-efi --print-json=no --property=BootLoaderPartitionUUID 2>/dev/null)
            if [ -z "$ESP_DEV_PARTUUID" ]; then
                handle_error "systemd-boot Kernel Parameters" "Could not determine EFI System Partition PARTUUID from 'bootctl show-efi'. Manual configuration required."
                UNIMPLEMENTED_FEATURES+=("systemd-boot Kernel Parameters (ESP PARTUUID not found)")
            else
                ESP_DEV_PATH=$(find /dev/disk/by-partuuid -type l -lname "*$ESP_DEV_PARTUUID" 2>/dev/null)
                if [ -z "$ESP_DEV_PATH" ]; then
                    handle_error "systemd-boot Kernel Parameters" "Could not find device path for PARTUUID $ESP_DEV_PARTUUID. Manual configuration required."
                    UNIMPLEMENTED_FEATURES+=("systemd-boot Kernel Parameters (ESP device path not found)")
                else
                    TEMP_ESP_MOUNT_POINT="/mnt/esp_hardened_script"
                    mkdir -p "$TEMP_ESP_MOUNT_POINT"

                    echo -e "${YELLOW}Temporarily mounting ESP ($ESP_DEV_PATH) to $TEMP_ESP_MOUNT_POINT...${NC}"
                    if ! mount "$ESP_DEV_PATH" "$TEMP_ESP_MOUNT_POINT"; then
                        handle_error "systemd-boot Kernel Parameters" "Failed to temporarily mount ESP $ESP_DEV_PATH to $TEMP_ESP_MOUNT_POINT. Manual configuration required."
                        UNIMPLEMENTED_FEATURES+=("systemd-boot Kernel Parameters (ESP mount failed)")
                        rmdir "$TEMP_ESP_MOUNT_POINT" # Clean up empty dir
                    else
                        # Ensure cleanup on exit
                        # Using a unique trap name and then unsetting it later to prevent conflicts
                        # This part of the script handles its own temp mount/unmount and then disables the trap
                        trap "echo -e \"${YELLOW}Unmounting $TEMP_ESP_MOUNT_POINT...${NC}\"; umount \"$TEMP_ESP_MOUNT_POINT\" 2>/dev/null; rmdir \"$TEMP_ESP_MOUNT_POINT\" 2>/dev/null; exit" INT TERM EXIT_TEMP_MOUNT

                        SYSTEMD_BOOT_ENTRIES_DIR="$TEMP_ESP_MOUNT_POINT/loader/entries"
                        if [ ! -d "$SYSTEMD_BOOT_ENTRIES_DIR" ]; then
                            handle_error "systemd-boot Kernel Parameters" "systemd-boot entries directory not found at $SYSTEMD_BOOT_ENTRIES_DIR after mounting ESP. Manual configuration required."
                            UNIMPLEMENTED_FEATURES+=("systemd-boot Kernel Parameters (Entries dir not found in ESP)")
                        else
                            CURRENT_BOOT_ENTRY_FILENAME=$(bootctl status 2>/dev/null | grep "Current Entry:" | awk '{print $NF}')

                            TARGET_BOOT_ENTRY_FILE=""
                            if [ -n "$CURRENT_BOOT_ENTRY_FILENAME" ] && [ -f "$SYSTEMD_BOOT_ENTRIES_DIR/$CURRENT_BOOT_ENTRY_FILENAME" ]; then
                                TARGET_BOOT_ENTRY_FILE="$SYSTEMD_BOOT_ENTRIES_DIR/$CURRENT_BOOT_ENTRY_FILENAME"
                                echo -e "${GREEN}Identified current systemd-boot entry: $TARGET_BOOT_ENTRY_FILE.${NC}"
                            else
                                echo -e "${YELLOW}Could not automatically determine current systemd-boot entry. Listing available entries:${NC}"
                                ls -1 "$SYSTEMD_BOOT_ENTRIES_DIR"
                                read -rp "$(echo -e "${GREEN}Please enter the name of the systemd-boot entry file (e.g., 'arch.conf' or '2025-06-22_11-48-56_linux.conf') you want to modify: ${NC}")" USER_SELECTED_ENTRY
                                TARGET_BOOT_ENTRY_FILE="$SYSTEMD_BOOT_ENTRIES_DIR/$USER_SELECTED_ENTRY"
                            fi

                            if [ ! -f "$TARGET_BOOT_ENTRY_FILE" ]; then
                                handle_error "systemd-boot Kernel Parameters" "Target boot entry file $TARGET_BOOT_ENTRY_FILE not found. Please ensure the path and filename are correct. Manual configuration required."
                                UNIMPLEMENTED_FEATURES+=("systemd-boot Kernel Parameters (Entry file not found)")
                            else
                                # Read current options line
                                CURRENT_OPTIONS_LINE=$(grep "^options" "$TARGET_BOOT_ENTRY_FILE")

                                # If no options line found, create one
                                if [ -z "$CURRENT_OPTIONS_LINE" ]; then
                                    UPDATED_OPTIONS_LINE="options "
                                else
                                    UPDATED_OPTIONS_LINE="$CURRENT_OPTIONS_LINE"
                                fi

                                # Add hardening params if not present
                                for param in $HARDENING_PARAMS; do
                                    if ! echo "$UPDATED_OPTIONS_LINE" | grep -qw "$param"; then
                                        UPDATED_OPTIONS_LINE+=" $param"
                                    fi
                                done

                                # Add AppArmor params if not present
                                for param in $APPAMOR_GRUB_PARAMS; do
                                    if ! echo "$UPDATED_OPTIONS_LINE" | grep -qw "$param"; then
                                        UPDATED_OPTIONS_LINE+=" $param"
                                    fi
                                done

                                # Clean up extra spaces
                                UPDATED_OPTIONS_LINE=$(echo "$UPDATED_OPTIONS_LINE" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g' | sed -E 's/[[:space:]]+/ /g')

                                # Replace the line in the file, or append if it didn't exist
                                if grep -q "^options" "$TARGET_BOOT_ENTRY_FILE"; then
                                    sed -i.bak_hardening "s|^options.*|${UPDATED_OPTIONS_LINE}|" "$TARGET_BOOT_ENTRY_FILE"
                                else
                                    echo "$UPDATED_OPTIONS_LINE" >> "$TARGET_BOOT_ENTRY_FILE"
                                    echo -e "${YELLOW}Added new 'options' line to $TARGET_BOOT_ENTRY_FILE.${NC}"
                                fi

                                if [ $? -eq 0 ]; then
                                    echo -e "${GREEN}Kernel hardening parameters added/updated in $TARGET_BOOT_ENTRY_FILE.${NC}"
                                    echo -e "${YELLOW}No 'grub-mkconfig' equivalent is needed for systemd-boot. Changes will take effect on next reboot.${NC}"
                                    INSTALLED_FEATURES+=("systemd-boot Kernel Parameters")
                                else
                                    handle_error "systemd-boot Kernel Parameters" "Failed to modify $TARGET_BOOT_ENTRY_FILE. Manual edit required."
                                    UNIMPLEMENTED_FEATURES+=("systemd-boot Kernel Parameters (modification failed)")
                                fi
                            fi
                        fi
                        # Unmount the ESP
                        echo -e "${YELLOW}Unmounting $TEMP_ESP_MOUNT_POINT...${NC}"
                        umount "$TEMP_ESP_MOUNT_POINT" 2>/dev/null
                        rmdir "$TEMP_ESP_MOUNT_POINT" 2>/dev/null
                        trap - INT TERM EXIT_TEMP_MOUNT # Remove the specific trap
                    fi
                fi
            fi
        fi # End of systemd-boot specific configuration
    else # Unknown bootloader
        handle_error "Bootloader Kernel Parameters" "Could not detect a supported bootloader (GRUB or systemd-boot). Detected bootloader: ${BOOTLOADER}. Manual configuration required for kernel parameters."
        UNIMPLEMENTED_FEATURES+=("Bootloader Kernel Parameters (Unknown type)")
    fi
else # User opted out of Kernel Parameters
    SKIPPED_FEATURES+=("Bootloader Kernel Parameters")
fi


# LKRG (Linux Kernel Runtime Guard)
print_header "Linux Kernel Runtime Guard (LKRG)"
# Check if LKRG is already installed and configured
if is_package_installed "lkrg-dkms" && is_service_running "lkrg@default.service"; then
    echo -e "${GREEN}LKRG is already installed and enabled. Skipping this step.${NC}"
    INSTALLED_FEATURES+=("Linux Kernel Runtime Guard (LKRG)")
else
    print_explanation "LKRG is a kernel module that performs runtime integrity checking of the Linux kernel, detecting and preventing various exploits. It's an advanced security layer."
    # Check if LKRG is installed
    if is_package_installed "lkrg-dkms"; then
        # If package is installed, but service is not running/enabled, check if unit file exists
        if unit_file_exists "lkrg@default.service"; then
            echo -e "${YELLOW}LKRG (lkrg-dkms) is installed but its service is not active or enabled.${NC}"
            if confirm_action "Do you want to enable and start LKRG service now?"; then
                echo -e "${GREEN}Enabling and starting LKRG service...${NC}"
                systemctl enable lkrg@default.service
                systemctl start lkrg@default.service
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}LKRG enabled and started successfully.${NC}"
                    echo -e "${YELLOW}Verify LKRG status with 'sudo dmesg | grep LKRG'.${NC}"
                    INSTALLED_FEATURES+=("Linux Kernel Runtime Guard (LKRG)")
                else
                    handle_error "Linux Kernel Runtime Guard (LKRG)" "Failed to enable/start LKRG service. Check 'journalctl -xe' for details. The service unit file exists, but starting it failed."
                    SKIPPED_FEATURES+=("Linux Kernel Runtime Guard (LKRG) (failed to activate)")
                fi
            else
                SKIPPED_FEATURES+=("Linux Kernel Runtime Guard (LKRG) (user opted out of activation)")
            fi
        else
            # LKRG package is installed, but the service unit file does not exist.
            # This is the core problem. It means DKMS might not have built/installed it correctly.
            echo -e "${RED}LKRG (lkrg-dkms) is installed, but the systemd service unit 'lkrg@default.service' was not found.${NC}"
            echo -e "${YELLOW}This usually means the DKMS module or its service file did not install correctly.${NC}"
            if confirm_action "Do you want to try rebuilding the lkrg-dkms module and then enable/start the service?"; then
                echo -e "${GREEN}Rebuilding lkrg-dkms module...${NC}"
                # Get the installed version of lkrg-dkms
                LKRG_VERSION=$(pacman -Q lkrg-dkms | awk '{print $2}')
                # Rebuild DKMS module for the current running kernel
                if ! dkms autoinstall lkrg/"$LKRG_VERSION" -k "$(uname -r)"; then
                    handle_error "Linux Kernel Runtime Guard (LKRG)" "Failed to rebuild lkrg-dkms module. Please check dkms logs for details."
                    SKIPPED_FEATURES+=("Linux Kernel Runtime Guard (LKRG) (DKMS rebuild failed)")
                else
                    echo -e "${GREEN}lkrg-dkms module rebuilt. Attempting to enable and start LKRG service...${NC}"
                    systemctl enable lkrg@default.service
                    systemctl start lkrg@default.service
                    if [ $? -eq 0 ]; then
                        echo -e "${GREEN}LKRG enabled and started successfully.${NC}"
                        echo -e "${YELLOW}Verify LKRG status with 'sudo dmesg | grep LKRG'.${NC}"
                        INSTALLED_FEATURES+=("Linux Kernel Runtime Guard (LKRG)")
                    else
                        handle_error "Linux Kernel Runtime Guard (LKRG)" "Failed to enable/start LKRG service after rebuild. Check 'journalctl -xe' for details."
                        SKIPPED_FEATURES+=("Linux Kernel Runtime Guard (LKRG) (configuration failed after rebuild)")
                    fi
                fi
            else
                SKIPPED_FEATURES+=("Linux Kernel Runtime Guard (LKRG) (user opted out of rebuild)")
            fi
        fi
    else # LKRG is not installed at all
        echo -e "${YELLOW}LKRG (lkrg-dkms) is not installed on your system.${NC}"
        if confirm_action "Do you want to install and enable LKRG from AUR? (Requires 'yay' to be installed)"; then
            if command -v yay &> /dev/null; then
                echo -e "${GREEN}Importing required GPG keys for LKRG...${NC}"
                # This specific key is often needed for lkgr-dkms from AUR
                # Using --keyserver-options timeout=10 to prevent indefinite hangs
                sudo -u "$CURRENT_USER" gpg --keyserver hkps://keys.openpgp.org --keyserver-options timeout=10 --recv-keys 297AD21CF86C948081520C1805C027FD4BDC136E || \
                echo -e "${YELLOW}Warning: Failed to import GPG key for LKRG. yay might still succeed, or you may need to import it manually later.${NC}"

                echo -e "${GREEN}Installing lkrg-dkms from AUR...${NC}"
                # Run yay as the current user for security, it will prompt for sudo password internally
                if ! sudo -u "$CURRENT_USER" yay -S --noconfirm lkrg-dkms; then # No --needed for yay as it handles this
                    handle_error "Linux Kernel Runtime Guard (LKRG)" "Failed to install lkrg-dkms from AUR. Please check AUR helper output and error messages (e.g., 'makepkg as root' errors indicate yay was run with sudo incorrectly, or missing build dependencies)."
                    SKIPPED_FEATURES+=("Linux Kernel Runtime Guard (LKRG) (installation failed)")
                else
                    echo -e "${GREEN}lkrg-dkms installed. Enabling and starting LKRG service...${NC}"
                    systemctl enable lkrg@default.service
                    systemctl start lkrg@default.service
                    if [ $? -eq 0 ]; then
                        echo -e "${GREEN}LKRG enabled and started successfully.${NC}"
                        echo -e "${YELLOW}Verify LKRG status with 'sudo dmesg | grep LKRG'.${NC}"
                        INSTALLED_FEATURES+=("Linux Kernel Runtime Guard (LKRG)")
                    else
                        handle_error "Linux Kernel Runtime Guard (LKRG)" "Failed to enable/start LKRG service after installation. Check 'journalctl -xe' for details."
                        SKIPPED_FEATURES+=("Linux Kernel Runtime Guard (LKRG) (configuration failed after install)")
                    fi
                fi
            else
                handle_error "Linux Kernel Runtime Guard (LKRG)" "AUR helper 'yay' is not installed. Please install it first to proceed with LKRG."
                UNIMPLEMENTED_FEATURES+=("Linux Kernel Runtime Guard (LKRG) (AUR helper 'yay' not found)")
            fi
        else
            SKIPPED_FEATURES+=("Linux Kernel Runtime Guard (LKRG) (user opted out of installation)")
        fi
    fi
fi

# --- II. Application Security ---

print_header "II. Application Security"

# AppArmor Profiles
print_header "AppArmor Profiles"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " AppArmor Profiles " ]]; then # Check if already handled by pre-check
    echo -e "${GREEN}AppArmor is already installed and configured. Skipping this step.${NC}"
else
    print_explanation "AppArmor is a Linux Security Module (LSM) that allows you to confine programs to a limited set of resources. This enhances security by preventing compromised applications from causing widespread damage. We will install AppArmor and configure your bootloader (GRUB or systemd-boot) to enable it."
    if confirm_action "Do you want to install and configure AppArmor?"; then
        echo -e "${GREEN}Installing apparmor...${NC}"
        if ! pacman -S --noconfirm --needed apparmor; then
            handle_error "AppArmor Profiles" "Failed to install apparmor. Skipping AppArmor setup."
        else
            echo -e "${GREEN}AppArmor packages installed.${NC}"
            echo -e "${YELLOW}Ensuring AppArmor is enabled in bootloader kernel parameters...${NC}"

            APPAMOR_GRUB_PARAMS="apparmor=1 security=apparmor" # Parameters for both GRUB and systemd-boot

            if [ "$BOOTLOADER" == "grub" ]; then
                GRUB_CFG="/etc/default/grub"
                if [ -f "$GRUB_CFG" ]; then
                    CURRENT_GRUB_CMDLINE=$(grep "^GRUB_CMDLINE_LINUX_DEFAULT=" "$GRUB_CFG" | sed -E 's/GRUB_CMDLINE_LINUX_DEFAULT="(.*)"/\1/')
                    UPDATED_GRUB_CMDLINE="$CURRENT_GRUB_CMDLINE"

                    for param in $APPAMOR_GRUB_PARAMS; do
                        if ! echo "$UPDATED_GRUB_CMDLINE" | grep -qw "$param"; then
                            UPDATED_GRUB_CMDLINE+=" $param"
                        fi
                    done
                    UPDATED_GRUB_CMDLINE=$(echo "$UPDATED_GRUB_CMDLINE" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g' | sed -E 's/[[:space:]]+/ /g')
                    sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=\".*\"|GRUB_CMDLINE_LINUX_DEFAULT=\"$UPDATED_GRUB_CMDLINE\"|" "$GRUB_CFG"
                    echo -e "${GREEN}AppArmor kernel parameters added/updated in GRUB_CMDLINE_LINUX_DEFAULT in $GRUB_CFG.${NC}"
                    echo -e "${YELLOW}Remember to run 'sudo grub-mkconfig -o /boot/grub/grub.cfg' after this script completes and reboot.${NC}"
                    # Don't add to INSTALLED_FEATURES yet, as it's not fully enabled until reboot + service started
                else
                    handle_error "AppArmor Profiles" "GRUB configuration file not found at $GRUB_CFG. AppArmor kernel parameters MUST be manually added to your bootloader (e.g., 'apparmor=1 security=apparmor')."
                    UNIMPLEMENTED_FEATURES+=("AppArmor Profiles (Manual GRUB Config Required)")
                fi
            elif [ "$BOOTLOADER" == "systemd-boot" ]; then
                # --- Dynamically find and mount ESP for systemd-boot (again for AppArmor) ---
                ESP_DEV_PARTUUID=$(bootctl show-efi --print-json=no --property=BootLoaderPartitionUUID 2>/dev/null)
                if [ -z "$ESP_DEV_PARTUUID" ]; then
                    handle_error "AppArmor Profiles" "Could not determine EFI System Partition PARTUUID from 'bootctl show-efi'. Manual AppArmor kernel parameter config required."
                    UNIMPLEMENTED_FEATURES+=("AppArmor Profiles (systemd-boot ESP PARTUUID not found)")
                else
                    ESP_DEV_PATH=$(find /dev/disk/by-partuuid -type l -lname "*$ESP_DEV_PARTUUID" 2>/dev/null)
                    if [ -z "$ESP_DEV_PATH" ]; then
                        handle_error "AppArmor Profiles" "Could not find device path for PARTUUID $ESP_DEV_PARTUUID. Manual AppArmor kernel parameter config required."
                        UNIMPLEMENTED_FEATURES+=("AppArmor Profiles (systemd-boot ESP device path not found)")
                    else
                        TEMP_ESP_MOUNT_POINT="/mnt/esp_hardened_script_apparmor" # Use a different temp mount point
                        mkdir -p "$TEMP_ESP_MOUNT_POINT"

                        echo -e "${YELLOW}Temporarily mounting ESP ($ESP_DEV_PATH) to $TEMP_ESP_MOUNT_POINT for AppArmor config...${NC}"
                        if ! mount "$ESP_DEV_PATH" "$TEMP_ESP_MOUNT_POINT"; then
                            handle_error "AppArmor Profiles" "Failed to temporarily mount ESP $ESP_DEV_PATH to $TEMP_ESP_MOUNT_POINT for AppArmor. Manual config required."
                            UNIMPLEMENTED_FEATURES+=("AppArmor Profiles (ESP mount failed)")
                            rmdir "$TEMP_ESP_MOUNT_POINT"
                        else
                            # Ensure cleanup on exit
                            # Using a unique trap name and then unsetting it later to prevent conflicts
                            trap "echo -e \"${YELLOW}Unmounting $TEMP_ESP_MOUNT_POINT...${NC}\"; umount \"$TEMP_ESP_MOUNT_POINT\" 2>/dev/null; rmdir \"$TEMP_ESP_MOUNT_POINT\" 2>/dev/null; exit" INT TERM EXIT_TEMP_MOUNT_APPARMOR

                            SYSTEMD_BOOT_ENTRIES_DIR="$TEMP_ESP_MOUNT_POINT/loader/entries"
                            CURRENT_BOOT_ENTRY_FILENAME=$(bootctl status 2>/dev/null | grep "Current Entry:" | awk '{print $NF}')
                            TARGET_BOOT_ENTRY_FILE=""
                            if [ -n "$CURRENT_BOOT_ENTRY_FILENAME" ] && [ -f "$SYSTEMD_BOOT_ENTRIES_DIR/$CURRENT_BOOT_ENTRY_FILENAME" ]; then
                                TARGET_BOOT_ENTRY_FILE="$SYSTEMD_BOOT_ENTRIES_DIR/$CURRENT_BOOT_ENTRY_FILENAME"
                            else
                                TARGET_BOOT_ENTRY_FILE="$SYSTEMD_BOOT_ENTRIES_DIR/arch.conf" # Common default on Arch
                                echo -e "${YELLOW}Could not determine current systemd-boot entry. Attempting to modify default '$TARGET_BOOT_ENTRY_FILE'.${NC}"
                            fi

                            if [ -f "$TARGET_BOOT_ENTRY_FILE" ]; then
                                CURRENT_OPTIONS_LINE=$(grep "^options" "$TARGET_BOOT_ENTRY_FILE")
                                if [ -z "$CURRENT_OPTIONS_LINE" ]; then
                                    UPDATED_OPTIONS_LINE="options "
                                else
                                    UPDATED_OPTIONS_LINE="$CURRENT_OPTIONS_LINE"
                                fi

                                for param in $APPAMOR_GRUB_PARAMS; do
                                    if ! echo "$UPDATED_OPTIONS_LINE" | grep -qw "$param"; then
                                        UPDATED_OPTIONS_LINE+=" $param"
                                    fi
                                done
                                UPDATED_OPTIONS_LINE=$(echo "$UPDATED_OPTIONS_LINE" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g' | sed -E 's/[[:space:]]+/ /g')

                                if grep -q "^options" "$TARGET_BOOT_ENTRY_FILE"; then
                                    sed -i.bak_apparmor "s|^options.*|${UPDATED_OPTIONS_LINE}|" "$TARGET_BOOT_ENTRY_FILE"
                                else
                                     echo "$UPDATED_OPTIONS_LINE" >> "$TARGET_BOOT_ENTRY_FILE"
                                fi

                                if [ $? -eq 0 ]; then
                                    echo -e "${GREEN}AppArmor kernel parameters added/updated in $TARGET_BOOT_ENTRY_FILE.${NC}"
                                    echo -e "${YELLOW}No 'grub-mkconfig' equivalent is needed for systemd-boot. Changes will take effect on next reboot.${NC}"
                                else
                                    handle_error "AppArmor Profiles" "Failed to modify $TARGET_BOOT_ENTRY_FILE for AppArmor. Manual edit required."
                                    UNIMPLEMENTED_FEATURES+=("AppArmor Profiles (systemd-boot modification failed)")
                                fi # FIXED: Changed 'fn' to 'fi' here
                            else
                                handle_error "AppArmor Profiles" "systemd-boot entry file $TARGET_BOOT_ENTRY_FILE not found for AppArmor configuration. Manual edit required."
                                UNIMPLEMENTED_FEATURES+=("AppArmor Profiles (systemd-boot entry file not found)")
                            fi
                            # Unmount the ESP
                            echo -e "${YELLOW}Unmounting $TEMP_ESP_MOUNT_POINT...${NC}"
                            umount "$TEMP_ESP_MOUNT_POINT" 2>/dev/null
                            rmdir "$TEMP_ESP_MOUNT_POINT" 2>/dev/null
                            trap - INT TERM EXIT_TEMP_MOUNT_APPARMOR # Remove the specific trap
                        fi
                    fi
                fi
            else # Unknown bootloader
                handle_error "AppArmor Profiles" "Could not detect a supported bootloader (GRUB or systemd-boot) for AppArmor kernel parameters. Manual configuration required."
                UNIMPLEMENTED_FEATURES+=("AppArmor Profiles (Unknown bootloader)")
            fi


            echo -e "${GREEN}Enabling and starting AppArmor systemd service...${NC}"
            systemctl enable apparmor.service
            systemctl start apparmor.service
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}AppArmor service enabled and started.${NC}"
                echo -e "${YELLOW}You will need to reboot for AppArmor to be fully active in the kernel. This is critical for profiles to load correctly.${NC}"
                echo -e "${YELLOW}After reboot, verify with 'sudo aa-enabled' and 'sudo aa-status'.${NC}"
                echo -e "${YELLOW}Default AppArmor profiles are located in /etc/apparmor.d/. They will be loaded by the AppArmor service upon successful boot with the kernel parameters.${NC}"
                echo -e "${YELLOW}If you wish to install additional community-contributed profiles, you can look for 'apparmor-profiles-extra' or similar packages in the AUR manually.${NC}"

                # Mark as installed because the package and service are set up.
                INSTALLED_FEATURES+=("AppArmor Profiles")
            else
                handle_error "AppArmor Profiles" "Failed to enable/start AppArmor service."
            fi
        fi
    else
        SKIPPED_FEATURES+=("AppArmor Profiles")
    fi
fi

# Secure Time Synchronization (chrony with NTS)
print_header "Secure Time Synchronization (chrony with NTS)"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " Secure Time Synchronization (chrony with NTS) " ]]; then
    echo -e "${GREEN}Chrony with NTS is already configured. Skipping this step.${NC}"
else
    print_explanation "Accurate and secure time synchronization is critical to security (e.g., for TLS certificate validation). Chrony with Network Time Security (NTS) provides authenticated time synchronization, protecting against time-based attacks."
    if confirm_action "Do you want to install and configure chrony with NTS? (Requires NTS-enabled NTP servers)"; then
        echo -e "${GREEN}Installing chrony...${NC}"
        if ! pacman -S --noconfirm --needed chrony; then
            handle_error "Secure Time Synchronization (chrony with NTS)" "Failed to install chrony. Skipping secure time synchronization."
        else
            echo -e "${GREEN}chrony installed. Configuring /etc/chrony.conf...${NC}"
            CHRONY_CONF="/etc/chrony.conf"
            cp "$CHRONY_CONF" "$CHRONY_CONF.bak_hardening" # Backup

            # Clear existing server lines and add NTS-enabled ones
            sed -i '/^pool/d' "$CHRONY_CONF"
            sed -i '/^server/d' "$CHRONY_CONF"

            cat << 'EOF' >> "$CHRONY_CONF"
pool time.cloudflare.com iburst nts
pool nts.ntps.org iburst nts
pool nts.geant.net iburst nts
# Uncomment and add more NTS-enabled servers if you have preferred ones
# pool some.other.nts.server iburst nts

makestep 1.0 3
rtcsync
EOF
            echo -e "${GREEN}chrony.conf configured with NTS servers.${NC}"
            echo -e "${GREEN}Enabling and starting chronyd service...${NC}"
            systemctl enable chronyd.service
            systemctl start chronyd.service
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}chronyd enabled and started. Time will synchronize securely.${NC}"
                echo -e "${YELLOW}Verify with 'chronyc sources -v' or 'chronyc ntsdata'.${NC}"
                INSTALLED_FEATURES+=("Secure Time Synchronization (chrony with NTS)")
            else
                handle_error "Secure Time Synchronization (chrony with NTS)" "Failed to enable/start chronyd service. Check 'journalctl -xe' for errors."
            fi
        fi
    else
        SKIPPED_FEATURES+=("Secure Time Synchronization (chrony with NTS)")
    fi
fi

# --- III. Boot & Hardware Security ---

print_header "III. Boot & Hardware Security"

# Secure Boot with Custom Keys (Informative & Manual Steps)
print_header "Secure Boot with Custom Keys (Manual Steps)"
print_explanation "Implementing Secure Boot with your own keys is a powerful defense against bootkits and tampering. This is a complex process that cannot be fully automated by a script as it involves interacting with your BIOS/UEFI firmware."
if confirm_action "Do you want to learn about implementing Secure Boot with custom keys? (Highly recommended, but manual)"; then
    echo -e "${YELLOW}----------------------------------------------------------------${NC}"
    echo -e "${YELLOW}Secure Boot Manual Steps Overview:${NC}"
    echo -e "${YELLOW}1. Enter your UEFI/BIOS settings (usually by pressing DEL, F2, F10, F12 during boot).${NC}"
    echo -e "${YELLOW}2. Disable Secure Boot initially and clear any existing keys (Platform Key, KEK, DB, DBX). This is crucial!${NC}"
    echo -e "${YELLOW}3. Generate your own PK (Platform Key), KEK (Key Exchange Key), and DB (Signature Database) keys.${NC}"
    echo -e "${YELLOW}   Tools like 'efitools' or 'sbctl' (available in AUR) can help with key generation and enrollment.${NC}"
    echo -e "${YELLOW}   Example using 'sbctl' (install from AUR: 'yay -S sbctl'):${NC}"
    echo -e "${YELLOW}   - sudo sbctl create-keys${NC}"
    echo -e "${YELLOW}   - sudo sbctl enroll-keys -m # Enroll keys into firmware. '-m' keeps Microsoft keys, remove for full custom.${NC}"
    echo -e "${YELLOW}4. Sign your bootloader (e.g., GRUB EFI binary or systemd-boot EFI binary) and your Linux kernel image with your DB key.${NC}"
    echo -e "${YELLOW}   - For GRUB: Use 'sbsign' (from 'sbsigntools' package). Example: 'sbsign --key DB.key --cert DB.crt --output grubx64.efi.signed /boot/efi/EFI/GRUB/grubx64.efi' (adjust paths)${NC}"
    echo -e "${YELLOW}   - For Kernel (GRUB/systemd-boot): You might need to configure your mkinitcpio hooks or use tools like 'sbupdate' (AUR) to sign unified kernel images (UKI).${NC}"
    echo -e "${YELLOW}   - For systemd-boot EFI binary: Sign /EFI/systemd/systemd-bootx64.efi or similar path in your ESP.${NC}"
    echo -e "${YELLOW}5. Re-enable Secure Boot in your UEFI/BIOS settings.${NC}"
    echo -e "${YELLOW}6. Verify Secure Boot status (e.g., 'mokutil --sb-state' or 'bootctl status').${NC}"
    echo -e "${YELLOW}7. Consult the ArchWiki for 'Unified Extensible Firmware Interface/Secure Boot' for comprehensive and up-to-date instructions. This is essential!${NC}"
    echo -e "${BLUE}     https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot${NC}"
    echo -e "${YELLOW}----------------------------------------------------------------${NC}"
    echo -e "${YELLOW}This process is involved. Proceed with caution and thorough research.${NC}"
    UNIMPLEMENTED_FEATURES+=("Secure Boot with Custom Keys (Manual/Firmware Interaction Required)")
else
    SKIPPED_FEATURES+=("Secure Boot with Custom Keys (Discussion)")
fi

# Boot Loader Password (GRUB/systemd-boot)
print_header "Boot Loader Password (GRUB/systemd-boot)"
BOOTLOADER=$(detect_bootloader) # Re-detect bootloader type
if [ "$BOOTLOADER" == "grub" ]; then
    if [[ " ${INSTALLED_FEATURES[@]} " =~ " Boot Loader Password (GRUB) " ]]; then
        echo -e "${GREEN}GRUB password is already set. Skipping this step.${NC}"
    else
        print_explanation "Setting a GRUB password prevents unauthorized users from modifying boot parameters or booting into single-user mode, which could bypass security measures."
        if confirm_action "Do you want to set a password for GRUB?"; then
            GRUB_CONF_FILE="/etc/grub.d/40_custom" # Or another appropriate file
            if [ ! -f "/etc/default/grub" ]; then
                handle_error "Boot Loader Password (GRUB)" "/etc/default/grub not found. Is GRUB installed? Skipping GRUB password setup."
                UNIMPLEMENTED_FEATURES+=("Boot Loader Password (GRUB) (GRUB not found)")
            else
                echo -e "${YELLOW}You will be prompted to enter and confirm a password.${NC}"
                echo -e "${YELLOW}Remember this password! It will be needed at boot time to access GRUB options.${NC}"

                GRUB_PASSWORD_HASH=$(sudo -u "$CURRENT_USER" grub-mkpasswd-pbkdf2 | grep 'grub.pbkdf2.sha512' | awk '{print $NF}')
                if [ -n "$GRUB_PASSWORD_HASH" ]; then
                    echo -e "${GREEN}Adding GRUB password entry to $GRUB_CONF_FILE...${NC}"
                    # Ensure the password entry is only added once
                    if ! grep -qF "password_pbkdf2 $CURRENT_USER" "$GRUB_CONF_FILE"; then
                        cat << EOF >> "$GRUB_CONF_FILE"
set superusers="$CURRENT_USER"
password_pbkdf2 $CURRENT_USER $GRUB_PASSWORD_HASH
EOF
                        echo -e "${GREEN}GRUB password configured. Remember to run 'sudo grub-mkconfig -o /boot/grub/grub.cfg' and reboot.${NC}"
                        INSTALLED_FEATURES+=("Boot Loader Password (GRUB)")
                    else
                        echo -e "${YELLOW}GRUB password entry for '$CURRENT_USER' already seems to be present in $GRUB_CONF_FILE.${NC}"
                        INSTALLED_FEATURES+=("Boot Loader Password (GRUB)") # Consider it configured
                    fi
                else
                    handle_error "Boot Loader Password (GRUB)" "Failed to generate GRUB password hash. Is grub installed?"
                fi
            fi
        else
            SKIPPED_FEATURES+=("Boot Loader Password (GRUB)")
        fi
    fi
elif [ "$BOOTLOADER" == "systemd-boot" ]; then
    print_explanation "systemd-boot does not have a direct 'password' feature like GRUB. Its configuration files are typically on the EFI System Partition, which should ideally be secured by full disk encryption. If you need boot-time authentication, consider implementing Secure Boot with custom keys (as discussed above) or using full disk encryption with a strong passphrase."
    echo -e "${YELLOW}Boot Loader Password feature is not directly applicable to systemd-boot.${NC}"
    UNIMPLEMENTED_FEATURES+=("Boot Loader Password (systemd-boot - Not Applicable)")
else
    print_explanation "Could not detect a supported bootloader. Boot loader password configuration is skipped."
    UNIMPLEMENTED_FEATURES+=("Boot Loader Password (Unknown Bootloader)")
fi

# Entropy Enhancement (haveged)
print_header "Entropy Enhancement (haveged)"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " Entropy Enhancement (haveged) " ]]; then # Check if already handled by pre-check
    echo -e "${GREEN}Haveged is already installed and enabled. Skipping this step.${NC}"
else
    print_explanation "Entropy is crucial for strong cryptography. 'haveged' is a daemon that uses CPU jitter to generate entropy, ensuring enough randomness for cryptographic operations, especially on VMs or systems with limited hardware RNG."
    if confirm_action "Do you want to install and enable haveged?"; then
        echo -e "${GREEN}Installing haveged...${NC}"
        if ! pacman -S --noconfirm --needed haveged; then
            handle_error "Entropy Enhancement (haveged)" "Failed to install haveged. Skipping entropy enhancement."
        else
            echo -e "${GREEN}haveged installed. Enabling and starting haveged service...${NC}"
            systemctl enable haveged.service
            systemctl start haveged.service
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}haveged enabled and started. Your system's entropy will be enhanced.${NC}"
                echo -e "${YELLOW}Verify with 'cat /proc/sys/kernel/random/entropy_avail'.${NC}"
                INSTALLED_FEATURES+=("Entropy Enhancement (haveged)")
            else
                handle_error "Entropy Enhancement (haveged)" "Failed to enable/start haveged service."
            fi
        fi
    else
        SKIPPED_FEATURES+=("Entropy Enhancement (haveged)")
    fi
fi

# --- IV. User & Operational Security ---

print_header "IV. User & Operational Security"

# Console Lockdown (Restrict Root Login on TTYs)
print_header "Console Lockdown (Restrict Root Login on TTYs)"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " Console Lockdown (Restrict Root Login on TTYs) " ]]; then
    echo -e "${GREEN}Root login on TTYs is already restricted. Skipping this step.${NC}"
else
    print_explanation "Restricting direct root login on TTYs (text consoles) forces administrators to use 'sudo' from a regular user account, which logs the activity and reduces exposure of the root password. This script achieves this by ensuring /etc/securetty is empty, which prevents root login on all TTYs except those explicitly allowed by PAM (usually none by default)."
    if confirm_action "Do you want to restrict direct root login on TTYs by emptying /etc/securetty?"; then
        SECURETTY_FILE="/etc/securetty"
        if [ -f "$SECURETTY_FILE" ]; then
            if [ -s "$SECURETTY_FILE" ]; then # Check if file is not empty
                cp "$SECURETTY_FILE" "$SECURETTY_FILE.bak_hardening" # Backup
                echo -e "${YELLOW}Emptying $SECURETTY_FILE to restrict root logins...${NC}"
                echo "" > "$SECURETTY_FILE" # Empty the file
                echo -e "${GREEN}Root login restricted on TTYs. Only 'console' will be allowed (if specified by agetty).${NC}"
                echo -e "${YELLOW}You will still be able to log in as root via SSH (if enabled) or using 'sudo' from a regular user.${NC}"
                INSTALLED_FEATURES+=("Console Lockdown (Restrict Root Login on TTYs)")
            else
                echo -e "${YELLOW}$SECURETTY_FILE is already empty. Root login is likely already restricted on TTYs.${NC}"
                INSTALLED_FEATURES+=("Console Lockdown (Restrict Root Login on TTYs)")
            fi
        else
            echo -e "${YELLOW}Warning: $SECURETTY_FILE not found. Creating it as an empty file to restrict root logins.${NC}"
            touch "$SECURETTY_FILE"
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}Created empty $SECURETTY_FILE. Root login restricted on TTYs.${NC}"
                INSTALLED_FEATURES+=("Console Lockdown (Restrict Root Login on TTYs)")
            else
                handle_error "Console Lockdown (Restrict Root Login on TTYs)" "Failed to create empty $SECURETTY_FILE. Manual configuration needed."
                UNIMPLEMENTED_FEATURES+=("Console Lockdown (Restrict Root Login on TTYs) (file creation failed)")
            fi
        fi
    else
        SKIPPED_FEATURES+=("Console Lockdown (Restrict Root Login on TTYs)")
    fi
fi

# Automatic Terminal Logout
print_header "Automatic Terminal Logout"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " Automatic Terminal Logout " ]]; then
    echo -e "${GREEN}Automatic terminal logout is already configured. Skipping this step.${NC}"
else
    print_explanation "Automatically logging out inactive terminal sessions reduces the risk of unauthorized access if you leave your workstation unattended."
    if confirm_action "Do you want to configure automatic terminal logout after inactivity?"; then
        read -rp "$(echo -e "${GREEN}Enter inactivity timeout in seconds (e.g., 600 for 10 minutes): ${NC}")" TMOUT_SECONDS
        if ! [[ "$TMOUT_SECONDS" =~ ^[0-9]+$ ]] || [ "$TMOUT_SECONDS" -eq 0 ]; then
            handle_error "Automatic Terminal Logout" "Invalid timeout. Skipping automatic terminal logout."
        else
            PROFILE_FILE="/etc/profile"
            if [ -f "$PROFILE_FILE" ]; then
                if ! grep -q "export TMOUT=" "$PROFILE_FILE"; then
                    echo "" >> "$PROFILE_FILE"
                    echo "export TMOUT=$TMOUT_SECONDS" >> "$PROFILE_FILE"
                    echo -e "${GREEN}Automatic terminal logout configured for $TMOUT_SECONDS seconds in $PROFILE_FILE.${NC}"
                    echo -e "${YELLOW}This will take effect on next shell login.${NC}"
                    INSTALLED_FEATURES+=("Automatic Terminal Logout")
                else
                    sed -i "s/^export TMOUT=.*/export TMOUT=$TMOUT_SECONDS/" "$PROFILE_FILE"
                    echo -e "${GREEN}Updated automatic terminal logout to $TMOUT_SECONDS seconds in $PROFILE_FILE.${NC}"
                    INSTALLED_FEATURES+=("Automatic Terminal Logout")
                fi
            else
                handle_error "Automatic Terminal Logout" "Could not find /etc/profile. Manual configuration needed for your shell's rc file (e.g., ~/.bashrc, ~/.zshrc)."
                UNIMPLEMENTED_FEATURES+=("Automatic Terminal Logout (/etc/profile not found)")
            fi
        fi
    else
        SKIPPED_FEATURES+=("Automatic Terminal Logout")
    fi
fi

# --- V. Auditing & Monitoring ---

print_header "V. Auditing & Monitoring"

# Auditd
print_header "Auditd"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " Auditd " ]]; then # Check if already handled by pre-check
    echo -e "${GREEN}Auditd is already installed and enabled. Skipping this step.${NC}"
else
    print_explanation "Auditd is the userspace component of the Linux Auditing System, providing a way to log and monitor security-relevant events on your system. This is crucial for detecting and investigating security incidents."
    if confirm_action "Do you want to install and enable auditd?"; then
        echo -e "${GREEN}Installing audit...${NC}"
        if ! pacman -S --noconfirm --needed audit; then
            handle_error "Auditd" "Failed to install audit. Skipping auditd setup."
        else
            echo -e "${GREEN}audit installed. Enabling and starting auditd service...${NC}"
            systemctl enable auditd.service
            systemctl start auditd.service
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}auditd enabled and started.${NC}"
                echo -e "${YELLOW}You will need to configure audit rules in /etc/audit/rules.d/ to log specific events.${NC}"
                echo -e "${BLUE}  https://wiki.archlinux.org/title/Auditd${NC}"
                echo -e "${YELLOW}A basic set of rules could include: ${NC}"
                echo -e "   -w /etc/passwd -p wa -k identity # Monitor changes to user info"
                echo -e "   -w /etc/shadow -p wa -k identity # Monitor changes to password hashes"
                echo -e "   -w /etc/group -p wa -k identity # Monitor changes to group info"
                echo -e "   -w /etc/sudoers -p wa -k sudoers # Monitor changes to sudoers"
                echo -e "   -a always,exit -F arch=b64 -S execve -k exec # Monitor program execution"
                INSTALLED_FEATURES+=("Auditd")
            else
                handle_error "Auditd" "Failed to enable/start Auditd service."
            fi
        fi
    else
        SKIPPED_FEATURES+=("Auditd")
    fi
fi

# Rkhunter and Chkrootkit
print_header "Rootkit Detection (rkhunter, chkrootkit)"
if [[ " ${INSTALLED_FEATURES[@]} " =~ " Rootkit Detection (rkhunter, chkrootkit) " ]]; then # Check if already handled by pre-check
    echo -e "${GREEN}Rkhunter and Chkrootkit are already installed. Skipping this step.${NC}"
else
    print_explanation "Rkhunter (Rootkit Hunter) and Chkrootkit are tools designed to scan for rootkits, backdoors, and other malware on your system. They provide an important layer of post-compromise detection."
    if confirm_action "Do you want to install rkhunter and chkrootkit?"; then
        echo -e "${GREEN}Installing rkhunter and chkrootkit...${NC}"
        if ! pacman -S --noconfirm --needed rkhunter chkrootkit; then
            handle_error "Rootkit Detection (rkhunter, chkrootkit)" "Failed to install rkhunter or chkrootkit. Skipping rootkit detection tools."
        else
            echo -e "${GREEN}rkhunter and chkrootkit installed.${NC}"
            echo -e "${YELLOW}Recommended usage:${NC}"
            echo -e "  - ${GREEN}sudo rkhunter --update${NC} (Update database)"
            echo -e "  - ${GREEN}sudo rkhunter --check${NC} (Run a scan)"
            echo -e "  - ${GREEN}sudo chkrootkit${NC} (Run a scan)"
            echo -e "${YELLOW}Consider setting up daily cron jobs for these tools and reviewing their output.${NC}"
            INSTALLED_FEATURES+=("Rootkit Detection (rkhunter, chkrootkit)")
        fi
    else
        SKIPPED_FEATURES+=("Rootkit Detection (rkhunter, chkrootkit)")
    fi
fi


# --- Final Summary ---

print_header "Hardening Process Summary"
echo -e "${BLUE}Here's a summary of the security features addressed by this script:${NC}\n"

echo -e "${BLUE}--- Features Successfully Applied ---${NC}"
if [ ${#INSTALLED_FEATURES[@]} -eq 0 ]; then
    echo -e "${YELLOW}  No features were successfully applied by this script.${NC}"
else
    for feature in "${INSTALLED_FEATURES[@]}"; do
        echo -e "${GREEN}  ✔ $feature${NC}"
    done
fi
echo -e "\n--------------------------------------------------------------------------\n" # Separator for readability

echo -e "${BLUE}--- Features Not Applied / With Issues ---${NC}"
# Combine all non-installed features into a single array for easier iteration
ALL_NON_INSTALLED_FEATURES=()
for feature in "${SKIPPED_FEATURES[@]}"; do
    ALL_NON_INSTALLED_FEATURES+=("→ $feature")
done
for feature in "${FAILED_FEATURES[@]}"; do
    ALL_NON_INSTALLED_FEATURES+=("✖ $feature")
done
for feature in "${UNIMPLEMENTED_FEATURES[@]}"; do
    ALL_NON_INSTALLED_FEATURES+=("⚠ $feature")
done

if [ ${#ALL_NON_INSTALLED_FEATURES[@]} -eq 0 ]; then
    echo -e "${GREEN}  All targeted features were successfully applied or already configured.${NC}"
else
    for feature in "${ALL_NON_INSTALLED_FEATURES[@]}"; do
        # Non-success features already have color codes and symbols
        echo -e "${YELLOW}  $feature${NC}" # Using YELLOW for all non-success for consistency, symbols provide distinction
    done
fi
echo -e "\n${BLUE}--------------------------------------------------------------------------${NC}\n"


echo -e "${BLUE}Most of the selected Kicksecure security features have been adapted and configured for your Arch Linux system.${NC}"
echo -e "${BLUE}Please review the summary carefully for any errors or manual steps required.${NC}"

if confirm_action "A reboot is highly recommended to apply all changes (e.g., kernel parameters, AppArmor). Do you want to reboot now?"; then
    echo -e "${GREEN}Rebooting system... Goodbye!${NC}"
    reboot
else
    echo -e "${YELLOW}Please remember to reboot your system manually at your earliest convenience to ensure all security changes take effect.${NC}"
    # Conditionally remind about grub-mkconfig based on detected bootloader
    # Re-detect bootloader here one last time, in case it changed mid-script (e.g., if GRUB was installed)
    FINAL_BOOTLOADER_CHECK=$(detect_bootloader)
    if [ "$FINAL_BOOTLOADER_CHECK" == "grub" ]; then
        echo -e "${YELLOW}Also, don't forget to run 'sudo grub-mkconfig -o /boot/grub/grub.cfg' if GRUB changes were made (especially after kernel or AppArmor changes).${NC}"
    elif [ "$FINAL_BOOTLOADER_CHECK" == "systemd-boot" ]; then
        echo -e "${YELLOW}No specific 'mkconfig' command is needed for systemd-boot. Changes will take effect on next reboot.${NC}"
    fi
fi

echo -e "${BLUE}Thank you for using the Arch Linux Hardening Script.${NC}"
exit 0
