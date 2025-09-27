------------------------
# ultimate-arch-security
------------------------

It litterally secures your Arch linux implementing most Kicksecure settings and features.
This README provides instructions for setting up and running your Arch Linux hardening and security monitoring scripts.

Arch Linux Security Scripts
These scripts are designed to enhance the security of your Arch Linux system, inspired by features from Kicksecure, and provide ongoing monitoring for updates, malware, and AppArmor policy violations.

Prerequisites
Download/Clone: Place all scripts (arch-secure.sh, check-update.sh, hardenclamav.sh, apparmor-clamav-warnings.sh) into the same directory.

Make Executable: Ensure all scripts have execute permissions:

Bash

chmod +x *.sh
Target System: These scripts are specifically written for an Arch Linux system.

Root Access: Most scripts must be run using sudo.

1. Main Hardening Script: arch-secure.sh
This script is the central entry point. It runs a comprehensive set of hardening procedures and includes prompts asking the user to confirm the implementation of each feature, including prompts that lead to the functionality of check-update.sh (for weekly update reminders) and hardenclamav.sh (for ClamAV hardening).

Script Name	Purpose	Execution
arch-secure.sh	Main script to apply various security features and system hardening.	Runs hardening, prompts for choices, and integrates logic from check-update and hardenclamav.
To Run arch-secure.sh:

Open your terminal and navigate to the script directory.

Run the script with sudo:

Bash

sudo ./arch-secure.sh
Follow the on-screen prompts. The script will ask for user confirmation (Y/n) before implementing most changes, with 'Y' as the default choice.

2. Separate Execution Instructions
All scripts can be run individually. The following sections detail how to run each one separately, including the necessary initial setup mode for some.

2.1. check-update.sh (Requires Setup Mode First)
This script is designed to run periodically (usually weekly) via a systemd user timer to check for system updates and send a desktop notification via dunst. It must be run in setup mode first to install dependencies and configure the timer.

Script Name	Purpose	Setup Command	Run Command (Manual Check)
check-update.sh	Installs dunst and sets up a systemd user timer for weekly update reminders.	./check-update.sh setup	./check-update.sh
Steps to Run check-update.sh Separately:

Setup Mode (Initial Run): Run the script with the setup argument as the non-root user who will receive the notifications:

Bash

./check-update.sh setup
This command will install dunst and libnotify (using sudo internally) and configure the systemd --user timer to run the script weekly.

Manual Check (After Setup): To manually check for updates and receive a notification immediately, run:

Bash

./check-update.sh
2.2. hardenclamav.sh
This script focuses on configuring and hardening ClamAV by installing ClamAV and the signature update tool Fangfrisch, enabling real-time on-access scanning, and setting up automatic updates.

Script Name	Purpose	Execution
hardenclamav.sh	Installs and configures ClamAV, sets up Fangfrisch for third-party signatures, and enables on-access scanning.	Requires sudo and prompts for user choices during execution.
To Run hardenclamav.sh Separately:

Run the script with sudo (it requires a non-root user running it via sudo):

Bash

sudo ./hardenclamav.sh
Follow the prompts to confirm package installation and configuration choices.

2.3. apparmor-clamav-warnings.sh (Requires Setup Mode First)
This script checks the system logs for AppArmor denial warnings and ClamAV virus detections, sending a desktop notification if any are found. The script is structured to perform its setup, including configuring ClamAV's monitored paths and enabling a weekly systemd timer, upon its initial run.

Script Name	Purpose	Setup/Run Command	Execution Details
apparmor-clamav-warnings.sh	Monitors logs for AppArmor denials and ClamAV detections, and configures weekly log scanning.	sudo ./apparmor-clamav-warnings.sh	The initial run configures ClamAV monitored paths and sets up a weekly systemd timer/service.
To Run apparmor-clamav-warnings.sh Separately (Setup and First Run):

Run the script with sudo:

Bash

sudo ./apparmor-clamav-warnings.sh
This command will perform the setup, which includes:

Configuring ClamAV to monitor specified paths (e.g., /home/ppk, /srv, /var/www/html).

Setting necessary file access control lists (setfacl) for the clamav user.

Creating and enabling the apparmor-clamav-warnings.timer for weekly execution.

The script will also run its log checks immediately.

-------------------------
Troubleshooting Solutions
-------------------------

Here are solutions for common issues you might encounter when running your Arch Linux security scripts.

1. check-update.sh Troubleshooting: Manual libnotify Installation
The check-update.sh script relies on libnotify to work with dunst for desktop notifications. If the script fails to install this dependency, you can install it manually.

Problem: Notifications are not appearing, and the script failed to install dependencies.
Solution: Manually install the libnotify and dunst packages.

Command:

Bash

sudo pacman -S --noconfirm libnotify dunst
2. hardenclamav.sh Troubleshooting: Restarting clamd@scan.service
The ClamAV on-access scanning feature (clamonacc) is critical for real-time protection. The hardenclamav.sh script should enable and start the service, but if it fails, you can manage it manually using systemctl. The script uses the clamd@scan.service template for this.

Problem: Real-time scanning is not active after running hardenclamav.sh.
Solution: Manually enable and start the clamd@scan.service.

Commands:

Bash

# 1. Enable the service to ensure it starts on boot
sudo systemctl enable clamd@scan.service

# 2. Start the service immediately
sudo systemctl start clamd@scan.service

# 3. Check the status to confirm it's running
sudo systemctl status clamd@scan.service
3. apparmor-clamav-warnings.sh Troubleshooting: Testing ClamAV Real-Time Scanning
The best way to confirm that your clamonacc service (started by hardenclamav.sh) and your monitoring script (apparmor-clamav-warnings.sh) are working is to use the EICAR test file. This is a non-viral file universally detected by antivirus programs to safely test functionality.

The apparmor-clamav-warnings.sh script mentions using the EICAR string and specifies the path as EICAR_PATH="/home/$USER/script/eicar_test.txt".

Problem: Need to confirm real-time scanning is active and the warning script works.
Solution: Create the EICAR test file in a monitored location and check the results.

Steps and Commands:

Create the Test Directory:
Ensure the script directory exists in your home directory (the user defined in the script).

Bash

mkdir -p ~/script
Create the EICAR Test File:
Write the official EICAR test string into a file using the path defined in your script:

Bash

echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > ~/script/eicar_test.txt
If ClamAV's on-access scanner (clamonacc) is working, it should immediately detect and quarantine/delete this file upon its creation.

Check for Detection:
If the file is deleted immediately, real-time scanning is working. If not, wait a moment and then check the ClamAV log file defined in your script (/var/log/clamav/clamd.log):

Bash

sudo grep 'EICAR-Test-File' /var/log/clamav/clamd.log
You should see an entry indicating the file was detected and, ideally, moved or removed.

Run the Warning Script:
Manually run the apparmor-clamav-warnings.sh script with sudo. Since a detection should be recorded in the log, the script should read it and fire a desktop notification (if dunst is running).

Bash

sudo ./apparmor-clamav-warnings.sh
