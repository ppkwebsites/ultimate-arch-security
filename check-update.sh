#!/bin/bash

# Script to check for Arch Linux system updates and notify via dunst
# Usage: ./check-update.sh [setup|test]

# Function to detect desktop environment
detect_desktop_environment() {
    if [ -n "$XDG_CURRENT_DESKTOP" ]; then
        echo "$XDG_CURRENT_DESKTOP" | tr '[:upper:]' '[:lower:]'
    elif [ -n "$DESKTOP_SESSION" ]; then
        echo "$DESKTOP_SESSION" | tr '[:upper:]' '[:lower:]'
    else
        echo "unknown"
    fi
}

# Function to provide dunst instructions based on desktop environment
provide_dunst_instructions() {
    local de="$1"
    echo "Instructions to ensure dunst runs after reboot:"
    case "$de" in
        hyprland)
            echo "For Hyprland, add the following line to ~/.config/hypr/hyprland.conf:"
            echo "exec-once = dunst &"
            ;;
        gnome)
            echo "For GNOME, dunst should start automatically. If not, add 'dunst &' to your startup applications."
            ;;
        kde|plasma)
            echo "For KDE Plasma, add 'dunst &' to your autostart scripts in System Settings."
            ;;
        *)
            echo "Unknown desktop environment. Add 'dunst &' to your window manager or desktop environment's startup configuration."
            ;;
    esac
}

# Function to check and install dunst and libnotify
check_and_install_dunst() {
    if ! command -v dunst >/dev/null 2>&1 || ! command -v dunstify >/dev/null 2>&1; then
        echo "dunst or dunstify (libnotify) not found. Attempting to install..."
        sudo pacman -S --noconfirm dunst libnotify
        if ! command -v dunst >/dev/null 2>&1 || ! command -v dunstify >/dev/null 2>&1; then
            echo "Error: Failed to install dunst or libnotify."
            echo "To install manually, run the following command:"
            echo "sudo pacman -S dunst libnotify"
            echo "Additional steps to fix installation issues:"
            echo "1. Ensure you have an active internet connection."
            echo "2. Update the package database: sudo pacman -Syy"
            echo "3. Check for errors in /var/log/pacman.log"
            exit 1
        else
            echo "dunst and libnotify installed successfully."
            local de=$(detect_desktop_environment)
            provide_dunst_instructions "$de"
        fi
    else
        echo "dunst and dunstify (libnotify) are already installed. Skipping installation."
    fi

    # Verify dunst is running
    if ! pgrep -x dunst >/dev/null; then
        echo "Warning: dunst is not running. Attempting to start it..."
        dunst &
        sleep 1
        if ! pgrep -x dunst >/dev/null; then
            echo "Error: Failed to start dunst."
            echo "To fix this, try the following steps:"
            echo "1. Check dunst configuration in ~/.config/dunst/dunstrc"
            echo "2. Start dunst manually: dunst &"
            echo "3. Ensure dunst starts on boot using your desktop environment's startup settings."
            echo "4. Verify libnotify is working: notify-send 'Test notification'"
            exit 1
        else
            echo "dunst started successfully."
        fi
    fi

    # Always show manual install command for libnotify
    echo
    echo "**When you encounter an error, manually install dunst and libnotify by running:"
    echo "  sudo pacman -S dunst libnotify"
    echo
}

# Function to set up systemd service and timer
setup_service_and_timer() {
    local script_path
    script_path=$(realpath "$0")
    local service_dir="$HOME/.config/systemd/user"
    local service_file="$service_dir/check-update.service"
    local timer_file="$service_dir/check-update.timer"

    echo "Setting up systemd service and timer..."
    mkdir -p "$service_dir"

    # Create service file
    cat > "$service_file" << EOF
[Unit]
Description=Check for Arch Linux updates

[Service]
Type=oneshot
ExecStart=$script_path
EOF

    # Create timer file
    cat > "$timer_file" << EOF
[Unit]
Description=Run update check weekly

[Timer]
OnCalendar=weekly
Persistent=true
Unit=check-update.service

[Install]
WantedBy=timers.target
EOF

    echo "Created service file: $service_file"
    echo "Created timer file: $timer_file"

    # Set up user session environment
    export XDG_RUNTIME_DIR=/run/user/$(id -u)
    export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus

    echo "Enabling and starting the timer..."
    systemctl --user daemon-reload
    systemctl --user enable check-update.timer
    systemctl --user start check-update.timer

    if [ $? -eq 0 ]; then
        echo "Systemd timer and service have been set up and started. The script will now run weekly."
    else
        echo "Error: Failed to enable or start the systemd timer."
        exit 1
    fi
}

# Main script logic
case "$1" in
    setup)
        check_and_install_dunst
        setup_service_and_timer
        exit 0
        ;;
    test)
        check_and_install_dunst
        dunstify -u normal "Test Notification" "This is a test notification from check-update.sh."
        exit 0
        ;;
    *)
        check_and_install_dunst
        echo "Checking for updates..."
        if ! command -v checkupdates >/dev/null 2>&1; then
            echo "Installing pacman-contrib for checkupdates..."
            sudo pacman -S --noconfirm pacman-contrib
        fi
        if checkupdates > /dev/null; then
            dunstify -u critical "System Updates Available" "Run 'sudo pacman -Syu' to update your system."
        else
            dunstify -u normal "System Up to Date" "No updates are available at this time."
        fi
        ;;
esac
