#!/bin/bash

# Shell script for setting up the project environment

echo "Starting setup..."

# Update package list
echo "Updating package list..."
sudo apt update -y

# Upgrade packages
echo "Upgrading package list..."
sudo apt upgrade -y

# Install required packages
echo "Installing required packages..."
sudo apt install -y g++ make pkg-config libssl-dev libgmp-dev libgmpxx4ldbl

# Verify installation
echo "Verifying installations..."
if command -v g++ &>/dev/null && command -v make &>/dev/null && command -v pkg-config &>/dev/null; then
    echo "All required packages installed successfully."
else
    echo "Some packages failed to install. Please check your package manager."
    exit 1
fi

# Print success message
echo "Setup complete. You can now build the project using 'make'."

