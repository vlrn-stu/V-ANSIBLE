#!/bin/bash
# Simple Wazuh Agent Installation for Ubuntu
# Uses the official Wazuh dashboard-generated installation commands

# Colors for better readability
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This script must be run as root${NC}"
    echo "Please run with sudo or as root user"
    exit 1
fi

# Prompt for manager IP
echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}      WAZUH AGENT INSTALLATION FOR UBUNTU         ${NC}"
echo -e "${BLUE}==================================================${NC}"

# Prompt for manager IP
echo -ne "${YELLOW}Enter Wazuh manager IP address [10.69.0.240]: ${NC}"
read manager_ip
if [ -z "$manager_ip" ]; then
    manager_ip="10.69.0.240"
fi

# Prompt for agent name (optional)
echo -ne "${YELLOW}Enter agent name (leave blank to use hostname): ${NC}"
read agent_name

# Prompt for agent group
echo -ne "${YELLOW}Enter agent group [Ubuntu]: ${NC}"
read agent_group
if [ -z "$agent_group" ]; then
    agent_group="Ubuntu"
fi

echo -e "\n${BLUE}Installing Wazuh agent with these settings:${NC}"
echo -e "  Manager IP: ${GREEN}$manager_ip${NC}"
echo -e "  Agent Group: ${GREEN}$agent_group${NC}"
if [ -n "$agent_name" ]; then
    echo -e "  Agent Name: ${GREEN}$agent_name${NC}"
else
    echo -e "  Agent Name: ${GREEN}$(hostname)${NC} (default hostname)"
fi

echo -e "\n${YELLOW}Starting installation in 3 seconds...${NC}"
sleep 3

# Download and install Wazuh agent
echo -e "\n${BLUE}Downloading and installing Wazuh agent...${NC}"
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.11.2-1_amd64.deb -O wazuh-agent.deb

# Set manager IP and install
if [ -n "$agent_name" ]; then
    WAZUH_MANAGER="$manager_ip" WAZUH_AGENT_NAME="$agent_name" WAZUH_AGENT_GROUP="$agent_group" dpkg -i ./wazuh-agent.deb
else
    WAZUH_MANAGER="$manager_ip" WAZUH_AGENT_GROUP="$agent_group" dpkg -i ./wazuh-agent.deb
fi

if [ $? -ne 0 ]; then
    echo -e "${RED}[ERROR] Failed to install Wazuh agent${NC}"
    exit 1
fi

# Start agent
echo -e "\n${BLUE}Starting Wazuh agent...${NC}"
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

# Check service status
if systemctl is-active --quiet wazuh-agent; then
    echo -e "\n${GREEN}[SUCCESS] Wazuh agent installed and running!${NC}"
    echo -e "${YELLOW}Agent details:${NC}"
    echo -e "  Manager: ${GREEN}$manager_ip${NC}"
    echo -e "  Group: ${GREEN}$agent_group${NC}"
    echo -e "  Status: ${GREEN}Running${NC}"
else
    echo -e "\n${RED}[ERROR] Wazuh agent is not running${NC}"
    echo -e "${YELLOW}Check status with:${NC} systemctl status wazuh-agent"
    exit 1
fi

# Cleanup
rm -f wazuh-agent.deb

# Installation of YARA (if needed)
echo -e "\n${YELLOW}Do you want to install YARA? (y/n):${NC} "
read install_yara

if [[ "$install_yara" == "y" || "$install_yara" == "Y" ]]; then
    echo -e "\n${BLUE}Installing YARA...${NC}"
    apt-get update
    apt-get install -y automake libtool make gcc pkg-config libssl-dev libjansson-dev libmagic-dev
    
    cd /tmp
    wget -q https://github.com/VirusTotal/yara/archive/v4.3.1.tar.gz
    tar -xzf v4.3.1.tar.gz
    cd yara-4.3.1
    ./bootstrap.sh
    ./configure --enable-magic
    make -j$(nproc)
    make install
    ldconfig
    
    if command -v yara &> /dev/null; then
        echo -e "${GREEN}[SUCCESS] YARA installed!${NC}"
    else
        echo -e "${RED}[ERROR] YARA installation failed${NC}"
    fi
fi

echo -e "\n${GREEN}Installation complete!${NC}"
echo -e "${YELLOW}To check agent status:${NC} systemctl status wazuh-agent"
echo -e "${YELLOW}To view agent logs:${NC} tail -f /var/ossec/logs/ossec.log"