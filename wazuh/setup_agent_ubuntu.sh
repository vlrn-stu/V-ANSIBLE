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

# Verify internet connectivity
echo -e "\n${BLUE}Checking internet connectivity...${NC}"
if ! ping -c 1 8.8.8.8 &> /dev/null; then
    echo -e "${YELLOW}Internet connectivity check failed. This may affect package downloads.${NC}"
    echo -e "Do you want to continue anyway? (y/n): "
    read continue_anyway
    if [[ "$continue_anyway" != "y" && "$continue_anyway" != "Y" ]]; then
        echo -e "${RED}Installation aborted.${NC}"
        exit 1
    fi
fi

# Verify Wazuh manager is reachable
echo -e "\n${BLUE}Checking manager connection...${NC}"
# Prompt for manager IP
echo -ne "${YELLOW}Enter Wazuh manager IP address [10.69.0.240]: ${NC}"
read manager_ip
if [ -z "$manager_ip" ]; then
    manager_ip="10.69.0.240"
fi

# Check if manager is reachable
ping -c 1 $manager_ip &> /dev/null
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}Warning: Cannot ping Wazuh manager at $manager_ip${NC}"
    echo -e "This may be due to firewall restrictions or the manager being unreachable."
    echo -e "Do you want to continue anyway? (y/n): "
    read continue_anyway
    if [[ "$continue_anyway" != "y" && "$continue_anyway" != "Y" ]]; then
        echo -e "${RED}Installation aborted.${NC}"
        exit 1
    fi
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

# Install dependencies first
echo -e "\n${BLUE}Installing dependencies...${NC}"
apt-get update -y
apt-get install -y wget apt-transport-https gnupg curl

# Download and install Wazuh agent with retry
echo -e "\n${BLUE}Downloading and installing Wazuh agent...${NC}"
max_retries=3
retry_count=0

while [ $retry_count -lt $max_retries ]; do
    echo -e "${YELLOW}Download attempt $((retry_count+1))/${max_retries}...${NC}"
    wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.11.2-1_amd64.deb -O wazuh-agent.deb
    
    if [ -s wazuh-agent.deb ]; then
        echo -e "${GREEN}Download successful${NC}"
        break
    else
        retry_count=$((retry_count+1))
        echo -e "${YELLOW}Download failed. Retrying in 5 seconds...${NC}"
        sleep 5
    fi
done

if [ ! -s wazuh-agent.deb ]; then
    echo -e "${RED}[ERROR] Failed to download Wazuh agent after $max_retries attempts${NC}"
    echo -e "${YELLOW}Would you like to try an alternative installation method using repository? (y/n):${NC} "
    read use_alternative
    
    if [[ "$use_alternative" == "y" || "$use_alternative" == "Y" ]]; then
        echo -e "\n${BLUE}Setting up Wazuh repository...${NC}"
        
        # Import the GPG key
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
        chmod 644 /usr/share/keyrings/wazuh.gpg
        
        # Add the repository
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list > /dev/null
        
        # Update and install
        apt-get update
        echo -e "\n${BLUE}Installing Wazuh agent from repository...${NC}"
        apt-get install -y wazuh-agent
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}[ERROR] Failed to install Wazuh agent from repository${NC}"
            exit 1
        else
            echo -e "${GREEN}Successfully installed Wazuh agent from repository${NC}"
        fi
    else
        echo -e "${RED}Installation aborted.${NC}"
        exit 1
    fi
else
    # Set manager IP and install
    echo -e "\n${BLUE}Installing Wazuh agent package...${NC}"
    if [ -n "$agent_name" ]; then
        WAZUH_MANAGER="$manager_ip" WAZUH_AGENT_NAME="$agent_name" WAZUH_AGENT_GROUP="$agent_group" dpkg -i ./wazuh-agent.deb
    else
        WAZUH_MANAGER="$manager_ip" WAZUH_AGENT_GROUP="$agent_group" dpkg -i ./wazuh-agent.deb
    fi
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}[ERROR] Failed to install Wazuh agent package${NC}"
        exit 1
    fi
fi

# Ensure proper configuration
echo -e "\n${BLUE}Setting up final configurations...${NC}"

# Make sure manager address is set correctly
echo -e "${YELLOW}Ensuring manager address is properly configured...${NC}"
sed -i "s/<address>.*<\/address>/<address>$manager_ip<\/address>/" /var/ossec/etc/ossec.conf

# Set agent group manually if needed
if [ -n "$agent_group" ]; then
    echo -e "${YELLOW}Setting agent group to $agent_group...${NC}"
    echo "$agent_group" > /var/ossec/etc/shared/agent.conf
fi

# Set agent name if provided
if [ -n "$agent_name" ]; then
    echo -e "${YELLOW}Setting agent name to $agent_name...${NC}"
    sed -i "s/<client_name>.*<\/client_name>/<client_name>$agent_name<\/client_name>/" /var/ossec/etc/ossec.conf 2>/dev/null
    if [ $? -ne 0 ]; then
        # If the tag doesn't exist, add it
        sed -i "/<client>/a \ \ <client_name>$agent_name<\/client_name>" /var/ossec/etc/ossec.conf
    fi
fi

# Start agent
echo -e "\n${BLUE}Starting Wazuh agent...${NC}"
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent

# Check service status
sleep 3
if systemctl is-active --quiet wazuh-agent; then
    echo -e "\n${GREEN}[SUCCESS] Wazuh agent installed and running!${NC}"
    echo -e "${YELLOW}Agent details:${NC}"
    echo -e "  Manager: ${GREEN}$manager_ip${NC}"
    echo -e "  Group: ${GREEN}$agent_group${NC}"
    echo -e "  Status: ${GREEN}Running${NC}"
else
    echo -e "\n${RED}[WARNING] Wazuh agent service is not running${NC}"
    echo -e "${YELLOW}Attempting to fix...${NC}"
    
    # Troubleshooting steps
    echo -e "1. Checking configuration..."
    /var/ossec/bin/ossec-logtest -t
    
    echo -e "2. Restarting service..."
    systemctl restart wazuh-agent
    
    sleep 3
    if systemctl is-active --quiet wazuh-agent; then
        echo -e "${GREEN}Service is now running!${NC}"
    else
        echo -e "${RED}Service still not running.${NC}"
        echo -e "${YELLOW}Check status with:${NC} systemctl status wazuh-agent"
        echo -e "${YELLOW}View logs with:${NC} tail -f /var/ossec/logs/ossec.log"
    fi
fi

# Clean up
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
        
        # Create a basic YARA rule as example
        mkdir -p /var/ossec/yara/rules
        cat > /var/ossec/yara/rules/suspicious.yar << 'EOL'
rule SuspiciousFiles {
    meta:
        description = "Detects suspicious file characteristics"
        author = "Wazuh"
        reference = "Internal"
    strings:
        $s1 = "eval(base64_decode" nocase
        $s2 = "system(" nocase
        $s3 = "shell_exec(" nocase
        $s4 = "preg_replace" nocase
        $s5 = "str_rot13" nocase
        $s6 = "/dev/shm/" nocase
        $s7 = "/tmp/." nocase
    condition:
        2 of them
}
EOL
        chmod 750 /var/ossec/yara/rules/suspicious.yar
        echo -e "${GREEN}Created sample YARA rule at /var/ossec/yara/rules/suspicious.yar${NC}"
    else
        echo -e "${RED}[ERROR] YARA installation failed${NC}"
    fi
fi

echo -e "\n${GREEN}Installation complete!${NC}"
echo -e "${YELLOW}Here's how to verify everything is working:${NC}"
echo -e "1. Check agent status: ${GREEN}systemctl status wazuh-agent${NC}"
echo -e "2. View agent logs: ${GREEN}tail -f /var/ossec/logs/ossec.log${NC}"
echo -e "3. Test connection to manager: ${GREEN}ping $manager_ip${NC}"
echo -e "4. Check agent info: ${GREEN}/var/ossec/bin/agent_control -i${NC}"

echo -e "\n${BLUE}Thank you for installing Wazuh!${NC}"

exit 0