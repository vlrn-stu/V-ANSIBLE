#!/bin/bash
# Wazuh Agent Installation with YARA for Ubuntu
# Simple script to install Wazuh agent and YARA on Ubuntu

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_header() {
    echo -e "\n${BLUE}======================================================================${NC}"
    echo -e "${BLUE}    $1${NC}"
    echo -e "${BLUE}======================================================================${NC}"
}

print_success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

print_info() {
    echo -e "${YELLOW}[INFO] $1${NC}"
}

print_error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    print_error "This script must be run as root"
    echo "Please run with sudo or as root user"
    exit 1
fi

# Configuration - MODIFY THESE VALUES
WAZUH_MANAGER="10.69.0.240"
WAZUH_AGENT_GROUP="Ubuntu"
WAZUH_REGISTRATION_PASSWORD="wazuh1234"
WAZUH_AGENT_NAME=""  # Leave empty to use hostname

print_header "WAZUH AGENT INSTALLATION FOR UBUNTU"
print_info "Manager: $WAZUH_MANAGER"
print_info "Group: $WAZUH_AGENT_GROUP"

# Install dependencies
print_header "INSTALLING DEPENDENCIES"
apt-get update
apt-get install -y curl apt-transport-https gnupg
if [ $? -ne 0 ]; then
    print_error "Failed to install dependencies"
    exit 1
fi
print_success "Dependencies installed"

# Install Wazuh agent
print_header "INSTALLING WAZUH AGENT"

# Add Wazuh repository
print_info "Adding Wazuh repository"
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

# Update and install
print_info "Installing Wazuh agent package"
apt-get update
apt-get install -y wazuh-agent

if [ $? -ne 0 ]; then
    print_error "Failed to install Wazuh agent"
    exit 1
fi
print_success "Wazuh agent installed"

# Configure Wazuh agent
print_header "CONFIGURING WAZUH AGENT"
print_info "Setting manager connection"

# Set Wazuh manager
/var/ossec/bin/agent-auth -m "$WAZUH_MANAGER" -P "$WAZUH_REGISTRATION_PASSWORD" -G "$WAZUH_AGENT_GROUP" ${WAZUH_AGENT_NAME:+-A "$WAZUH_AGENT_NAME"}

if [ $? -ne 0 ]; then
    print_error "Agent registration failed"
    exit 1
fi
print_success "Agent registered with manager"

# Set manager IP in ossec.conf
sed -i "s/<address>.*<\/address>/<address>$WAZUH_MANAGER<\/address>/" /var/ossec/etc/ossec.conf

# Enable and start agent
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

if ! systemctl is-active --quiet wazuh-agent; then
    print_error "Failed to start Wazuh agent"
    exit 1
fi
print_success "Wazuh agent configured and started"

# Install YARA
print_header "INSTALLING YARA"

# Install YARA dependencies
print_info "Installing YARA dependencies"
apt-get install -y automake libtool make gcc pkg-config libssl-dev libjansson-dev libmagic-dev

print_info "Downloading and compiling YARA"
cd /tmp
curl -LO https://github.com/VirusTotal/yara/archive/v4.3.1.tar.gz
tar -xzf v4.3.1.tar.gz
cd yara-4.3.1
./bootstrap.sh
./configure --enable-magic --enable-dotnet
make -j$(nproc)
make install
ldconfig

# Create YARA rules directory
mkdir -p /var/ossec/yara/rules

# Create basic YARA rule
print_info "Creating basic YARA rule"
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

# Create simple YARA scanner script
print_info "Creating YARA scanner script"
mkdir -p /var/ossec/wodles/yara
cat > /var/ossec/wodles/yara/yara_scan.sh << 'EOL'
#!/bin/bash
RULES_DIR="/var/ossec/yara/rules"
SCAN_PATHS=("/bin" "/usr/bin" "/tmp" "/var/tmp" "/dev/shm")

echo "{\"yara_scan\": {"
echo "  \"timestamp\": \"$(date +"%Y-%m-%d %H:%M:%S")\"," 
echo "  \"hostname\": \"$(hostname)\","
echo "  \"results\": ["

first=true
for path in "${SCAN_PATHS[@]}"; do
    results=$(find "$path" -type f -not -path "/proc/*" -maxdepth 2 2>/dev/null | xargs -I{} yara -r "$RULES_DIR"/*.yar {} 2>/dev/null)
    if [ -n "$results" ]; then
        while IFS= read -r line; do
            if [ -n "$line" ]; then
                rule_name=$(echo "$line" | awk '{print $1}')
                file_path=$(echo "$line" | awk '{$1=""; print $0}' | awk '{$1=$1};1')
                if [ "$first" = true ]; then
                    first=false
                else
                    echo ","
                fi
                echo "    {\"rule\":\"$rule_name\", \"file\":\"$file_path\"}"
            fi
        done <<< "$results"
    fi
done

echo "  ]"
echo "}}"
EOL

chmod +x /var/ossec/wodles/yara/yara_scan.sh
chown -R root:ossec /var/ossec/yara
chmod -R 750 /var/ossec/yara
chown root:ossec /var/ossec/wodles/yara/yara_scan.sh

# Configure Wazuh to use YARA
print_info "Configuring YARA integration with Wazuh"
grep -q "<wodle name=\"command\">" /var/ossec/etc/ossec.conf
if [ $? -eq 0 ]; then
    # Add YARA wodle to existing config
    sed -i '/<\/wodle>/a \
  <wodle name="command">\
    <disabled>no</disabled>\
    <tag>yara-scan</tag>\
    <command>/var/ossec/wodles/yara/yara_scan.sh</command>\
    <interval>1d</interval>\
    <run_on_start>yes</run_on_start>\
    <timeout>300</timeout>\
  </wodle>' /var/ossec/etc/ossec.conf
else
    # Add first wodle
    sed -i '/<\/ossec_config>/i \
  <wodle name="command">\
    <disabled>no</disabled>\
    <tag>yara-scan</tag>\
    <command>/var/ossec/wodles/yara/yara_scan.sh</command>\
    <interval>1d</interval>\
    <run_on_start>yes</run_on_start>\
    <timeout>300</timeout>\
  </wodle>' /var/ossec/etc/ossec.conf
fi

# Restart agent
systemctl restart wazuh-agent

print_header "INSTALLATION COMPLETE"
print_success "Wazuh agent installed and registered to group: $WAZUH_AGENT_GROUP"
print_success "YARA installed and configured to run daily scans"
print_info "YARA rules location: /var/ossec/yara/rules"
print_info "YARA scanner script: /var/ossec/wodles/yara/yara_scan.sh"

# Show agent status
echo ""
systemctl status wazuh-agent --no-pager | grep "Active:"
echo ""
print_info "To check Wazuh agent status: systemctl status wazuh-agent"
print_info "To view agent logs: tail -f /var/ossec/logs/ossec.log"

exit 0