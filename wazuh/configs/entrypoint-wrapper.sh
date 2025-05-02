#!/bin/bash

# Function to copy configuration files from mounted volume to their destination
copy_configs() {
  if [ -d /opt/wazuh-mounted-configs/etc ]; then
    mkdir -p /var/ossec/etc
    cp -rf /opt/wazuh-mounted-configs/etc/* /var/ossec/etc/ 2>/dev/null || true
    echo "Copied custom etc files"
  fi
  
  if [ -d /opt/wazuh-mounted-configs/groups ]; then
    mkdir -p /var/ossec/etc/shared
    cp -rf /opt/wazuh-mounted-configs/groups/* /var/ossec/etc/shared/ 2>/dev/null || true
    echo "Copied agent group files"
  fi
  
  if [ -d /opt/wazuh-mounted-configs/wodles ]; then
    mkdir -p /var/ossec/wodles/custom
    cp -rf /opt/wazuh-mounted-configs/wodles/* /var/ossec/wodles/custom/ 2>/dev/null || true
    chmod -R +x /var/ossec/wodles/custom/*.sh 2>/dev/null || true
    echo "Copied custom wodles"
  fi
  
  if [ -d /opt/wazuh-mounted-configs/rules ]; then
    mkdir -p /var/ossec/etc/rules
    cp -rf /opt/wazuh-mounted-configs/rules/* /var/ossec/etc/rules/ 2>/dev/null || true
    echo "Copied custom rules"
  fi
  
  if [ -d /opt/wazuh-mounted-configs/decoders ]; then
    mkdir -p /var/ossec/etc/decoders
    cp -rf /opt/wazuh-mounted-configs/decoders/* /var/ossec/etc/decoders/ 2>/dev/null || true
    echo "Copied custom decoders"
  fi
}

# Copy configs when container starts
copy_configs

# Start the original entrypoint
exec /entrypoint.sh "$@"