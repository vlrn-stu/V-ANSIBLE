#!/bin/bash
# Complete automated Wazuh deployment on Proxmox

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_header() {
    echo -e "\n${BLUE}================================================================================${NC}"
    echo -e "${BLUE}    $1${NC}"
    echo -e "${BLUE}================================================================================${NC}\n"
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

read_input() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"
    local is_password="$4"
    
    if [ "$is_password" = true ]; then
        echo -ne "${YELLOW}$prompt [${NC}$default${YELLOW}]: ${NC}"
        read -s input
        echo ""
    else
        echo -ne "${YELLOW}$prompt [${NC}$default${YELLOW}]: ${NC}"
        read input
    fi
    
    if [ -z "$input" ]; then
        input="$default"
    fi
    
    eval "$var_name=\"$input\""
    
    if [ "$is_password" = true ]; then
        echo -e "${GREEN}✓ Set to: ********${NC}"
    else
        echo -e "${GREEN}✓ Set to: $input${NC}"
    fi
}

fetch_wazuh_versions() {
    print_header "FETCHING AVAILABLE WAZUH VERSIONS"
    
    print_info "Fetching available versions from GitHub..."
    
    if ! command -v curl &> /dev/null; then
        print_error "curl is not installed."
        WAZUH_VERSIONS=("v4.7.0" "v4.8.0" "v4.9.0" "v4.10.0" "v4.11.0" "v4.11.1" "v4.11.2" "v4.11.3" "v4.12.0" "v4.13.0")
        return
    fi
    
    tag_list=$(curl -s https://api.github.com/repos/wazuh/wazuh-docker/tags?per_page=100 | grep -o '"name": "[^"]*"' | cut -d'"' -f4)
    
    WAZUH_VERSIONS=()
    while IFS= read -r tag; do
        if [[ $tag == v* ]]; then
            WAZUH_VERSIONS+=("$tag")
        fi
    done <<< "$tag_list"
    
    if [ ${#WAZUH_VERSIONS[@]} -eq 0 ]; then
        WAZUH_VERSIONS=("v4.7.0" "v4.8.0" "v4.9.0" "v4.10.0" "v4.11.0" "v4.11.1" "v4.11.2" "v4.11.3" "v4.12.0" "v4.13.0")
    fi
    
    print_success "Found ${#WAZUH_VERSIONS[@]} Wazuh versions."
}

select_wazuh_version() {
    print_header "SELECT WAZUH VERSION"
    
    fetch_wazuh_versions
    
    if [ ${#WAZUH_VERSIONS[@]} -eq 0 ]; then
        print_error "No Wazuh versions found. Using default version v4.11.1."
        wazuh_version="v4.11.1"
        return
    fi
    
    echo -e "${BLUE}Available Wazuh versions:${NC}"
    
    sorted_versions=($(printf '%s\n' "${WAZUH_VERSIONS[@]}" | sort -rV))
    
    total_versions=${#sorted_versions[@]}
    versions_to_show=$((total_versions > 15 ? 15 : total_versions))
    
    for ((i=0; i<versions_to_show; i++)); do
        echo -e "  ${GREEN}$((i+1)).${NC} ${sorted_versions[$i]}"
    done
    
    if [ $total_versions -gt 15 ]; then
        echo -e "\n${YELLOW}Showing newest 15 versions out of $total_versions available versions.${NC}"
        echo -ne "${YELLOW}Do you want to see all versions? (y/n) [n]: ${NC}"
        read show_all
        
        if [[ "$show_all" == "y" || "$show_all" == "Y" ]]; then
            echo -e "\n${BLUE}All available Wazuh versions:${NC}"
            for ((i=0; i<total_versions; i++)); do
                if [ $((i % 3)) -eq 0 ]; then
                    echo -ne "  "
                fi
                echo -ne "${GREEN}$((i+1)).${NC} ${sorted_versions[$i]}    "
                if [ $((i % 3)) -eq 2 ]; then
                    echo ""
                fi
            done
            if [ $(((total_versions-1) % 3)) -ne 2 ]; then
                echo ""
            fi
        fi
    fi
    
    echo -ne "\n${YELLOW}Enter the number of the version to use or type a specific version [1]: ${NC}"
    read version_selection
    
    if [ -z "$version_selection" ]; then
        version_selection=1
    fi
    
    if [[ "$version_selection" =~ ^[0-9]+$ ]]; then
        index=$((version_selection - 1))
        
        if [ $index -ge 0 ] && [ $index -lt $total_versions ]; then
            wazuh_version="${sorted_versions[$index]}"
        else
            print_error "Invalid selection. Using newest version ${sorted_versions[0]}."
            wazuh_version="${sorted_versions[0]}"
        fi
    else
        if [[ "$version_selection" == v* ]]; then
            wazuh_version="$version_selection"
        else
            wazuh_version="v$version_selection"
        fi
        
        version_exists=false
        for v in "${WAZUH_VERSIONS[@]}"; do
            if [ "$v" == "$wazuh_version" ]; then
                version_exists=true
                break
            fi
        done
        
        if [ "$version_exists" = false ]; then
            print_info "Warning: Version $wazuh_version was not found in the list of known versions."
            echo -ne "${YELLOW}Continue with this version anyway? (y/n) [n]: ${NC}"
            read continue_anyway
            
            if [[ "$continue_anyway" != "y" && "$continue_anyway" != "Y" ]]; then
                print_info "Using default version v4.11.1 instead."
                wazuh_version="v4.11.1"
            fi
        fi
    fi
    
    print_success "Selected Wazuh version: $wazuh_version"
}

generate_ansible_playbook() {
    print_header "GENERATING ANSIBLE PLAYBOOK"
    
    cat > deploy_wazuh.yml << EOL
# Complete automated Wazuh deployment on Proxmox
- name: Deploy Wazuh on Proxmox using Ubuntu and Docker Compose
  hosts: localhost
  gather_facts: false
  vars:
    vm_name: "${vm_name}"
    vm_id: ${vm_id}
    vm_cores: ${vm_cores}
    vm_memory: ${vm_memory}
    vm_disk_size: "${vm_disk_size}"
    vm_storage: "${vm_storage}"
    vm_ip: "${vm_ip}"
    vm_netmask: "${vm_netmask}"
    vm_gateway: "${vm_gateway}"
    vm_password: "${vm_password}"
    wazuh_username: "${wazuh_username}"
    wazuh_password: "${wazuh_password}"
    wazuh_version: "${wazuh_version}"
    ubuntu_image_url: "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
    ubuntu_image_name: "ubuntu-22.04.img"
    local_configs_path: "${PWD}/configs"
    
  tasks:
    - name: Install necessary packages on Proxmox host
      shell: |
        apt-get update && apt-get install -y sshpass wget
      become: yes
      
    - name: Check if VM with specified ID already exists
      shell: qm status {{ vm_id }} 2>/dev/null || echo "NotFound"
      register: vm_exists
      changed_when: false
      failed_when: false
      
    - name: Stop and destroy VM if it exists
      shell: qm stop {{ vm_id }} && sleep 5 && qm destroy {{ vm_id }} --purge
      when: "'NotFound' not in vm_exists.stdout"
      ignore_errors: yes
      
    - name: Download Ubuntu cloud image
      get_url:
        url: "{{ ubuntu_image_url }}"
        dest: "/tmp/{{ ubuntu_image_name }}"
        mode: '0644'
        force: no
        
    - name: Create new VM
      shell: |
        qm create {{ vm_id }} \\
          --name {{ vm_name }} \\
          --memory {{ vm_memory }} \\
          --cores {{ vm_cores }} \\
          --cpu x86-64-v2 \\
          --net0 virtio,bridge=vmbr0
      register: vm_created
        
    - name: Import disk from Ubuntu cloud image
      shell: |
        qm importdisk {{ vm_id }} /tmp/{{ ubuntu_image_name }} {{ vm_storage }}
      register: disk_imported
        
    - name: Attach the imported disk to the VM
      shell: |
        qm set {{ vm_id }} --scsihw virtio-scsi-pci --scsi0 {{ vm_storage }}:vm-{{ vm_id }}-disk-0
      
    - name: Add cloud-init drive
      shell: |
        qm set {{ vm_id }} --ide2 {{ vm_storage }}:cloudinit
      
    - name: Configure cloud-init for user, password and network
      shell: |
        qm set {{ vm_id }} \\
          --ciuser root \\
          --cipassword "{{ vm_password }}" \\
          --ipconfig0 ip={{ vm_ip }}/{{ vm_netmask }},gw={{ vm_gateway }} \\
          --sshkeys /root/.ssh/authorized_keys
      ignore_errors: yes
    
    - name: Configure boot order
      shell: |
        qm set {{ vm_id }} --boot c --bootdisk scsi0
    
    - name: Resize disk to specified size
      shell: |
        qm resize {{ vm_id }} scsi0 {{ vm_disk_size }}
    
    - name: Start the VM
      shell: |
        qm start {{ vm_id }}
    
    - name: Wait for VM to boot (120 seconds)
      pause:
        seconds: 120
    
    - name: Wait for SSH to become available
      wait_for:
        host: "{{ vm_ip }}"
        port: 22
        state: started
        delay: 10
        timeout: 300
    
    - name: Add SSH key to known_hosts
      shell: |
        ssh-keyscan -H {{ vm_ip }} >> ~/.ssh/known_hosts
      ignore_errors: yes
    
    - name: Configure SSH connection to avoid host key checking
      shell: |
        mkdir -p ~/.ssh
        echo "Host {{ vm_ip }}
          StrictHostKeyChecking no
          UserKnownHostsFile=/dev/null" > ~/.ssh/config
      
    - name: Wait for cloud-init to complete
      shell: |
        timeout 180 bash -c 'until sshpass -p "{{ vm_password }}" ssh -o StrictHostKeyChecking=no root@{{ vm_ip }} "cloud-init status --wait"; do sleep 10; done'
      ignore_errors: yes
    
    - name: Wait for apt to be available on VM
      shell: |
        for i in \$(seq 1 30); do
          if sshpass -p "{{ vm_password }}" ssh -o StrictHostKeyChecking=no root@{{ vm_ip }} "which apt"; then
            exit 0
          fi
          echo "Waiting for apt to be available... attempt \$i/30"
          sleep 5
        done
        exit 1
      ignore_errors: yes
    
    - name: Install Docker with curl method
      shell: |
        sshpass -p "{{ vm_password }}" ssh -o StrictHostKeyChecking=no root@{{ vm_ip }} "apt-get update && apt-get install -y curl && curl -fsSL https://get.docker.com | sh"
      ignore_errors: no
      
    - name: Install Docker Compose and Git
      shell: |
        sshpass -p "{{ vm_password }}" ssh -o StrictHostKeyChecking=no root@{{ vm_ip }} "apt-get install -y docker-compose-plugin git"
      ignore_errors: no
      
    - name: Increase max_map_count
      shell: |
        sshpass -p "{{ vm_password }}" ssh -o StrictHostKeyChecking=no root@{{ vm_ip }} "sysctl -w vm.max_map_count=262144"
      ignore_errors: no
      
    - name: Make max_map_count setting permanent
      shell: |
        sshpass -p "{{ vm_password }}" ssh -o StrictHostKeyChecking=no root@{{ vm_ip }} "echo 'vm.max_map_count=262144' >> /etc/sysctl.conf"
      ignore_errors: no

    - name: Clone Wazuh Docker repository version {{ wazuh_version }}
      shell: |
        sshpass -p "{{ vm_password }}" ssh -o StrictHostKeyChecking=no root@{{ vm_ip }} "git clone -b {{ wazuh_version }} https://github.com/wazuh/wazuh-docker.git /opt/wazuh-docker"
      ignore_errors: no

    - name: Create Wazuh deployment directory
      shell: |
        sshpass -p "{{ vm_password }}" ssh -o StrictHostKeyChecking=no root@{{ vm_ip }} "mkdir -p /opt/wazuh"
      ignore_errors: no

    - name: Copy single-node deployment files to Wazuh directory
      shell: |
        sshpass -p "{{ vm_password }}" ssh -o StrictHostKeyChecking=no root@{{ vm_ip }} "cp -r /opt/wazuh-docker/single-node/* /opt/wazuh/"
      ignore_errors: no

    - name: Check if local configs directory exists
      stat:
        path: "{{ local_configs_path }}"
      register: config_dir
      delegate_to: localhost

    - name: Check if local configs directory contains files
      find:
        paths: "{{ local_configs_path }}"
        file_type: any
        excludes: ".gitkeep"
      register: config_files
      delegate_to: localhost
      when: config_dir.stat.exists and config_dir.stat.isdir

    - name: Copy local configuration files to VM
      shell: |
        echo "Copying local configuration files from {{ local_configs_path }} to VM..."
        sshpass -p "{{ vm_password }}" scp -r -o StrictHostKeyChecking=no "{{ local_configs_path }}"/* root@{{ vm_ip }}:/opt/wazuh/
        echo "Local configuration files copied successfully."
      register: copy_configs_result
      when: config_dir.stat.exists and config_dir.stat.isdir and config_files.matched > 0
      
    - name: Display local config files copy result
      debug:
        msg: "{{ copy_configs_result.stdout_lines | default('No config files found to copy', true) }}"
      when: config_dir.stat.exists and config_dir.stat.isdir

    - name: Examine default configuration files
      shell: |
        sshpass -p "{{ vm_password }}" ssh -o StrictHostKeyChecking=no root@{{ vm_ip }} "ls -la /opt/wazuh/ && \
        cat /opt/wazuh/docker-compose.yml | grep -A 20 environment || echo 'No environment section found' && \
        find /opt/wazuh -name '*.yml' -type f | xargs grep -l 'password' || echo 'No password files found'"
      register: config_examination
      ignore_errors: yes

    - name: Display configuration examination results
      debug:
        var: config_examination.stdout_lines
      when: config_examination.stdout is defined

    - name: Create custom .env file with credentials
      copy:
        dest: "/tmp/wazuh.env"
        content: |
          # Wazuh indexer variables
          INDEXER_USERNAME={{ wazuh_username }}
          INDEXER_PASSWORD={{ wazuh_password }}
          ADMIN_USERNAME={{ wazuh_username }}
          ADMIN_PASSWORD={{ wazuh_password }}
          # Dashboard variables
          DASHBOARD_USERNAME={{ wazuh_username }}
          DASHBOARD_PASSWORD={{ wazuh_password }}
          # API variables
          API_USERNAME={{ wazuh_username }}
          API_PASSWORD={{ wazuh_password }}
          # Other variables 
          WAZUH_API_USERNAME={{ wazuh_username }}
          WAZUH_API_PASSWORD={{ wazuh_password }}
          ELASTIC_USERNAME={{ wazuh_username }}
          ELASTIC_PASSWORD={{ wazuh_password }}
      delegate_to: localhost

    - name: Copy .env file to VM
      shell: |
        sshpass -p "{{ vm_password }}" scp -o StrictHostKeyChecking=no /tmp/wazuh.env root@{{ vm_ip }}:/opt/wazuh/.env
      ignore_errors: no

    - name: Modify docker-compose.yml to use environment variables from .env file
      shell: |
        sshpass -p "{{ vm_password }}" ssh -o StrictHostKeyChecking=no root@{{ vm_ip }} "cd /opt/wazuh && \
        if [ -f 'docker-compose.yml' ]; then \
          sed -i 's/DASHBOARD_USERNAME=admin/DASHBOARD_USERNAME=${DASHBOARD_USERNAME}/g' docker-compose.yml && \
          sed -i 's/DASHBOARD_PASSWORD=SecretPassword/DASHBOARD_PASSWORD=${DASHBOARD_PASSWORD}/g' docker-compose.yml && \
          sed -i 's/API_USERNAME=wazuh/API_USERNAME=${API_USERNAME}/g' docker-compose.yml && \
          sed -i 's/API_PASSWORD=wazuh/API_PASSWORD=${API_PASSWORD}/g' docker-compose.yml && \
          sed -i 's/INDEXER_USERNAME=admin/INDEXER_USERNAME=${INDEXER_USERNAME}/g' docker-compose.yml && \
          sed -i 's/INDEXER_PASSWORD=SecretPassword/INDEXER_PASSWORD=${INDEXER_PASSWORD}/g' docker-compose.yml; \
        fi"
      ignore_errors: yes

    - name: Update opensearch_dashboards.yml config
      shell: |
        sshpass -p "{{ vm_password }}" ssh -o StrictHostKeyChecking=no root@{{ vm_ip }} "cd /opt/wazuh && \
        if [ -f 'config/wazuh_dashboard/opensearch_dashboards.yml' ]; then \
          sed -i 's/^opensearch.username:.*/opensearch.username: {{ wazuh_username }}/g' config/wazuh_dashboard/opensearch_dashboards.yml && \
          sed -i 's/^opensearch.password:.*/opensearch.password: {{ wazuh_password }}/g' config/wazuh_dashboard/opensearch_dashboards.yml; \
        fi"
      ignore_errors: yes

    - name: Update Wazuh API configuration
      shell: |
        sshpass -p "{{ vm_password }}" ssh -o StrictHostKeyChecking=no root@{{ vm_ip }} "cd /opt/wazuh && \
        if [ -d 'config/wazuh_manager' ]; then \
          mkdir -p config/wazuh_manager/api_configuration && \
          echo 'user: {{ wazuh_username }}' > config/wazuh_manager/api_configuration/custom_user.yml && \
          echo 'password: {{ wazuh_password }}' >> config/wazuh_manager/api_configuration/custom_user.yml; \
        fi"
      ignore_errors: yes

    - name: Generate SSL certificates
      shell: |
        sshpass -p "{{ vm_password }}" ssh -o StrictHostKeyChecking=no root@{{ vm_ip }} "cd /opt/wazuh && docker compose -f generate-indexer-certs.yml run --rm generator"
      ignore_errors: no

    - name: Start Wazuh with Docker Compose
      shell: |
        sshpass -p "{{ vm_password }}" ssh -o StrictHostKeyChecking=no root@{{ vm_ip }} "cd /opt/wazuh && docker compose up -d"
      ignore_errors: no

    - name: Wait for Wazuh API to be available (3 minutes)
      pause:
        seconds: 180
        prompt: "Waiting for Wazuh to fully initialize..."

    - name: Get container status
      shell: |
        sshpass -p "{{ vm_password }}" ssh -o StrictHostKeyChecking=no root@{{ vm_ip }} "cd /opt/wazuh && docker compose ps"
      register: container_status

    - name: Check for actual credentials used in each service
      shell: |
        sshpass -p "{{ vm_password }}" ssh -o StrictHostKeyChecking=no root@{{ vm_ip }} "cd /opt/wazuh && \
        echo 'Checking Docker environment variables:' && \
        docker compose config | grep -E 'USERNAME|PASSWORD' || echo 'No credentials found in docker-compose' && \
        echo -e '\nChecking for Wazuh dashboard users:' && \
        docker compose exec wazuh.dashboard sh -c 'cat /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml | grep -A 5 -B 5 password' || echo 'Could not check dashboard users'"
      register: creds_check
      ignore_errors: yes

    - name: Display Wazuh deployment information
      debug:
        msg: |
          ============= Wazuh Deployment Information =============
          
          Wazuh Dashboard: https://{{ vm_ip }}
          Username: {{ wazuh_username }}
          Password: {{ wazuh_password }}
          
          Wazuh Manager: {{ vm_ip }}:55000
          
          VM Information:
          - Name: {{ vm_name }}
          - ID: {{ vm_id }}
          - IP Address: {{ vm_ip }}
          - CPU Cores: {{ vm_cores }}
          - Memory: {{ vm_memory }} MB
          - Disk Size: {{ vm_disk_size }}
          
          Wazuh Version: {{ wazuh_version }}
          
          Container Status:
          {{ container_status.stdout }}
          
          TROUBLESHOOTING INFO:
          ---------------------
          If you cannot log in with the credentials above, try these fallback credentials:
          - Username: admin
          - Password: SecretPassword
          
          - Username: wazuh
          - Password: wazuh
          
          - Username: wazuh-wui
          - Password: wazuh-wui
          
          Note: It might take up to 5 minutes for all services to fully initialize.
          
          For troubleshooting:
          1. Check container status: ssh root@{{ vm_ip }} "cd /opt/wazuh && docker compose ps"
          2. View logs: ssh root@{{ vm_ip }} "cd /opt/wazuh && docker compose logs -f"
          3. Check current credentials: ssh root@{{ vm_ip }} "cd /opt/wazuh && docker compose config | grep -E 'USERNAME|PASSWORD'"
          4. Restart containers: ssh root@{{ vm_ip }} "cd /opt/wazuh && docker compose restart"
          
          ========================================================
EOL

    print_success "Ansible playbook generated: deploy_wazuh.yml"
}

collect_configuration() {
    print_header "VM CONFIGURATION"
    
    read_input "Enter the name of the VM" "wazuh" "vm_name"
    read_input "Enter the VM ID" "100" "vm_id"
    read_input "Enter the number of CPU cores for the VM" "4" "vm_cores"
    read_input "Enter the memory size (in MB) for the VM" "8192" "vm_memory"
    read_input "Enter the disk size for the VM (e.g., 150G)" "150G" "vm_disk_size"
    read_input "Enter the storage location for the VM (e.g., local-lvm)" "local-lvm" "vm_storage"
    read_input "Enter the IP address for the VM" "192.168.0.70" "vm_ip"
    read_input "Enter the netmask for the VM" "24" "vm_netmask"
    read_input "Enter the gateway for the VM" "192.168.0.1" "vm_gateway"
    read_input "Enter the root password for the VM" "wazuh1234" "vm_password" true
    
    print_header "WAZUH CONFIGURATION"
    
    select_wazuh_version
    
    read_input "Enter the Wazuh admin username" "admin" "wazuh_username"
    read_input "Enter the Wazuh admin password" "SecretPassword" "wazuh_password" true
    
    if [ -d "./configs" ]; then
        file_count=$(find ./configs -type f -not -name ".gitkeep" | wc -l)
        if [ "$file_count" -gt 0 ]; then
            print_info "Found $file_count files in the local 'configs' directory. These will be copied to the Wazuh VM."
        else
            print_info "The 'configs' directory exists but contains no configuration files."
        fi
    else
        print_info "No local 'configs' directory found. Create a 'configs' directory in the same location as this script to include custom configuration files."
    fi
}

display_summary() {
    print_header "CONFIGURATION SUMMARY"
    
    echo -e "${BLUE}VM Configuration:${NC}"
    echo -e "  Name:           ${YELLOW}$vm_name${NC}"
    echo -e "  ID:             ${YELLOW}$vm_id${NC}"
    echo -e "  CPU Cores:      ${YELLOW}$vm_cores${NC}"
    echo -e "  Memory:         ${YELLOW}$vm_memory MB${NC}"
    echo -e "  Disk Size:      ${YELLOW}$vm_disk_size${NC}"
    echo -e "  Storage:        ${YELLOW}$vm_storage${NC}"
    echo -e "  IP Address:     ${YELLOW}$vm_ip${NC}"
    echo -e "  Netmask:        ${YELLOW}$vm_netmask${NC}"
    echo -e "  Gateway:        ${YELLOW}$vm_gateway${NC}"
    
    echo -e "\n${BLUE}Wazuh Configuration:${NC}"
    echo -e "  Version:        ${YELLOW}$wazuh_version${NC}"
    echo -e "  Username:       ${YELLOW}$wazuh_username${NC}"
    echo -e "  Password:       ${YELLOW}********${NC}"
    
    if [ -d "./configs" ]; then
        file_count=$(find ./configs -type f -not -name ".gitkeep" | wc -l)
        echo -e "\n${BLUE}Local Configurations:${NC}"
        echo -e "  Files to copy:   ${YELLOW}$file_count${NC}"
    fi
}

run_ansible() {
    print_header "RUNNING ANSIBLE PLAYBOOK"
    
    if ! command -v ansible-playbook &> /dev/null; then
        print_error "Ansible is not installed. Please install Ansible first."
        print_info "You can install Ansible with: apt-get install ansible"
        exit 1
    fi
    
    ansible-playbook deploy_wazuh.yml
    
    if [ $? -eq 0 ]; then
        print_success "Wazuh deployment completed successfully."
    else
        print_error "There was an issue with the Wazuh deployment. Please check the logs above."
    fi
}

echo -e "${BLUE}"
echo "============================================================================="
echo "               AUTOMATED WAZUH DEPLOYMENT ON PROXMOX                         "
echo "============================================================================="
echo -e "${NC}"

collect_configuration
display_summary

echo ""
read -p "Do you want to proceed with the deployment? (y/n): " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    print_info "Deployment cancelled."
    exit 0
fi

generate_ansible_playbook
run_ansible