#!/bin/bash
# Process hunter for Ubuntu 24.04
# Save as /var/ossec/wodles/prochunter.sh

# Make directory if it doesn't exist
mkdir -p /var/ossec/wodles

# Collect system processes with details
PROCESSES=$(ps -e -o pid,ppid,user,%cpu,%mem,vsz,rss,tty,stat,start,time,comm,cmd -w --no-headers)

# Get timestamp
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
HOSTNAME=$(hostname)

# Initialize JSON structure
echo "{
  \"timestamp\": \"$TIMESTAMP\",
  \"hostname\": \"$HOSTNAME\",
  \"processes\": ["

# Process counter for JSON formatting
PROCESS_COUNT=$(echo "$PROCESSES" | wc -l)
CURRENT=0

# Parse processes and output as JSON
echo "$PROCESSES" | while IFS= read -r line; do
  CURRENT=$((CURRENT + 1))
  
  # Extract fields
  PID=$(echo "$line" | awk '{print $1}')
  PPID=$(echo "$line" | awk '{print $2}')
  USER=$(echo "$line" | awk '{print $3}')
  CPU=$(echo "$line" | awk '{print $4}')
  MEM=$(echo "$line" | awk '{print $5}')
  VSZ=$(echo "$line" | awk '{print $6}')
  RSS=$(echo "$line" | awk '{print $7}')
  TTY=$(echo "$line" | awk '{print $8}')
  STAT=$(echo "$line" | awk '{print $9}')
  START=$(echo "$line" | awk '{print $10}')
  TIME=$(echo "$line" | awk '{print $11}')
  COMM=$(echo "$line" | awk '{print $12}')
  CMD=$(echo "$line" | cut -d' ' -f13-)
  
  # Try to get executable path
  EXEPATH=$(readlink -f /proc/$PID/exe 2>/dev/null || echo "N/A")
  
  # Get process start time with full date
  STARTTIME=$(ls -ld --time-style=full-iso /proc/$PID 2>/dev/null | awk '{print $6, $7, $8}' || echo "N/A")
  
  # Detect suspicious processes
  SUSPICIOUS="false"
  SUSPICIOUS_REASONS=""
  
  # Check for processes running from /tmp
  if [[ "$EXEPATH" == */tmp/* ]]; then
    SUSPICIOUS="true"
    SUSPICIOUS_REASONS="Process running from /tmp directory, "
  fi
  
  # Check for processes running from /dev/shm
  if [[ "$EXEPATH" == */dev/shm/* ]]; then
    SUSPICIOUS="true"
    SUSPICIOUS_REASONS="${SUSPICIOUS_REASONS}Process running from /dev/shm, "
  fi
  
  # Check for processes with high privileges but suspicious locations
  if [[ "$USER" == "root" && ("$EXEPATH" == */tmp/* || "$EXEPATH" == */dev/shm/*) ]]; then
    SUSPICIOUS="true"
    SUSPICIOUS_REASONS="${SUSPICIOUS_REASONS}Root process in suspicious location, "
  fi
  
  # Output process details as JSON
  echo "    {
      \"pid\": $PID,
      \"ppid\": $PPID,
      \"user\": \"$USER\",
      \"cpu\": $CPU,
      \"mem\": $MEM,
      \"vsz\": $VSZ,
      \"rss\": $RSS,
      \"tty\": \"$TTY\",
      \"stat\": \"$STAT\",
      \"start\": \"$STARTTIME\",
      \"time\": \"$TIME\",
      \"comm\": \"$COMM\",
      \"cmd\": \"$CMD\",
      \"executable\": \"$EXEPATH\",
      \"suspicious\": $SUSPICIOUS,
      \"suspiciousReasons\": \"${SUSPICIOUS_REASONS%,*}\"
    }$(if [ $CURRENT -lt $PROCESS_COUNT ]; then echo ","; fi)"
done

# Close JSON
echo "  ]
}"