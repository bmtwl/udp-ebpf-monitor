#!/bin/bash
# stop_capture.sh

if [ $# -lt 1 ]; then
    echo "Usage: $0 <port> [interface]"
    exit 1
fi

PORT=${1}
INTERFACE=${2:-eth0}
BPF_FS_PATH="/sys/fs/bpf"
PROGRAM_NAME="udp_monitor_${PORT}"

echo "Stopping UDP capture for port ${PORT}..."

# Detach from interface
echo "Detaching from interface ${INTERFACE}..."
sudo bpftool net detach xdp dev ${INTERFACE} 2>/dev/null || true

# Wait a moment for detachment to complete
sleep 1

# Remove pinned objects
echo "Removing pinned objects..."
sudo rm -f ${BPF_FS_PATH}/${PROGRAM_NAME}
sudo rm -rf ${BPF_FS_PATH}/${PROGRAM_NAME}_maps

# Verify removal
if [ -f ${BPF_FS_PATH}/${PROGRAM_NAME} ] || [ -d ${BPF_FS_PATH}/${PROGRAM_NAME}_maps ]; then
    echo "Warning: Some objects may not have been fully removed"
else
    echo "Successfully removed UDP capture for port ${PORT}"
fi
