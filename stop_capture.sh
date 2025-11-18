#!/bin/bash
# stop_capture.sh

if [ $# -lt 2 ]; then
    echo "Usage: $0 <port_start> <port_end> [interface]"
    echo "Example: $0 5005 5010 eth0"
    exit 1
fi

PORT_START=${1}
PORT_END=${2}
INTERFACE=${3:-eth0}
BPF_FS_PATH="/sys/fs/bpf"
PROGRAM_NAME="udp_monitor_${PORT_START}_${PORT_END}"

echo "Removing UDP monitor for port range ${PORT_START}-${PORT_END} from interface ${INTERFACE}..."

# Detach the XDP program from the interface
bpftool net detach xdp dev ${INTERFACE} 2>/dev/null || true

# Remove pinned objects
rm -f ${BPF_FS_PATH}/${PROGRAM_NAME}
rm -rf ${BPF_FS_PATH}/${PROGRAM_NAME}_maps

echo "Successfully removed UDP monitor for port range ${PORT_START}-${PORT_END}"
