#!/bin/bash
# start_capture.sh

if [ $# -lt 2 ]; then
    echo "Usage: $0 <port_start> <port_end> [interface]"
    echo "Example: $0 5005 5010 eth0"
    echo "Example: $0 5005 5005 eth0  # Single port"
    exit 1
fi

PORT_START=${1}
PORT_END=${2}
INTERFACE=${3:-eth0}
BPF_FS_PATH="/sys/fs/bpf"
PROGRAM_NAME="udp_monitor_${PORT_START}_${PORT_END}"

# Validate port range
if [ ${PORT_START} -gt ${PORT_END} ]; then
    echo "Error: Start port must be <= end port"
    exit 1
fi

if [ ${PORT_START} -lt 1 ] || [ ${PORT_END} -gt 65535 ]; then
    echo "Error: Ports must be between 1 and 65535"
    exit 1
fi

# Create BPF filesystem if it doesn't exist
mkdir -p ${BPF_FS_PATH}

# Check if clang is available
if ! command -v clang &> /dev/null; then
    echo "Error: clang is required but not found"
    exit 1
fi

# Check if bpftool is available
if ! command -v bpftool &> /dev/null; then
    echo "Error: bpftool is required but not found"
    exit 1
fi

# Clean up any existing deployment for this port range
echo "Cleaning up existing deployment for port range ${PORT_START}-${PORT_END}..."
bpftool net detach xdp dev ${INTERFACE} 2>/dev/null || true
rm -f ${BPF_FS_PATH}/${PROGRAM_NAME}
rm -rf ${BPF_FS_PATH}/${PROGRAM_NAME}_maps

# Compile program for port range
echo "Compiling eBPF program for port range ${PORT_START}-${PORT_END}..."
clang -O2 -target bpf -g -DPORT_START=${PORT_START} -DPORT_END=${PORT_END} -c udp_capture_multi.c -o ${PROGRAM_NAME}.o

# Check if compilation was successful
if [ $? -ne 0 ]; then
    echo "Error: Failed to compile eBPF program"
    rm -f ${PROGRAM_NAME}.o
    exit 1
fi

# Load program
echo "Loading program for port range ${PORT_START}-${PORT_END}..."
bpftool prog load ${PROGRAM_NAME}.o ${BPF_FS_PATH}/${PROGRAM_NAME} \
    pinmaps ${BPF_FS_PATH}/${PROGRAM_NAME}_maps

# Check if loading was successful
if [ $? -ne 0 ]; then
    echo "Error: Failed to load eBPF program"
    rm -f ${PROGRAM_NAME}.o
    exit 1
fi

# Get program ID
PROGRAM_ID=$(bpftool prog show pinned ${BPF_FS_PATH}/${PROGRAM_NAME} | head -n1 | awk '{print $1}' | cut -d':' -f1)
if [ -z "$PROGRAM_ID" ]; then
    echo "Error: Could not find the ID of the newly loaded program."
    rm -f ${PROGRAM_NAME}.o
    exit 1
fi

echo "Attaching to interface ${INTERFACE}..."
bpftool net attach xdpdrv id ${PROGRAM_ID} dev ${INTERFACE}

# Check if attachment was successful
if [ $? -ne 0 ]; then
    echo "Error: Failed to attach to interface ${INTERFACE}"
    rm -f ${PROGRAM_NAME}.o
    exit 1
else
    echo "Successfully attached to interface ${INTERFACE}"
fi

echo "Successfully deployed UDP monitor for port range ${PORT_START}-${PORT_END}"
echo "Ring buffer available at: ${BPF_FS_PATH}/${PROGRAM_NAME}_maps/ring_buffer"
echo ""
echo "To monitor: ./udp_reader ${PORT_START} ${PORT_END}"
echo "To remove: ./remove_udp_monitor.sh ${PORT_START} ${PORT_END} ${INTERFACE}"

# Cleanup temporary file
rm -f ${PROGRAM_NAME}.o
