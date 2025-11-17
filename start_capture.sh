#!/bin/bash
# start_capture.sh

if [ $# -lt 1 ]; then
    echo "Usage: $0 <port> [interface]"
    echo "Example: $0 5005 eth0"
    exit 1
fi

PORT=${1}
INTERFACE=${2:-eth0}
BPF_FS_PATH="/sys/fs/bpf"
PROGRAM_NAME="udp_monitor_${PORT}"

# Create BPF filesystem if it doesn't exist
sudo mkdir -p ${BPF_FS_PATH}

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

# Clean up any existing deployment for this port
echo "Cleaning up existing deployment for port ${PORT}..."
sudo bpftool net detach xdp dev ${INTERFACE} 2>/dev/null || true
sudo rm -f ${BPF_FS_PATH}/${PROGRAM_NAME}
sudo rm -rf ${BPF_FS_PATH}/${PROGRAM_NAME}_maps

# Compile program for specific port
echo "Compiling eBPF program for port ${PORT}..."
clang -O2 -target bpf -g -DTARGET_PORT=${PORT} -c udp_capture.c -o ${PROGRAM_NAME}.o

# Check if compilation was successful
if [ $? -ne 0 ]; then
    echo "Error: Failed to compile eBPF program"
    rm -f ${PROGRAM_NAME}.o
    exit 1
fi

# Load program with port-specific naming
echo "Loading program for port ${PORT}..."
sudo bpftool prog load ${PROGRAM_NAME}.o ${BPF_FS_PATH}/${PROGRAM_NAME} \
    pinmaps ${BPF_FS_PATH}/${PROGRAM_NAME}_maps

# Check if loading was successful
if [ $? -ne 0 ]; then
    echo "Error: Failed to load eBPF program"
    rm -f ${PROGRAM_NAME}.o
    exit 1
fi

echo "Attaching to interface ${INTERFACE}..."
sudo bpftool net attach xdpdrv name xdp_udp_capture dev ${INTERFACE}

# Check if attachment was successful
if [ $? -ne 0 ]; then
    echo "Error: Failed to attach to interface ${INTERFACE} on port ${PORT}"
else
    echo "Successfully attached to interface ${INTERFACE}"
fi

echo "Successfully deployed UDP monitor for port ${PORT}"
echo "Ring buffer available at: ${BPF_FS_PATH}/${PROGRAM_NAME}_maps/ring_buffer"
echo ""
echo "To monitor: ./udp_reader ${PORT}"
echo "To remove: sudo ./remove_udp_monitor.sh ${PORT} ${INTERFACE}"

# Cleanup temporary file
rm -f ${PROGRAM_NAME}.o
