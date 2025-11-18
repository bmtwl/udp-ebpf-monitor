// udp_monitor_tester.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <string.h>

static int handle_event(void *ctx, void *data, size_t data_sz) {
    // Structure matching the eBPF event structure
    struct {
        __u32 saddr;
        __u16 sport;
        __u32 daddr;
        __u16 dport;
        __u32 payload_len;
        __u8 data[0]; // Flexible array member
    } *event = (void *)data;

    if (data_sz < sizeof(*event)) {
        printf("[%ld] Invalid event size: %zu bytes\n", time(NULL), data_sz);
        return 0;
    }

    // Convert IP addresses to human-readable format
    unsigned char *src_ip = (unsigned char *)&event->saddr;
    unsigned char *dst_ip = (unsigned char *)&event->daddr;

    printf("[%ld] UDP Packet: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d (%u bytes)\n",
           time(NULL),
           src_ip[0], src_ip[1], src_ip[2], src_ip[3], event->sport,
           dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3], event->dport,
           event->payload_len);

    // Print first few bytes of payload
    unsigned int payload_size = event->payload_len;
    if (payload_size > (data_sz - sizeof(*event))) {
        payload_size = data_sz - sizeof(*event);
    }

    printf("Payload (%u bytes): ", payload_size);
    for (int i = 0; i < (payload_size > 32 ? 32 : payload_size); i++) {
        printf("%02x ", event->data[i]);
    }
    if (payload_size > 32) printf("...");
    printf("\n\n");

    return 0;
}

void print_usage(const char *program_name) {
    printf("Usage: %s <port_range>\n", program_name);
    printf("Examples:\n");
    printf("  %s 5005      # Single port\n", program_name);
    printf("  %s 5005-5010 # Port range\n", program_name);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        print_usage(argv[0]);
        return 1;
    }

    // Parse port range
    const char *port_range_str = argv[1];
    char *dash = strchr(port_range_str, '-');

    int start_port, end_port;
    if (dash) {
        // Port range format: "5005-5010"
        char start_str[16];
        int len = dash - port_range_str;
        if (len >= sizeof(start_str)) {
            fprintf(stderr, "Invalid port range format\n");
            return 1;
        }
        strncpy(start_str, port_range_str, len);
        start_str[len] = '\0';

        start_port = atoi(start_str);
        end_port = atoi(dash + 1);
    } else {
        // Single port
        start_port = end_port = atoi(port_range_str);
    }

    if (start_port <= 0 || start_port > 65535 || end_port <= 0 || end_port > 65535 || start_port > end_port) {
        fprintf(stderr, "Invalid port range: %s\n", port_range_str);
        return 1;
    }

    char ringbuf_path[256];
    snprintf(ringbuf_path, sizeof(ringbuf_path),
             "/sys/fs/bpf/udp_monitor_%d_%d_maps/ring_buffer", start_port, end_port);

    printf("Monitoring UDP port range %d-%d using ring buffer: %s\n", start_port, end_port, ringbuf_path);

    // Open the ring buffer
    int ringbuf_fd = bpf_obj_get(ringbuf_path);
    if (ringbuf_fd < 0) {
        perror("Failed to open ring buffer (is the eBPF program loaded?)");
        fprintf(stderr, "Make sure udp_monitor_%d_%d is deployed first\n", start_port, end_port);
        return 1;
    }

    // Create ring buffer manager
    struct ring_buffer *rb = ring_buffer__new(ringbuf_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer manager\n");
        close(ringbuf_fd);
        return 1;
    }

    // Poll for events
    if (start_port == end_port) {
        printf("Listening for UDP packets on port %d...\n", start_port);
    } else {
        printf("Listening for UDP packets on ports %d-%d...\n", start_port, end_port);
    }
    printf("Press Ctrl+C to stop\n\n");

    while (1) {
        int ret = ring_buffer__poll(rb, 1000); // Poll every 1000ms
        if (ret < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", ret);
            break;
        }
    }

    ring_buffer__free(rb);
    close(ringbuf_fd);
    return 0;
}
