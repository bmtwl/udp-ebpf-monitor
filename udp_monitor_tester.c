// udp_monitor_tester.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <string.h>

static int handle_event(void *ctx, void *data, size_t data_sz) {
    printf("[%ld] Received UDP packet (%zu bytes)\n", time(NULL), data_sz);

    // Print first few bytes of payload
    unsigned char *payload = (unsigned char *)data;
    printf("Payload: ");
    for (int i = 0; i < (data_sz > 32 ? 32 : data_sz); i++) {
        printf("%02x ", payload[i]);
    }
    if (data_sz > 32) printf("...");
    printf("\n\n");

    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        fprintf(stderr, "Example: %s 5005\n", argv[0]);
        return 1;
    }

    int port = atoi(argv[1]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port number: %d\n", port);
        return 1;
    }

    char ringbuf_path[256];
    snprintf(ringbuf_path, sizeof(ringbuf_path), 
             "/sys/fs/bpf/udp_monitor_%d_maps/ring_buffer", port);

    printf("Monitoring UDP port %d using ring buffer: %s\n", port, ringbuf_path);

    // Open the ring buffer
    int ringbuf_fd = bpf_obj_get(ringbuf_path);
    if (ringbuf_fd < 0) {
        perror("Failed to open ring buffer (is the eBPF program loaded?)");
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
    printf("Listening for UDP packets on port %d...\n", port);
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
