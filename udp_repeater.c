// udp_repeater.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// Structure matching the eBPF event structure
#define MAX_CAPTURE_SIZE 1500

struct event {
    __u32 saddr;
    __u16 sport;
    __u32 daddr;
    __u16 dport;
    __u32 payload_len;
    __u8 data[MAX_CAPTURE_SIZE];
};

static volatile bool exiting = false;
static bool debug_mode = false;
static int poll_interval = 100; // Default 100ms

static void sig_handler(int sig) {
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event *e = (struct event *)data;
    int *send_sock = (int *)ctx;

    if (data_sz < sizeof(struct event)) {
        if (debug_mode) {
            fprintf(stderr, "Invalid event size: %zu\n", data_sz);
        }
        return 0;
    }

    // Create UDP socket address for sending
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(e->dport);
    dest_addr.sin_addr.s_addr = e->daddr;

    // Send the payload
    ssize_t sent = sendto(*send_sock, e->data, e->payload_len, 0,
                         (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    if (sent < 0) {
        if (debug_mode) {
            perror("sendto failed");
        }
    } else {
        if (debug_mode) {
            printf("[%ld] Forwarded %u bytes from %s:%d to %s:%d\n",
                   time(NULL), e->payload_len,
                   inet_ntoa(*(struct in_addr *)&e->saddr), e->sport,
                   inet_ntoa(*(struct in_addr *)&e->daddr), e->dport);
        }
    }

    return 0;
}

void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS] <source_port> [target_ip] [target_port]\n", program_name);
    printf("\nOptions:\n");
    printf("  -d, --debug          Enable debug output\n");
    printf("  -i, --interval MS    Polling interval in milliseconds (default: 100)\n");
    printf("  -h, --help           Show this help message\n");
    printf("\nArguments:\n");
    printf("  source_port          UDP port to monitor (must have eBPF monitor deployed)\n");
    printf("  target_ip            IP address to forward packets to (default: 127.0.0.1)\n");
    printf("  target_port          Port to forward packets to (default: source_port)\n");
    printf("\nExamples:\n");
    printf("  %s 5005\n", program_name);
    printf("  %s -d 5005 192.168.1.100 5006\n", program_name);
    printf("  %s -i 50 53 127.0.0.1 5353\n", program_name);
}

int main(int argc, char **argv) {
    const char *target_ip = "127.0.0.1";
    int source_port = 0;
    int target_port = 0;

    // Parse command line options
    static struct option long_options[] = {
        {"debug",    no_argument,       0, 'd'},
        {"interval", required_argument, 0, 'i'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "di:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'd':
                debug_mode = true;
                break;
            case 'i':
                poll_interval = atoi(optarg);
                if (poll_interval <= 0) {
                    fprintf(stderr, "Invalid polling interval: %s\n", optarg);
                    return 1;
                }
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // Parse remaining arguments
    int remaining_args = argc - optind;
    if (remaining_args < 1) {
        fprintf(stderr, "Error: source port is required\n");
        print_usage(argv[0]);
        return 1;
    }

    source_port = atoi(argv[optind]);
    if (source_port <= 0 || source_port > 65535) {
        fprintf(stderr, "Invalid source port: %d\n", source_port);
        return 1;
    }

    if (remaining_args >= 2) {
        target_ip = argv[optind + 1];
    }

    if (remaining_args >= 3) {
        target_port = atoi(argv[optind + 2]);
        if (target_port <= 0 || target_port > 65535) {
            fprintf(stderr, "Invalid target port: %d\n", target_port);
            return 1;
        }
    } else {
        target_port = source_port;
    }

    // Set up signal handler for graceful exit
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Construct ring buffer path
    char ringbuf_path[256];
    snprintf(ringbuf_path, sizeof(ringbuf_path),
             "/sys/fs/bpf/udp_monitor_%d_maps/ring_buffer", source_port);

    if (debug_mode) {
        printf("UDP Repeater starting...\n");
        printf("Source port: %d\n", source_port);
        printf("Target IP: %s\n", target_ip);
        printf("Target port: %d\n", target_port);
        printf("Polling interval: %d ms\n", poll_interval);
        printf("Ring buffer: %s\n", ringbuf_path);
    }

    // Open the ring buffer
    int ringbuf_fd = bpf_obj_get(ringbuf_path);
    if (ringbuf_fd < 0) {
        fprintf(stderr, "Failed to open ring buffer: %s\n", ringbuf_path);
        fprintf(stderr, "Make sure udp_monitor_%d is deployed first\n", source_port);
        return 1;
    }

    // Create UDP socket for sending
    int send_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (send_sock < 0) {
        perror("Failed to create UDP socket");
        close(ringbuf_fd);
        return 1;
    }

    // Set up target address
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(target_port);

    if (inet_pton(AF_INET, target_ip, &target_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid target IP address: %s\n", target_ip);
        close(send_sock);
        close(ringbuf_fd);
        return 1;
    }

    // Create ring buffer manager
    struct ring_buffer *rb = ring_buffer__new(ringbuf_fd, handle_event, &send_sock, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer manager\n");
        close(send_sock);
        close(ringbuf_fd);
        return 1;
    }

    if (debug_mode) {
        printf("UDP Repeater started. Listening for packets on port %d...\n", source_port);
        printf("Forwarding to %s:%d\n", target_ip, target_port);
        printf("Press Ctrl+C to stop\n");
    } else {
        // Quiet mode - just log startup to stderr
        fprintf(stderr, "UDP Repeater started for port %d -> %s:%d\n", 
                source_port, target_ip, target_port);
    }

    // Poll for events
    while (!exiting) {
        int ret = ring_buffer__poll(rb, poll_interval);
        if (ret < 0) {
            if (ret == -EINTR) {
                // Interrupted by signal
                continue;
            }
            if (debug_mode) {
                fprintf(stderr, "Error polling ring buffer: %d\n", ret);
            }
            break;
        }
    }

    if (debug_mode) {
        printf("\nUDP Repeater shutting down\n");
    } else {
        fprintf(stderr, "\nUDP Repeater shutting down\n");
    }

    // Cleanup
    ring_buffer__free(rb);
    close(send_sock);
    close(ringbuf_fd);

    if (debug_mode) {
        printf("UDP Repeater stopped.\n");
    }
    return 0;
}
