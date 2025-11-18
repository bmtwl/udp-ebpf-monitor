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
static int start_port = 0;
static int end_port = 0;
static struct in_addr target_ip_addr;

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
    dest_addr.sin_addr = target_ip_addr;

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
                   inet_ntoa(target_ip_addr), e->dport);
        }
    }

    return 0;
}

void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS] <port_range> <target_ip>\n", program_name);
    printf("\nOptions:\n");
    printf("  -d, --debug          Enable debug output\n");
    printf("  -h, --help           Show this help message\n");
    printf("\nArguments:\n");
    printf("  port_range           Single port (5005) or port range (5005-5020)\n");
    printf("  target_ip            IP address to forward packets to\n");
    printf("\nExamples:\n");
    printf("  %s 5005 127.0.0.1\n", program_name);
    printf("  %s 5005-5010 127.0.0.1\n", program_name);
    printf("  %s -d 53-55 192.168.1.100\n", program_name);
}

int main(int argc, char **argv) {
    const char *target_ip = NULL;

    // Parse command line options
    static struct option long_options[] = {
        {"debug",    no_argument,       0, 'd'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "dh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'd':
                debug_mode = true;
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
    if (remaining_args < 2) {
        fprintf(stderr, "Error: port range and target IP are required\n");
        print_usage(argv[0]);
        return 1;
    }

    // Parse port range
    const char *port_range_str = argv[optind];
    char *dash = strchr(port_range_str, '-');

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

    target_ip = argv[optind + 1];

    // Convert target IP to in_addr structure for use in callback
    if (inet_pton(AF_INET, target_ip, &target_ip_addr) <= 0) {
        fprintf(stderr, "Invalid target IP address: %s\n", target_ip);
        return 1;
    }

    // Set up signal handler for graceful exit
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (debug_mode) {
        printf("UDP Repeater starting...\n");
        if (start_port == end_port) {
            printf("Source port: %d\n", start_port);
        } else {
            printf("Source port range: %d-%d\n", start_port, end_port);
        }
        printf("Target IP: %s\n", target_ip);
    }

    // Open the single ring buffer for the port range
    char ringbuf_path[256];
    snprintf(ringbuf_path, sizeof(ringbuf_path),
             "/sys/fs/bpf/udp_monitor_%d_%d_maps/ring_buffer", start_port, end_port);

    int ringbuf_fd = bpf_obj_get(ringbuf_path);
    if (ringbuf_fd < 0) {
        fprintf(stderr, "Failed to open ring buffer: %s\n", ringbuf_path);
        fprintf(stderr, "Make sure udp_monitor_%d_%d is deployed first\n", start_port, end_port);
        return 1;
    }

    // Create ring buffer manager
    struct ring_buffer *rb = ring_buffer__new(ringbuf_fd, handle_event, &ringbuf_fd, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer manager\n");
        close(ringbuf_fd);
        return 1;
    }

    // Create UDP socket for sending
    int send_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (send_sock < 0) {
        perror("Failed to create UDP socket");
        ring_buffer__free(rb);
        close(ringbuf_fd);
        return 1;
    }

    // Update ring buffer with correct context (send socket)
    ring_buffer__free(rb);
    rb = ring_buffer__new(ringbuf_fd, handle_event, &send_sock, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to recreate ring buffer manager with send socket\n");
        close(ringbuf_fd);
        close(send_sock);
        return 1;
    }

    if (debug_mode) {
        if (start_port == end_port) {
            printf("UDP Repeater started for port %d -> %s\n", start_port, target_ip);
        } else {
            printf("UDP Repeater started for ports %d-%d -> %s\n", start_port, end_port, target_ip);
        }
        printf("Press Ctrl+C to stop\n");
    } else {
        if (start_port == end_port) {
            fprintf(stderr, "UDP Repeater started for port %d -> %s\n", start_port, target_ip);
        } else {
            fprintf(stderr, "UDP Repeater started for ports %d-%d -> %s\n", start_port, end_port, target_ip);
        }
    }

    // Event loop
    while (!exiting) {
        int ret = ring_buffer__poll(rb, 100); // 100ms timeout
        if (ret < 0 && ret != -EINTR) {
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
    close(ringbuf_fd);
    close(send_sock);

    if (debug_mode) {
        printf("UDP Repeater stopped.\n");
    }
    return 0;
}
