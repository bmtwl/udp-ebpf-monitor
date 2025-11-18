// udp_capture.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Port range will be set at compile time
#ifndef PORT_START
#define PORT_START 5005
#endif

#ifndef PORT_END
#define PORT_END 5005
#endif

#define MAX_CAPTURE_SIZE 1500

// Define a fixed-size struct to make the verifier happy
struct event {
    __u32 saddr;
    __u16 sport;
    __u32 daddr;
    __u16 dport;
    __u32 payload_len;
    __u8 data[MAX_CAPTURE_SIZE]; // Fixed size buffer
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // Larger ring buffer for multiple ports
} ring_buffer SEC(".maps");

SEC("xdp")
int xdp_udp_capture_multi(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    // IP header
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    // Check if it's UDP
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // UDP header
    struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
        return XDP_PASS;

    // Check if destination port is in our range
    __u16 dest_port = bpf_ntohs(udp->dest);
    if (dest_port < PORT_START || dest_port > PORT_END)
        return XDP_PASS;

    void *payload_start = (void *)(udp + 1);

    __u32 full_udp_len = bpf_ntohs(udp->len);
    __u32 actual_payload_len = full_udp_len - sizeof(*udp);
    __u32 remaining_data = data_end - payload_start;

    __u32 copy_len = actual_payload_len;
    if (copy_len > remaining_data) copy_len = remaining_data;
    if (copy_len > MAX_CAPTURE_SIZE) copy_len = MAX_CAPTURE_SIZE;

    if (copy_len == 0) return XDP_DROP;

    struct event *e = bpf_ringbuf_reserve(&ring_buffer, sizeof(*e), 0);
    if (!e)
        return XDP_DROP;

    // Populate the metadata fields in the fixed struct
    e->saddr = ip->saddr;
    e->sport = bpf_ntohs(udp->source);
    e->daddr = ip->daddr;
    e->dport = bpf_ntohs(udp->dest);
    e->payload_len = actual_payload_len;

    // Copy only the determined safe amount of data into the fixed buffer field
    bpf_probe_read_kernel(e->data, copy_len, payload_start);

    bpf_ringbuf_submit(e, 0);

    // Nobody else gets this packet
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
