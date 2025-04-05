#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Define direction constants
#define DIRECTION_INGRESS 0
#define DIRECTION_EGRESS  1

// Define protocol constants
#define PROTO_UNKNOWN 0
#define PROTO_TCP     6    // Using actual IPPROTO values
#define PROTO_UDP     17
#define PROTO_ICMP    1
#define PROTO_OTHER   255

// Define key structure for our map
struct traffic_key {
    __u8 protocol;
    __u8 direction;
};

// Define value structure for our map
struct traffic_data {
    __u64 packets;
    __u64 bytes;
};

// BPF map to store traffic statistics
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct traffic_key);
    __type(value, struct traffic_data);
    __uint(max_entries, 16);
} traffic_map SEC(".maps");

// Function to process each packet
static __always_inline int process_packet(struct __sk_buff *skb, __u8 direction) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // Ensure we have an Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;
    
    // We only care about IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    // Check we have an IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    // Determine protocol
    __u8 protocol;
    switch (ip->protocol) {
        case PROTO_TCP:
            protocol = PROTO_TCP;
            break;
        case PROTO_UDP:
            protocol = PROTO_UDP;
            break;
        case PROTO_ICMP:
            protocol = PROTO_ICMP;
            break;
        default:
            protocol = PROTO_OTHER;
            break;
    }
    
    // Create key for map lookup/update
    struct traffic_key key = {
        .protocol = protocol,
        .direction = direction
    };
    
    // Lookup existing data
    struct traffic_data *value;
    struct traffic_data new_value = {0};
    
    value = bpf_map_lookup_elem(&traffic_map, &key);
    if (value) {
        // Update existing entry
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, skb->len);
    } else {
        // Create new entry
        new_value.packets = 1;
        new_value.bytes = skb->len;
        bpf_map_update_elem(&traffic_map, &key, &new_value, BPF_ANY);
    }
    
    // Allow packet to pass through
    return TC_ACT_OK;
}

// TC ingress handler
SEC("tc")
int traffic_ingress(struct __sk_buff *skb) {
    return process_packet(skb, DIRECTION_INGRESS);
}

// TC egress handler
SEC("tc")
int traffic_egress(struct __sk_buff *skb) {
    return process_packet(skb, DIRECTION_EGRESS);
}

// Required license
char LICENSE[] SEC("license") = "GPL";