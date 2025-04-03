// #include <linux/bpf.h>
// #include <linux/if_ether.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IPV6	0x86DD

char LICENSE[] SEC("license") = "Dual MIT/GPL";

SEC("xdp")
int fourth(struct xdp_md *ctx) {
    void *data_start = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;

    if(data_start + sizeof(struct ethhdr) > data_end) {
        return XDP_ABORTED;
    }
    
    struct ethhdr *header = data_start;
    __u16 protocol = bpf_ntohs(header->h_proto);
    if(protocol == ETH_P_IPV6) {
        bpf_printk("fourth => Dropped IPv6 packet.");
        return XDP_DROP;
    }

    return XDP_PASS;
}