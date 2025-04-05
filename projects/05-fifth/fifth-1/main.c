#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>

// Define direction constants (must match the eBPF program)
#define DIRECTION_INGRESS 0
#define DIRECTION_EGRESS  1

// Define protocol constants (must match the eBPF program)
#define PROTO_UNKNOWN 0
#define PROTO_TCP     6
#define PROTO_UDP     17
#define PROTO_ICMP    1
#define PROTO_OTHER   255

// Define key structure for our map (must match the eBPF program)
struct traffic_key {
    __u8 protocol;
    __u8 direction;
};

// Define value structure for our map (must match the eBPF program)
struct traffic_data {
    __u64 packets;
    __u64 bytes;
};

static int map_fd = -1;
static volatile int keep_running = 1;
static struct bpf_tc_hook *ingress_hook = NULL;
static struct bpf_tc_hook *egress_hook = NULL;
static struct bpf_tc_opts *ingress_opts = NULL;
static struct bpf_tc_opts *egress_opts = NULL;

// Signal handler for graceful termination
static void int_exit(int sig) {
    keep_running = 0;
}

// Print protocol name
static const char *proto_name(__u8 proto) {
    switch (proto) {
        case PROTO_TCP:  return "TCP";
        case PROTO_UDP:  return "UDP";
        case PROTO_ICMP: return "ICMP";
        case PROTO_OTHER: return "OTHER";
        default: return "UNKNOWN";
    }
}

static __u8 proto_index(__u8 proto) {
    switch (proto) {
        case PROTO_TCP:  return 0;
        case PROTO_UDP:  return 1;
        case PROTO_ICMP: return 2;
        case PROTO_OTHER: return 3;
        default: return 4;
    }
}

static const char *proto_name_from_index(__u8 proto_index) {
    switch (proto_index) {
        case 0:  return "TCP";
        case 1:  return "UDP";
        case 2: return "ICMP";
        case 3: return "OTHER";
        default: return "UNKNOWN";
    }
}

// Print direction name
static const char *direction_name(__u8 dir) {
    return dir == DIRECTION_INGRESS ? "INGRESS" : "EGRESS";
}

// Print statistics from BPF map
static void print_stats(void) {
    struct traffic_key key = {}, next_key;
    struct traffic_data value;
    

    __u64 packets[5][2];
    __u64 bytes[5][2];

    __builtin_memset(packets, 0, sizeof(packets));
    __builtin_memset(bytes, 0, sizeof(packets));

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            // printf("%-8s %-8s %10llu %10llu\n", 
            //        proto_name(next_key.protocol),
            //        direction_name(next_key.direction),
            //        value.packets, value.bytes);
            packets[proto_index(next_key.protocol)][next_key.direction] = value.packets;
            bytes[proto_index(next_key.protocol)][next_key.direction] = value.bytes;
        }
        key = next_key;
    }

    printf("\n%-8s %10s %10s %10s %10s\n", "PROTO", "PKT-IN", "PKT-OUT", "BYTES-IN", "BYTES-OUT");
    printf("----------------------------------------\n");


    for(int i=0;i<5;i++) {
        printf(
            "%-8s %10llu %10llu %10llu %10llu\n"
            , proto_name_from_index(i)
            , packets[i][0]
            , packets[i][1]
            , bytes[i][0]
            , bytes[i][1]
        );
    }
}

// Clean up resources
static void cleanup(void) {
    if (ingress_hook && ingress_opts) {
        // Detach the ingress program
        ingress_opts->flags = ingress_opts->prog_fd = ingress_opts->prog_id = 0;
        bpf_tc_detach(ingress_hook, ingress_opts);
        
        // Delete the ingress hook
        ingress_hook->attach_point = 0;
        bpf_tc_hook_destroy(ingress_hook);
    }
    
    if (egress_hook && egress_opts) {
        // Detach the egress program
        egress_opts->flags = egress_opts->prog_fd = egress_opts->prog_id = 0;
        bpf_tc_detach(egress_hook, egress_opts);
        
        // Delete the egress hook
        egress_hook->attach_point = 0;
        bpf_tc_hook_destroy(egress_hook);
    }
    
    free(ingress_hook);
    free(ingress_opts);
    free(egress_hook);
    free(egress_opts);
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog_ingress, *prog_egress;
    int err, prog_fd_ingress, prog_fd_egress;
    const char *default_ifname = "lo";
    const char *ifname = default_ifname;
    
    // Check command line arguments for interface name
    if (argc > 1) {
        ifname = argv[1];
    }
    
    // Set signal handler for graceful termination
    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);
    
    // Load the eBPF program
    obj = bpf_object__open("fifth.bpf.o");
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file\n");
        return 1;
    }
    
    // Load the BPF programs into the kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    
    // Get file descriptor for the map
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "traffic_map");
    if (!map) {
        fprintf(stderr, "Failed to find map\n");
        bpf_object__close(obj);
        return 1;
    }
    map_fd = bpf_map__fd(map);
    
    // Find the BPF programs
    prog_ingress = bpf_object__find_program_by_name(obj, "traffic_ingress");
    prog_egress = bpf_object__find_program_by_name(obj, "traffic_egress");
    if (!prog_ingress || !prog_egress) {
        fprintf(stderr, "Failed to find TC programs\n");
        bpf_object__close(obj);
        return 1;
    }
    
    prog_fd_ingress = bpf_program__fd(prog_ingress);
    prog_fd_egress = bpf_program__fd(prog_egress);
    if (prog_fd_ingress < 0 || prog_fd_egress < 0) {
        fprintf(stderr, "Failed to get program file descriptors\n");
        bpf_object__close(obj);
        return 1;
    }
    
    // Convert interface name to index
    unsigned int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Failed to get interface index for %s\n", ifname);
        bpf_object__close(obj);
        return 1;
    }
    
    // Allocate TC hook and options structures
    ingress_hook = calloc(1, sizeof(*ingress_hook));
    ingress_opts = calloc(1, sizeof(*ingress_opts));
    egress_hook = calloc(1, sizeof(*egress_hook));
    egress_opts = calloc(1, sizeof(*egress_opts));
    
    if (!ingress_hook || !ingress_opts || !egress_hook || !egress_opts) {
        fprintf(stderr, "Failed to allocate TC hook structures\n");
        cleanup();
        bpf_object__close(obj);
        return 1;
    }

    // Initialize TC hook for ingress
    ingress_hook->sz = sizeof(*ingress_hook);
    ingress_hook->ifindex = ifindex;
    ingress_hook->attach_point = BPF_TC_INGRESS;
    
    // Create TC hook point for ingress
    printf("Creating INGRESS hook...\n");
    err = bpf_tc_hook_create(ingress_hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC ingress hook: %s\n", strerror(-err));
        cleanup();
        bpf_object__close(obj);
        return 1;
    }
    
    // Initialize TC hook for egress
    printf("Creating EGRESS hook...\n");
    egress_hook->sz = sizeof(*egress_hook);
    egress_hook->ifindex = ifindex;
    egress_hook->attach_point = BPF_TC_EGRESS;
    
    // Create TC hook point for egress
    err = bpf_tc_hook_create(egress_hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC egress hook: %s\n", strerror(-err));
        cleanup();
        bpf_object__close(obj);
        return 1;
    }
    
    // Set up TC options for ingress
    ingress_opts->sz = sizeof(*ingress_opts);
    ingress_opts->prog_fd = prog_fd_ingress;
    
    // Attach ingress program
    printf("Attaching INGRESS hook...\n");
    err = bpf_tc_attach(ingress_hook, ingress_opts);
    if (err) {
        fprintf(stderr, "Failed to attach ingress program: %s\n", strerror(-err));
        cleanup();
        bpf_object__close(obj);
        return 1;
    }
    
    // Set up TC options for egress
    egress_opts->sz = sizeof(*egress_opts);
    egress_opts->prog_fd = prog_fd_egress;
    
    // Attach egress program
    printf("Attaching EGRESS hook...\n");
    err = bpf_tc_attach(egress_hook, egress_opts);
    if (err) {
        fprintf(stderr, "Failed to attach egress program: %s\n", strerror(-err));
        cleanup();
        bpf_object__close(obj);
        return 1;
    }
    
    printf("Traffic monitor started. Press Ctrl+C to exit.\n");
    printf("Interface: %s\n", ifname);
    
    // Main loop: print statistics every second
    while (keep_running) {
        print_stats();
        sleep(1);
    }
    
    printf("\nCleaning up...\n");
    cleanup();
    bpf_object__close(obj);
    
    return 0;
}