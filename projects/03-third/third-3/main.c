#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>

#include "third.h"
#include "third.bpf.skel.h"

bool cancel = false;

void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM)
        cancel = true;
}

void dump_map(struct third_bpf *bpfobj)
{
    printf("Dumpamapam...\n");
    char next_key[60] = "";
    char *curr_key = NULL;
    struct counter_record_t value = {};
    while (bpf_map__get_next_key(bpfobj->maps.counter_map, curr_key, &next_key, sizeof(next_key) ) ==0) {
        int res = bpf_map__lookup_elem(bpfobj->maps.counter_map, &next_key, sizeof(next_key), &value, sizeof(value), 0);
        if(res==0) {
            printf("    '%s' has been executed %d times.\n", next_key, value.counter);
        } else {
            printf("    ERROR: Lookup returned %d.\n", res);
        }
        curr_key = next_key;
    }
}

int main(int argc, char *argv[])
{
    struct third_bpf *bpfobj = third_bpf__open_and_load();
    if (bpfobj == NULL)
    {
        fprintf(stderr, "Could not load BPF program.\n");
        return 1;
    }

    int err = third_bpf__attach(bpfobj);
    if(err!=0) {
        fprintf(stderr, "Could not attach to BPF program.\n");
        return 1;
    }

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    printf("Monitoring started. Press ^C to stop...\n");
    while (!cancel)
    {
        dump_map(bpfobj);
        sleep(5);
    }

    printf("Monitoring stopped.\n");
    third_bpf__detach(bpfobj);
    third_bpf__destroy(bpfobj);
    return 0;
}
