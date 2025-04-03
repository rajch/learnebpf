#include <errno.h>
#include <stdio.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <linux/if_link.h>

#include "fourth.bpf.skel.h"

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s INTERFACENAME\n", argv[0]);
        return 1;
    }

    int ifindex = if_nametoindex(argv[1]);
    if (ifindex <= 0)
    {
        fprintf(stderr, "Error in interface named '%s': %d\n", argv[1], errno);
        return 1;
    }

    unsigned int progid;
    int err = bpf_xdp_query_id(ifindex, 0, &progid);
    if (err < 0)
    {
        fprintf(stderr, "Error occured while querying XDP program id: %d\n", err);
        return 1;
    }

    if (progid != 0)
    {
        printf("Program id %d already attached to interface %s[%d].\n", progid, argv[1], ifindex);
        return 0;
    }

    struct fourth_bpf *skel = fourth_bpf__open_and_load();
    if (skel == NULL)
    {
        fprintf(stderr, "Could not load BPF program.\n");
        return 1;
    }

    struct bpf_link *link = bpf_program__attach_xdp(skel->progs.fourth, ifindex);
    if(link == NULL) {
        fprintf(stderr, "Counld not attach program to interface %s[%d].\n", argv[1], ifindex);
        return 1;
    }

    err = bpf_link__pin(link, "/sys/fs/bpf/fourth-link-1");
    if(err!=0) {
        fprintf(stderr, "Error pinning attachment to interface named '%s': %d\n", argv[1], errno);
        return 1;
    }

    printf("Successfully attached program to interface %s[%d].\n", argv[1], ifindex);
    return 0;
}