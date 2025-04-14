#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <sys/stat.h>

//#include <bpf/libbpf.h>
#include "fourth.bpf.skel.h"

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s INTERFACENAME [detach]\n", argv[0]);
        return 1;
    }

    int ifindex = if_nametoindex(argv[1]);
    if (ifindex <= 0)
    {
        perror("Error getting interface");
        return 1;
    }

    char linkname[] = "/sys/fs/bpf/fourth-link-000";
    sprintf(linkname, "/sys/fs/bpf/fourth-link-%03d", ifindex);

    struct stat linkstat;
    bool linkpresent = (stat(linkname, &linkstat) == 0);

    bool detachflag = (argc == 3 && strncmp(argv[2], "detach", 6) == 0);

    int err;

    if (detachflag)
    {
        if (!linkpresent)
        {
            fprintf(stderr, "This BPF program is not attached to interface %s[%d]\n", argv[1], ifindex);
            return 1;
        }

        err = remove(linkname);
        if (err != 0)
        {
            fprintf(stderr, "Could not detach this BPF program.\n");
            return 1;
        }

        printf("This BPF program is succesfully detached.\n");
        return 0;
    }

    if (linkpresent)
    {
        printf(
            "This BPF program is already attached to interface %s[%d].\n",
            argv[1],
            ifindex);
        return 0;
    }

    unsigned int progid;
    err = bpf_xdp_query_id(ifindex, 0, &progid);
    if (err < 0)
    {
        fprintf(stderr, "Error checking if interface already has a BPF program attached.");
        return 1;
    }

    if (progid != 0)
    {
        fprintf(
            stderr,
            "A BPF program (id %d) is already attached to interface %s[%d].\n",
            progid,
            argv[1],
            ifindex);
        return 1;
    }

    struct fourth_bpf *skel = fourth_bpf__open_and_load();
    if (skel == NULL)
    {
        fprintf(stderr, "Could not load this BPF program.\n");
        return 1;
    }

    struct bpf_link *link = bpf_program__attach_xdp(skel->progs.fourth, ifindex);
    if (link == NULL)
    {
        fprintf(
            stderr,
            "Counld not attach this BPF program to interface %s[%d].\n",
            argv[1],
            ifindex);
        return 1;
    }

    err = bpf_link__pin(link, linkname);
    if (err != 0)
    {
        fprintf(
            stderr,
            "Error attaching this BPF program to interface named '%s': %d\n",
            argv[1],
            errno);
        return 1;
    }

    printf(
        "Successfully attached this BPF program to interface %s[%d].\n",
        argv[1],
        ifindex);
    return 0;
}