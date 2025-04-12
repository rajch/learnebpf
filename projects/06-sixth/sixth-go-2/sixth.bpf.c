//go:build ignore

#define __TARGET_ARCH_x86

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "sixth.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct comm_buffer
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
};

struct comm_buffer buffer SEC(".maps");

SEC("uprobe//usr/lib/libreadline.so.8:readline")
int BPF_UPROBE(sixth, const char *prompt)
{
    struct sixth_data *data;

    void *bufferspace = bpf_ringbuf_reserve(&buffer, sizeof(struct sixth_data), 0);
    if (bufferspace != NULL)
    {
        data = (struct sixth_data *) bufferspace;
        int len = bpf_probe_read_str(data->readline_prompt, sizeof(data->readline_prompt), prompt);
        if (len > 0)
        {
            data->promptlen = len;
            bpf_ringbuf_submit(bufferspace,0);
        }
        else
        {
            bpf_ringbuf_discard(bufferspace,0);
        }
    }
    else
    {
        bpf_printk("Missed recording readline call with %s", prompt);
    }

    return 0;
}
