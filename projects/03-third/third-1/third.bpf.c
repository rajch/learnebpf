#define __TARGET_ARCH_x86

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "third.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct counter_map_t
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 5);
    __type(key, typeof(char[60]));
    __type(value, typeof(struct counter_record_t));

} counter_map SEC(".maps");

SEC("ksyscall/execve")
int BPF_KPROBE_SYSCALL(third,
                       const char *pathname,
                       char *const _Nullable argv[],
                       char *const _Nullable envp[])
{

    char *argument;
    bpf_probe_read_str(&argument, sizeof(argument), &argv[0]);

    struct counter_record_t current = {};
    int namelength = bpf_probe_read_str(&current.program_name, sizeof(current.program_name), argument);

    if (namelength <= 0)
        return 0;

    Elf64_Addr updateflag;
    struct counter_record_t *lookedup = bpf_map_lookup_elem(&counter_map, &current.program_name);

    if (lookedup == NULL)
    {
        current.counter = 1;
        updateflag = BPF_NOEXIST;
    }
    else
    {
        current.counter = lookedup->counter + 1;
        updateflag = BPF_EXIST;
    }

    bpf_map_update_elem(&counter_map, &current.program_name, &current, updateflag);

    return 0;
}