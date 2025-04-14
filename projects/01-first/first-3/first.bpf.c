#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("ksyscall/execve")
int first(void *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("BPF program %s called from pid %d", "first", pid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";