#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/__x64_sys_execve")
int first(void *ctx) {
    return 0;
}