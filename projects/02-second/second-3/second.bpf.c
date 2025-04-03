#define __TARGET_ARCH_x86

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

void print_arguments(char *const _Nullable argv[]);

SEC("ksyscall/execve")
int BPF_KPROBE_SYSCALL(
                second, 
                const char *pathname, 
                char *const _Nullable argv[],
                char *const _Nullable envp[]
    ) {
        

    bpf_printk("Program '%s' was executed with the following parameters:", pathname);

    print_arguments(argv);

    return 0;
}

void print_arguments(char *const _Nullable argv[]) {
    for(int i=1;i<=60;i++) {
        char *argument;

        long res = bpf_probe_read_str(&argument, sizeof(argument), &argv[i]);
        if(res <= 0)
            break;
        
        if(argument == NULL)
            break;

        bpf_printk(" - %s", argument);
    }
}


