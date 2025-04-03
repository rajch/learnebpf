## Incorrect Program

```
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

SEC("ksyscall/execve")
int BPF_KPROBE_SYSCALL(
                second, 
                const char *pathname, 
                char *const _Nullable argv[],
                char *const _Nullable envp[]
    ) {
        

    bpf_printk("Program '%s' was executed with the following parameters:", pathname);
    return 0;
}
```

## Exercises

1. Explain CO-RE, and how it is used in **bpf_tracing.h**, **bpf_core_read.h** and the __BPF_KROBE_SYSCALL__ macro.
1. Generate vmlinux.h using `sudo bpftool btf dump id 1 format c > vmlinux.h`, and replace `#include <linux/bpf.h>` with `#include "vmlinux.h"`. 
1. Compile with `clang -target bpf -c second.bpf.c`. Point out error about __TARGET_ARCH_xx. Add `#define __TARGET_ARCH_x86` at beginning of file.
1. Compile with `clang -target bpf -c second.bpf.c`. Point out error about `-g` compiler option.
1. Compile with `clang -target bpf -c second.bpf.c -g`, which will succeed. Try to load with `sudo bpftool prog load second.bpf.o /sys/fs/bpf/second autoattach`, and point out "BTF is optional" error.
1. Compile with `clang -target bpf -c second.bpf.c -g -O2`, which will succeed. Load with `sudo bpftool prog load second.bpf.o /sys/fs/bpf/second autoattach`, which will succeed. Demonstrate using `sudo cat /sys/kernel/debug/tracing/trace_pipe`.

## Corrected progam

```
#define __TARGET_ARCH_x86

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

SEC("ksyscall/execve")
int BPF_KPROBE_SYSCALL(
                second, 
                const char *pathname, 
                char *const _Nullable argv[],
                char *const _Nullable envp[]
    ) {
        

    bpf_printk("Program '%s' was executed with the following parameters:", pathname);
    return 0;
}
```