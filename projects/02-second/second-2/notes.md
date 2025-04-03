## Incorrect Program 1

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
    bpf_printk(" - %s", argv[0]);

    return 0;
}
```

## Exercises

1. Compile the incorrect program. Try to load it, and see "invalid mem acccess" error from verifier.

## Corrected progam 1

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

    char *argument;
    long res = bpf_probe_read_str(&argument, sizeof(argument), &argv[1]);
    if(res <= 0) {
        bpf_printk(" - None");
    } else  {
        bpf_printk(" - %s", argument);
    }

    return 0;
}
```

## Incorrect Program 2

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

    char *argument;
    int i = 1;
    do {
        long res = bpf_probe_read_str(&argument, sizeof(argument), &argv[i]);
        if(res <= 0)
            break;
        
        if(argument == NULL)
            break;

        bpf_printk(" - %s", argument);
    } while (argument != NULL);
    

    return 0;
}
```

## Exercises

1. Compile the incorrect program. Try to load it, and see "infinite loop detected" error from verifier.
