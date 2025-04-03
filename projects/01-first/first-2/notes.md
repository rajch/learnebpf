## Incorrect Program

```
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/__x64_sys_execve")
int first(void *ctx) {
    bpf_printk("Hello from %s", "first");
    return 0;
}
```

`bpf_printk` is a macro defined in `<bpf/bpf_helpers.h>`, which expands to a helper function called `bpf_trace_printk`.

## Exercises

1. Compile with `clang -target bpf -c first.bpf.c`. This will produce **first.bpf.o**.
1. Load with `sudo bpftool prog load first.bpf.o /sys/fs/bpf/first`. This fails verification, because of license check, and hence demonstrates the verifier.
1. Add the line `char LICENSE[] SEC("license") = "Dual MIT/GPL";`. The variable has to be called __LICENSE__, has to be placed in an ELF section called "license", and must contain "GPL" or "Dual */GPL" value.
1. Compile with `clang -target bpf -c first.bpf.c`. Load with `sudo bpftool prog load first.bpf.o /sys/fs/bpf/first autoattach`. This will succeed, and the bpf program will be loaded and attached.
1. Demonstrate `sudo bpftool prog dump xlated name first` and `sudo bpftool prog dump jited name first`.
1. In a separate window/tab, run `sudo cat /sys/kernel/debug/tracing/trace_pipe`. Show how all process execution is traced.
1. Unload with `sudo rm /sys/fs/bpf/first`.
1. Use the corrected program to demonstrate calling another helper function.

