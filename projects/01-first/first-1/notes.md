## Program

```
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/__x64_sys_execve")
int first(void *ctx) {
    return 0;
}
```

`<linux/bpf.h>` is the kernel header which defines BPF data types etc. Specific to host kernel.
`<bpf/bpf_helpers.h>` defines a bunch of C macros to help write BPF programs.

`SEC` is one of those macros. It names the ELF section in which a function, struct/union or variable will be placed. Loaders, such as the libbpf loader, use that name to figure out the BPF program type, and the extension point (kprobe, tracepoint, ingress etc.) where this program is to be attached.

`"kprobe/__x64_sys_execve"` - this section name tells loaders that the following function is a BPF program of type Kprobe, and should be attached to the kernel function called `__x64_sys-execve`, which implements the `execve` syscall on AMD64 kernels. Kernel functions in the running kernel can be listed using `cat /proc/kallsyms`.

`int first(void *ctx)` - every BPF program is a C function that takes a pointer as an parameter, and returns an int. The parameter can contain different types of values depending on the program type (and sometimes the system architecture). The return value may or may not have an effect depending on the program type.

## Exercises

1. Compile with `clang -target bpf -c first.bpf.c`. `-target bpf` ensures that the object code is BPF bytecode, `-c` ensures that the compiler toolset does not try to link the object code into an executable binary. This will produce **first.bpf.o**.
1. Examine with `readelf -h first.bpf.o`. Show that this ELF file contains EBPF bytecode.
1. Examine with `readelf -S first.bpf.o`. Show our section name in the table.
1. Load with `sudo bpftool prog load first.bpf.o /sys/fs/bpf/first`. Explain why sudo, why the filename (pinning).
1. Demonstrate `sudo bpftool prog dump xlated name first` and `sudo bpftool prog dump jited name first`.
1. Unload with `sudo rm /sys/fs/bpf/first`.
