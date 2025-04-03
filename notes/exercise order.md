# Exercise Order

## Set one (introduction)

### Absolute start

1. Bare-bones ebpf program (just a return 0). Demonstrate:
  1. includes
  1. SEC macro and ELF section
  1. function name as program name
  1. compilation basics
  1. bpftool basics
2. Call a helper function or two
  1. Show the verifier catching license compliance
  1. Add the LICENSE global viariable in the "license" ELF section
3. Create a loader program
  1. Download and demonstrate

### BTF, CO-RE, Verifier

1. CO-RE and BTF
  1. Explain CO-RE and BTF
  1. Explain and generate **vmlinux.h**
  1. Explain `-g` and `-O2` while compiling BPF
2. Slightly more involved BPF program, syscall with parameters
  1. Explain the trace program function declaration macros
  1. Explain the architecture-specific define
  1. Write naive code
  1. Show the verifier catching problems
  1. Correct the code
3. Skeletons
  1. Generate skeleton
  1. Show main program with skeleton
  1. Explain the embedding of object code

### BPF Maps

1. Maps
  1. Explain maps and map types
  1. Write BPF program which uses a map
  1. Generate skeleton, show the map access
  1. Write userspace program
2. BPF programs in containers
  1. Show how the BPF programs are still running in the same kernel
  1. Show capabilities: CAP_BPF, CAP_PERFMON for tracing, CAP_NET_ADMIN for networking

### XDP Programs
