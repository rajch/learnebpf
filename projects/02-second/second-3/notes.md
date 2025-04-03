# Exercises

1. Compile bpf to object file.
1. Use `bpftool gen skeleton second.bpf.o >second.bpf.skel.h` to generate skeleton.
1. Show the skeleton. Especially show the static inline function NAME__elf_bytes and explain embedding
1. Re-write **main.c** from the last example (first-3) to use skeleton functions instead of libbpf ones.
