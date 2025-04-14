/*
    Sample userspace program

    This is a minimal sample that demonstrates how eBPF programs are loaded
    via a userspace program written in C, using libbpf.
*/

#include <stdio.h>
#include <errno.h>
#include <bpf/libbpf.h>

#define PROGFILE "first.bpf.o"
#define PROGNAME "first"

int main(int argc, char **argv)
{
    struct bpf_object * bpfobj;
    struct bpf_program * bpfprog;
    struct bpf_link *bpflink;
    int err;

    // The first step is to open the eBPF object file.
    // This step will verify if the file is a valid eBPF object file.
    //
    printf("Opening the eBPF object file...\n");
    bpfobj = bpf_object__open(PROGFILE);
    if(bpfobj == NULL) {
        fprintf(stderr, "Could not open the object file.\n");
        return 1;
    }

    // The second step is to load the eBPF object. This will run the eBPF verifier
    // and will fail if verification does not succeed.
    // This step requires elevated priviledges.
    printf("Object file opened. Now loading...\n");
    err = bpf_object__load(bpfobj);
    if(err!=0) {
        fprintf(stderr, "BPF object load failed with error: %d.\n", errno);
        return 1;
    }

    // The third step is to obtain a handle to an eBPF program in the eBPF object.
    // The program name matches the function name used in the eBPF source file.
    printf("BPF object loaded. Now retrieving program...\n");
    bpfprog = bpf_object__find_program_by_name(bpfobj, PROGNAME);
    if(bpfprog == NULL) {
       fprintf(stderr, "Could not find the program called %s in the object.\n", PROGNAME);
       return 1;
    }

    // The fourth step is to attach the eBPF program to the appropriate part  of
    // the kernel. For some kind of pograms, this attachment is automatic, based
    // on the ELF section name in the object file where the program was found.
    //
    // In this sample, the program "first " was defined in an ELF section called
    // ksyscall/execve. So, libbpf will be able to auto-attach it to a kprobe to
    // the syscall named execve.
    printf("BPF program found. Now attaching...\n");
    bpflink = bpf_program__attach(bpfprog);
    if(!bpflink) {
        fprintf(stderr, "BPF program attach failed with error: %d.\n", errno);
        return 1;
    }

    // Once the attachment is complete, the eBPF program will be called as and
    // when required. In the userspace program, we may now use any method to
    // communicate with it.
    printf("BPF program attached. You may now try 'cat /sys/kernel/debug/tracing/trace_pipe'.\n");

    // When the userspace program finishes, the eBPF program will by default be
    // detached and unloaded automatically. We can prevent this by "pinning" it,
    // or not exit the userspace program until our work is done.
    printf("Press ENTER to finish...\n");
    getchar();

    bpf_program__unload(bpfprog);
    bpf_object__close(bpfobj);

    return 0;
}
