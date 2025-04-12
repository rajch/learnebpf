#define __TARGET_ARCH_x86

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "sixth.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Here we define the ring buffer. Notice, nothing about
// keys or values here. The max_entries member specifies
// the size of the buffer in bytes.
struct comm_buffer
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128);
};

struct comm_buffer buffer SEC(".maps");

// The ELF section name needs to be "uprobe". You can
// optionally provide the fully qualified path to an ELF
// binary file, followed by a : and a symbol defined in
// it. This will enable auto-attachment.
// Note the use of the BPF_UPROBE macro, defined in 
// bpf_tracing.h. This is similar to BPF_KPROBE_SYSCALL
// used in the "second" example. It writes a function
// definition that extracts the parameters of the symbol
// that will be attached to the uprobe, from the ctx 
// parameter which is of type pt_regs.
// In this example, we are attaching via uprobe to a 
// shared library called libreadline.so.8, which is 
// usually available in the path /usr/lib/. Note the 
// full path after uprobe/ - that's why there are two /
// characters. We attach to a function called readline,
// whose signature is:
//   char * readline (const char *prompt);
SEC("uprobe//usr/lib/libreadline.so.8:readline")
int BPF_UPROBE(sixth, const char *prompt)
{
    struct sixth_data *data;

    // The helper function bpf_ringbuf_reserve checks to 
    // see if the ringbuffer has enough space to write
    // whatever data we need. If we call it, there HAS 
    // to be a corresponding call to either
    // bpf_ringbuf_submit or bpf_ringbuf_discard, on all
    // possible code paths. The verifier checks for this.
    void *bufferspace = bpf_ringbuf_reserve(&buffer, sizeof(struct sixth_data), 0);
    if (bufferspace != NULL)
    {
        // If there is available space, we copy the data
        // (value of the prompt parameter of the readline call)
        // to that space.
        data = (struct sixth_data *) bufferspace;
        int len = bpf_probe_read_str(data->readline_prompt, sizeof(data->readline_prompt), prompt);
        if (len > 0)
        {
            // If the prompt string is not empty, we commit or
            // send the data to the ringbuffer.,
            data->promptlen = len;
            bpf_ringbuf_submit(bufferspace,0);
        }
        else
        {
            // If the prompt string is empty, we discard the 
            // reserved space in the ringbuffer. If we leave
            // out this call, the verifier will complain.
            bpf_ringbuf_discard(bufferspace,0);
        }
    }
    else
    {
        // If there is no space, we don't have to even collect
        // the data: just trace and move on.
        bpf_printk("Missed recording readline call with %s", prompt);
    }

    return 0;
}
