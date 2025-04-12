#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "sixth.bpf.skel.h"
#include "sixth.h"

static bool cancel = false;

// This function is called if the process receives the SIGTERM
// or SIGINT signals. It causes the event loop in the main 
// program to finish.
void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM)
    {
        printf("\nInterrupt received by signal handler. Exiting...\n");
        fflush(stdout);
        cancel = true;
    }
    
}

// This function is called whenever data is received in the 
// ringbuffer. The BPF program can decide if this function is
// called on every write, or once after a batch of writes. 
// The userspace program cannot decide this: it just reacts.
int handle_rb_event(void *ctx, void *data, size_t data_sz)
{
    struct sixth_data *actualdata;
    if (data_sz != sizeof(*actualdata))
    {
        fprintf(stderr, "Invalid data received.\n");
        return -420; // A nonzero value indicates error
    }

    actualdata = (struct sixth_data *)data;
    printf("Data received: %s\n", actualdata->readline_prompt);
    fflush(stdout);
    return 0;
}

int main(int argc, char *argv[])
{
    printf("Loading BPF program...\n");
    fflush(stdout);
    struct sixth_bpf *obj = sixth_bpf__open_and_load();
    if (obj == NULL)
    {
        fprintf(stderr, "Could not open BPF object(s).\n");
        return 1;
    }

    printf("BPF program loaded. Now attaching uprobe...\n");
    fflush(stdout);

    // This macro, defined in libbpf_common.h, is a way to
    // define various BPF structs whose names end in opts.
    // In this case, we are defining a variable of type
    // bpf_uprobe_opts. The name of the variable is opts.
    // (I am amazingly creative while naming things.)
    // It specifies a field called attach mode whose value
    // indicates that the attachment should be via bpflink.
    // It also sets a field called retprobe to false, which
    // means that the probe created later will be an uprobe
    // and not a uretprobe.
    // Of special note is the field called func_name. This 
    // should be set to the symbol or name of the function
    // in a userspace binary to which you want to attach a
    // uprobe.
    // The macro ensures that a variable of the specified 
    // type gets created, its memory is zeroed out, and a
    // field called .sz is set to the size of the type. It
    // then fills in the other fields as specified in the
    // macro invocation.
    LIBBPF_OPTS(
        bpf_uprobe_opts, 
        opts, 
        .attach_mode=PROBE_ATTACH_MODE_LINK, 
        .func_name="readline", 
        .retprobe=false
    );

    // We call bpf_program__attach_uprobe_opts with the
    // opts defined above, and some parameters. The 2nd
    // parameter contains 0 if we want to attach the
    // uprobe to a function called by the userspace 
    // program itself (self), -1 if to a function called
    // from *any* PID, or a specific PID number if to 
    // a function called only in that process.
    // The third parameter is the path to a binary file.
    // It should be fully qualified if the binary is a
    // shared library.
    // Note that the path will be resolved by the 
    // userspace program, so only when the function
    // loaded from that path is hit will the uprobe fire.
    // So if you have programs which load a shared library
    // from different paths, your uprobe will not capture
    // all of them. This becomes even more important in
    // containers.
    // In this case, we specify the shared library
    // /usr/lib/libreadline.so.8. The function to attach 
    // the uprobe is specified in the opts.
    struct bpf_link * probelink = bpf_program__attach_uprobe_opts(
                            obj->progs.sixth,
                            -1,
                            "/usr/lib/libreadline.so.8",
                            0,
                            &opts
    );
    if (probelink == NULL)
    {
        fprintf(stderr, "Error while attaching: %d.\n", errno);
        sixth_bpf__destroy(obj);
        return 1;
    }

    printf("uprobe attached. Now setting up ringbuffer...\n");
    fflush(stdout);

    // This is where we set up communication with the ring
    // buffer. The function handle_rb_event will be called
    // when data arrives in the ring buffer.
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(obj->maps.buffer), handle_rb_event, NULL, NULL);
    if (rb == NULL)
    {
        fprintf(stderr, "Error while creating ringbuffer.\n");
        sixth_bpf__detach(obj);
        sixth_bpf__destroy(obj);
        return 1;
    }

    printf("Ringbuffer set. Now setting up monitoring...\n");
    fflush(stdout);

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    printf("Monitoring started. Press ^C to stop...\n");
    while (!cancel)
    {
        // The function ring_buffer__poll causes a wait to
        // happen until data arrives in the ring buffer. 
        // So, sleep() is not needed in this case.
        // It exits as soon as data arrives with a zero 
        // return value. In case of an error, including
        // SIGINT, it returns an appropriate error value.
        int err = ring_buffer__poll(rb, 3000);
        if (err == -EINTR)
        {
            printf("\nInterrupt received by polling handler. Exiting...\n");
            break;
        }

        if (err < 0)
        {
            fprintf(stderr, "Error while polling ringbuffer: %d.\n", err);
        }
    }

    printf("Monitoring done. Cleaning up...\n");
    fflush(stdout);

    sixth_bpf__detach(obj);
    sixth_bpf__destroy(obj);

    printf("All done.\n");
    fflush(stdout);
    return 0;
}