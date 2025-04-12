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

    // Here, we try to auto attach any bpf programs defined
    // in the object file. This requires the ELF section to
    // have been specified in the form:
    // uprobe/PATH_TO_BINARY:SYMBOL
    // The binary needs to be present in that path, as seen
    // by the userspace program. This means, if a userspace
    // program is running in a container, the binary needs 
    // to be present in the same container. 
    // The symbol needs to be present in the binary. Every
    // time the function (symbol) is called by any process
    // the BPF program will be invoked. In the case of the
    // binary being a shared library, the path needs to 
    // match exactly.
    int err = sixth_bpf__attach(obj);
    if (err < 0)
    {
        fprintf(stderr, "Error while attaching: %d.\n", err);
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