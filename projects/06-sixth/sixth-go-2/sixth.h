//go:build ignore

struct sixth_data
{
    char readline_prompt[255];
    int promptlen;
};

// Dummy instance added for bpf2go code generation
const struct sixth_data *unuseddata __attribute__((unused));