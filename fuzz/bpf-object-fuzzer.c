#include "libbpf.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct bpf_object *obj = NULL;
    int err;

    // Open libbpf object from memory
    obj = bpf_object__open_mem(data, size, NULL);
    
    // Check for errors
    if (!obj) {
        // Log or report error
        return 0;
    }

    // Close the libbpf object
    bpf_object__close(obj);

    return 0;
}

