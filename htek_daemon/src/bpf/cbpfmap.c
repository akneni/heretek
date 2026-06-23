#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/mman.h>


int32_t open_htekmap(const char *map_path) {
    int32_t fd = bpf_obj_get(map_path);
    return fd;
}

void *mmap_bfpmap(int32_t fd, size_t length, char *errstr, size_t errstr_len) {
    if (errstr != NULL && errstr_len > 0) {
        errstr[0] = '\0';
    }

    void *mptr = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (mptr == MAP_FAILED) {
        int err = errno;
        if (errstr != NULL && errstr_len > 0) {
            snprintf(errstr, errstr_len, "mmap failed: %s (errno %d)", strerror(err), err);
        }
        mptr = NULL;
    }

    return mptr;
}
