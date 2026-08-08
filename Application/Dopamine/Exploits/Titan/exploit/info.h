#ifndef INFO_H
#define INFO_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

struct titan_info {
    struct {
        uint64_t proc;
        uint64_t task;
        uint64_t vm_map;
        uint64_t pmap;
        uint64_t tte;
        uint64_t ttep;
        bool has_sptm;
    } kernel_info;
};
extern struct titan_info gInfo;

#define kerninfo(x) (gInfo.kernel_info.x)

#endif // INFO_H
