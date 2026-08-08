#ifndef momentarius_h
#define momentarius_h

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/sysctl.h>
#include <IOKit/IOKitLib.h>

int momentarius_init_A12(void);
int momentarius_init_A13(void);

#if 1
#define debug_log(...) {fprintf(stderr, "[momentarius] " __VA_ARGS__);usleep(1000);}
#else
#define debug_log(...)
#endif

#define TTE_PA_MASK             0x0000ffffffffc000ull
#define TT_L2_SIZE              0x0000000002000000ull
#define TT_L1_SIZE              0x0000001000000000ull
#define TT_L3_SHIFT             14
#define TT_L1_SHIFT             36

#define A64_B_COND_MASK         0xff000010
#define A64_B_COND_OPCODE       0x54000000

#define IO_MAP_DEFAULT_CACHE    0x0
#define IO_MAP_INNER_WRITEBACK  0x500

#define IOMFB_POWER_CHANGE      12
#define IOMFB_START_SWAP        4
#define IOMFB_CANCEL_SWAP       81
#define IOMFB_COLOR_INVERT      19

typedef struct {
    struct {
        uint64_t text_pa;
        uint64_t text_va;
        uint64_t text_size;
        uint64_t data_pa;
        uint64_t data_va;
        uint64_t data_kva;
        uint64_t data_size;
        uint64_t ttbr_pa;
        uint64_t ttbr_kva;
        uint32_t shc_offset;
        uint32_t *shc_data;
        uint32_t ttbr1_load_offset;
        uint32_t *ttbr1_load_data;
        uint32_t hook_offset;
        uint32_t *hook_data;
        uint32_t method;
        uint64_t target_l3_table;
    } gfx;
    uint64_t self_proc_addr;
    uint64_t kern_vm_map;
    uint64_t kern_min_va;
    uint64_t kern_max_va;
    uint64_t kern_tte;
    uint64_t kern_ttep;
    uint64_t fake_l1_table_kva;
    uint64_t fake_l2_table_kva;
    uint64_t self_ref_pt_kva;
    uint64_t new_ttbr1;
    uint64_t target_rw_mapping;
    uint64_t target_rw_pte;
    uint64_t target_kern_addr;
    uint64_t target_gfx_addr;
    uint64_t target_pte;
    uint64_t orig_pte;
    mach_port_t iomfb_client;
} momentarius_t;

#endif /* momentarius_h */
