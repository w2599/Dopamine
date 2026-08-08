#ifndef KERNEL_PATCHFINDER_H
#define KERNEL_PATCHFINDER_H

#include <stdint.h>
#include <stdlib.h>

typedef struct s_FilesetEntry {
    const char *name;
    uint64_t base;
    uint64_t text_exec, data;
    uint64_t text_exec_size, data_size;
} fileset_entry_t;

int kpf_init(void);
int kpf_find_fileset_partial(const char *name, size_t name_len, uint64_t *baseOut);
int kpf_find_fileset(const char *name, uint64_t *baseOut);
void kpf_deinit(void);

fileset_entry_t *kpf_fileset_entry_init(uint64_t va, const char *name);
void kpf_fileset_entry_deinit(fileset_entry_t *entry);
uint64_t kpf_fileset_entry_patchfind_text(fileset_entry_t *entry, uint32_t insns[], uint32_t masks[], int insn_count);
uint64_t kpf_fileset_entry_patchfind_data(fileset_entry_t *entry, uint8_t data[], uint8_t masks[], size_t data_len);

int kpf_run(void);

#endif // KERNEL_PATCHFINDER_H
