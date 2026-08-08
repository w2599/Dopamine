#ifndef utils_h
#define utils_h

#include "common.h"

void* reverse_memmem(const void* haystack, size_t haystack_len, const void* needle, size_t needle_len);
void hexdump(const void* data, size_t size);
char* get_device_machine(void);
void init_target_file(void);
void mem_clear_cache(void* ptr, uint64_t size);
int offsets_init(void);

#endif /* utils_h */
