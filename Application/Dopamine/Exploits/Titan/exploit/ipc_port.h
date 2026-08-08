#ifndef IPC_PORT_H
#define IPC_PORT_H

#include <stdint.h>
#include <mach/mach.h>

uint64_t proc_find_by_name(const char *name);
int create_port_for_port_number(uint32_t port_num);
int task_copy_ipc_entry(uint64_t ipc_entry, mach_port_t *out);
uint64_t process_find_open_userclient(const char *name, uint64_t vtable, uint64_t *uc_kaddr);

#endif // IPC_PORT_H
