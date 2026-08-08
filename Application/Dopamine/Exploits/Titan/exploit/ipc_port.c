//
//  ipc_port.c
//  Titan
//
//  Created by alfie on 29/07/2026.
//

#include "ipc_port.h"
#include "info.h"
#include "titan.h"
#include "offsets.h"

#include <unistd.h>
#include <errno.h>
#include <libjailbreak/libjailbreak.h>

#define PROC_PIDIPCTABLEINFO (32)

int proc_pidinfo(int pid, int flavor, uint64_t arg,  void *buffer, int buffersize);

uint64_t proc_find_by_name(const char *name) {
    int offset = 0;
    if (XNU_MAJOR_GREATER_THAN(8792)) {
        offset = 0x579;
    } else {
        offset = 0x381;
    }
    uint64_t proc = ksymbol(allproc);
    while ((proc = kread_ptr(proc))) {
        char name_buf[33];
        for (int i = 0; i < 33; i++) {
            name_buf[i] = kread8(proc + offset + i);
            if (!name_buf[i]) break;
        }
        if (strncmp(name_buf, name, 32) == 0) {
            return proc;
        }
    }
    return 0;
}

static uint64_t ipc_table_resolve(uint64_t smr_ptr, uint32_t *sizeOut) {
    const bool new_encoding = gTitanContext.xnu_version > 0x225814018FFFFFLL; // iOS 16.3 beta 2 and higher
    const bool wide_vas = gTitanContext.soc >= SOC_A16 || gTitanContext.large_memory;
    
    uint64_t addr_mask, count_mask, or_bits;
    uint8_t  count_shift;
    uint32_t count_field_mask;
    
    if (wide_vas) {
        addr_mask = new_encoding ? 0xFFFFFFFFFFFFFFE0ULL : 0xFFFF9FFFFFFFFFF0ULL;
        count_mask = new_encoding ? 0xFFFFBFFFFFFFC000ULL : 0xFFFF9FFFFFFFC000ULL;
        or_bits = new_encoding ? 0x0400000000000ULL    : 0x0600000000000ULL;
        count_shift = new_encoding ? 46 : 45;
    } else {
        addr_mask = new_encoding ? 0xFFFFFFFFFFFFFFE0ULL : 0xFFFFFF9FFFFFFFF0ULL;
        count_mask = new_encoding ? 0xFFFFFFBFFFFFC000ULL : 0xFFFFFF9FFFFFC000ULL;
        or_bits= new_encoding ? 0x0004000000000ULL    : 0x0006000000000ULL;
        count_shift = new_encoding ? 38 : 37;
    }
    
    count_field_mask = new_encoding ? 0x1 : 0x3;
    
    const uint32_t count_field = count_field_mask & (smr_ptr >> count_shift);
    const uint32_t alignment_bits = smr_ptr & 0xF;
    
    if (count_field) {
        if (new_encoding) {
            *sizeOut = (uint32_t)((smr_ptr & 0x10) | 0x20) << alignment_bits;
        } else {
            *sizeOut = count_field << alignment_bits;
        }
    } else {
        *sizeOut = ((uint32_t)smr_ptr << 14) & 0x0FFFC000;
        addr_mask  = count_mask;
    }
    
    return (smr_ptr & addr_mask) | or_bits;
}

static uint64_t ipc_space_table(uint64_t space, uint32_t *size_out) {
    uint32_t size = 0;
    uint64_t table = ipc_table_resolve(kread_ptr(space + koffsetof(ipc_space, table)), &size);
    if (size_out) *size_out = size;
    return table;
}

static int create_new_send_once_port(mach_port_name_t port_num) {
    mach_port_name_t new_port = MACH_PORT_NULL;

    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &new_port);
    if (kr != KERN_SUCCESS)
        return kr;

    mach_port_name_t target_name = (port_num << 8) | 3;
    kern_return_t insert_kr = mach_port_insert_right(mach_task_self(), target_name, new_port, MACH_MSG_TYPE_MAKE_SEND_ONCE);

    if (insert_kr == KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), target_name);
        kr = KERN_SUCCESS;
    } else if (insert_kr == KERN_NAME_EXISTS) {
        kr = KERN_SUCCESS;
    } else {
        kr = insert_kr;
    }

    if (MACH_PORT_VALID(new_port)) {
        mach_port_mod_refs(mach_task_self(), new_port, MACH_PORT_RIGHT_RECEIVE, -1);
    }

    return kr;
}

int create_port_for_port_number(uint32_t port_num) {
    uint64_t ipc_info = 0;

    if (proc_pidinfo(getpid(), PROC_PIDIPCTABLEINFO, 0, &ipc_info, sizeof(ipc_info)) != sizeof(ipc_info)) {
        printf("ERROR: proc_pidinfo failed to get IPC table info: %s\n", strerror(errno));
        return -1;
    }

    uint32_t table_size  = (uint32_t)(ipc_info);
    uint32_t table_limit = (uint32_t)(ipc_info >> 32);

    if (table_limit >= port_num)
        return 0;

    uint32_t target = port_num - table_limit + table_size;
    int kr = create_new_send_once_port(target);
    if (kr) {
        printf("ERROR: failed to create new send-once port for port number %u: 0x%X\n", port_num, kr);
        return -1;
    }

    return 0;
}


int task_copy_ipc_entry(uint64_t ipc_entry, mach_port_t *out) {
    uint32_t target_bit = 0x200000;
    uint32_t ie_bits = kread32(ipc_entry + 8);
    if ((ie_bits & target_bit) != 0) {
        kwrite32(ipc_entry + 8, ie_bits & ~target_bit);
    }

    if (create_port_for_port_number(8) == KERN_SUCCESS) {
        uint64_t itk_space = kread_ptr(task_self() + koffsetof(task, itk_space));
        uint32_t ipc_table_size = 0;
        uint64_t ipc_table = ipc_space_table(itk_space, &ipc_table_size);
        uint32_t ipc_table_count = ipc_table_size / ksizeof(ipc_entry);

        void *new_table = malloc(ipc_table_size);
        if (!new_table) {
            printf("ERROR: failed to allocate memory for new IPC table\n");
            return -1;
        }

        kreadbuf(ipc_table, new_table, (uint32_t)ipc_table_size);

        uint32_t port = 0;

        if (ipc_table_count) {
            int current_idx = 0;
            uint32_t chosen_entry = 0;
            while (1) {
                uint64_t cur_ptr = 0;
                memcpy(&cur_ptr, new_table + (current_idx * ksizeof(ipc_entry)), sizeof(uint64_t));
                if (cur_ptr == 0) {
                    if (++current_idx >= ipc_table_count) goto not_in_table;
                    continue;
                }
                cur_ptr = UNSIGN_PTR(cur_ptr);
                if (cur_ptr == ipc_entry) {
                    chosen_entry = *(uint32_t *)(new_table + (current_idx * ksizeof(ipc_entry)) + 8);
                    if (chosen_entry & 0x10000) {
                        break;
                    }
                }
                if (++current_idx >= ipc_table_count) {
                    goto not_in_table;
                }
            }
            port = (uint32_t)((((uint64_t)current_idx << 32) | (uint32_t)chosen_entry) >> 24);
        } else {
    not_in_table:;
            port = 0;
        }

        free(new_table);

       if (MACH_PORT_VALID(port)) {
            int kr = mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, 1);
            if (kr != KERN_SUCCESS)
                return kr | 0x80000000;
            *out = port;
            return 0;
        }
        mach_port_t name = MACH_PORT_NULL;
        kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &name);
        if (kr != KERN_SUCCESS) {
            printf("ERROR: failed to allocate new port: %s\n", mach_error_string(kr));
            return -1;
        }

        uint64_t port_object = task_get_ipc_port_object(task_self(), name);
        if (!port_object) {
            printf("ERROR: failed to get kernel address for new port\n");
            mach_port_deallocate(mach_task_self(), name);
            return -1;
        }

        uint32_t existing_bits = kread32(ipc_entry);
        if (existing_bits & 0x400) {
            kwrite32(ipc_entry, existing_bits & ~0x400);
        }
        kwrite64(port_object + koffsetof(ipc_port, kobject) + 2 * sizeof(uint64_t), ipc_entry);

        mach_port_t previous = MACH_PORT_NULL;
        kr = mach_port_request_notification(mach_task_self(), name, 70, 1, 0, 0x15, &previous);
        if (kr != KERN_SUCCESS) {
            printf("ERROR: failed to request port notification: %s\n", mach_error_string(kr));
            mach_port_deallocate(mach_task_self(), name);
            return -1;
        }

        if (MACH_PORT_VALID(previous)) {
            kr = create_port_for_port_number(8);
            if (kr != KERN_SUCCESS) {
                printf("ERROR: failed to create replacement port for previous notification port: %s\n", mach_error_string(kr));
                mach_port_deallocate(mach_task_self(), name);
                return -1;
            }

            uint64_t previous_entry = task_get_ipc_port_table_entry(task_self(), previous);
            uint32_t previous_bits = kread32(previous_entry + 8);
            if ((previous_bits & 0x1F0000) != 0x40000) {
                printf("ERROR: previous notification port has unexpected bits: 0x%X\n", previous_bits);
                mach_port_deallocate(mach_task_self(), name);
                return -1;
            }
            kwrite32(previous_entry + 8, (previous_bits & 0xFFE0FFFF) | 0x10000);

            kr = mach_port_mod_refs(mach_task_self(), name, 1, -1);
            if (kr != KERN_SUCCESS) {
                printf("ERROR: failed to decrement refcount on new port: %s\n", mach_error_string(kr));
                return -1;
            }

            uint32_t retries = 0;
            mach_port_t new_port = MACH_PORT_NULL;
            while (1) {
                kr = mach_port_allocate(mach_task_self(), 1, &new_port);
                if (kr) break;
                kr = mach_port_mod_refs(mach_task_self(), new_port, 1, -1);
                if (kr) break;
                kr = mach_port_insert_right(mach_task_self(), new_port, previous, 0x13);
                if (!kr) {
                    if (existing_bits & 0x400) {
                        kwrite32(ipc_entry, existing_bits);
                    }
                    uint64_t table_entry_ptr = task_get_ipc_port_table_entry(task_self(), previous);
                    uint32_t new_bits = kread32(table_entry_ptr + 8);
                    if ((new_bits & 0x1F0000) == 0x10000) {
                        new_bits = (new_bits & 0xFFE0FFFF) | 0x100000;
                        kwrite32(table_entry_ptr + 8, new_bits);
                        kr = mach_port_mod_refs(mach_task_self(), previous, 4, -1);
                        if (!kr) {
                            *out = new_port;
                            return 0;
                        }
                    }
                    printf("ERROR: incorrect bits\n");
                    return 0x28011;
                }
                if ((kr & ~8) != 5 || retries++ >= 8) {
                    printf("ERROR: hit maximum number of retries\n");
                    return kr | 0x80000000;
                }
            }
        }
    }
    printf("ERROR: failed to create port\n");
    return -1;
}

uint64_t process_find_open_userclient(const char *name, uint64_t vtable, uint64_t *uc_kaddr) {
    uint64_t proc = proc_find_by_name(name);
    if (!proc) {
        printf("ERROR: failed to find process with name %s\n", name);
        return 0;
    }
    
    uint64_t task = proc_task(proc);
    uint64_t itk_space = kread_ptr(task + koffsetof(task, itk_space));
    uint32_t ipc_table_size = 0;
    uint64_t ipc_table = ipc_space_table(itk_space, &ipc_table_size);
    uint32_t ipc_table_count = ipc_table_size / ksizeof(ipc_entry);
    printf("Process %s has IPC table at 0x%llX with %u entries\n", name, ipc_table, ipc_table_count);

    for (int i = 0; i < ipc_table_count; i++) {
        uint64_t entry = kread_ptr(ipc_table + (i * ksizeof(ipc_entry)));
        if (!entry) continue;
        uint32_t ie_object_lower = kread32(entry);
        if (ie_object_lower & 0x80000000) {
            if ((ie_object_lower & 0x3FF) != 0) {
                if ((ie_object_lower & 0x3FF) == 29) {
                    uint64_t kobject = kread_ptr(entry + koffsetof(ipc_port, kobject));
                    if (XNU_MAJOR_GREATER_THAN(10000)) {
                        // kobject is an IOMachPort
                        char buf[0x20];
                        kreadbuf(kobject + 0x18, buf, 0x20);
                        kobject = UNSIGN_PTR(*(uint64_t *)(buf + 0x18));
                    }
                    if (kread_ptr(kobject) == vtable + 0x10) {
                        printf("Found userclient with vtable 0x%llX at entry %d\n", vtable, i);
                        if (uc_kaddr) *uc_kaddr = kobject;
                        return entry;
                    }
                }
            }
        }
    }
    printf("ERROR: failed to find userclient with vtable 0x%llX in process %s\n", vtable, name);

    return 0;
}
