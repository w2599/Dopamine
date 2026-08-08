#ifndef IOGPUDEVICE_H
#define IOGPUDEVICE_H

#include <stdint.h>
#include <stdbool.h>

struct IOGPU_create_command_queue_input {
    const char name[0x400];
    uint32_t unknown1;
    bool unknown2;
} __attribute__((aligned(8)));

struct IOGPU_create_command_queue_output {
    uint32_t id;
    uint64_t globalObjectIDCounter;
};

struct IOGPU_create_notification_queue_input {
    uint64_t num_entries;
    uint64_t entry_size;
};

struct IOGPU_create_notificationqueue_output {
    uint64_t address;
    uint32_t id;
} __attribute__((aligned(8)));

struct IOGPU_set_notification_queue_input {
    uint32_t command_queue_id;
    uint64_t notification_queue_id;
} __attribute__ ((aligned(8)));

struct IOGPU_create_shmem_input {
    uint64_t size;
    uint32_t unknown;
} __attribute__ ((aligned(8)));

struct IOGPU_create_shmem_output {
    uint64_t address;
    uint32_t size;
    uint32_t id;
};

struct IOGPU_submit_command_buffer_input {
    uint32_t queue_id;
    uint64_t unknown;
    uint64_t arg_count;
    uint64_t arg_size;
};

#define IOGPU_SELECTOR_CREATE_COMMAND_QUEUE         (7)
#define IOGPU_SELECTOR_CREATE_NOTIFICATION_QUEUE    (15)
#define IOGPU_SELECTOR_CREATE_SHARED_MEMORY         (13)
#define IOGPU_SELECTOR_SET_NOTIFICATION_QUEUE       (25)
#define IOGPU_SELECTOR_SUBMIT_COMMAND_BUFFERS       (26)

int IOGPU_create_command_queue(uint32_t *id);
int IOGPU_create_notification_queue(uint32_t *id);
int IOGPU_create_shared_memory(uint32_t size, uint32_t *id);
int IOGPU_set_notification_queue(uint32_t command_queue_id, uint32_t shmem_id);
int IOGPU_submit_command_buffers(uint32_t command_queue_id, uint32_t shmem_id_1, uint32_t shmem_id_2);

#endif // IOGPUDEVICE_H
