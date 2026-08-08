#include "IOGPUDevice.h"
#include "titan.h"

#include <IOKit/IOKitLib.h>

int IOGPU_create_command_queue(uint32_t *id) {
    struct IOGPU_create_command_queue_input input = { 0 };
    struct IOGPU_create_command_queue_output output = { 0 };
    size_t out_size = sizeof(output);
    kern_return_t kr = IOConnectCallStructMethod(gTitanContext.IOGPUDevice_port,
                                                 IOGPU_SELECTOR_CREATE_COMMAND_QUEUE,
                                                 (const uint64_t *)&input, sizeof(input),
                                                 &output, &out_size);
    if (kr != KERN_SUCCESS) {
        printf("ERROR: failed to create command queue (%s)\n", mach_error_string(kr));
        return -1;
    }
    if (id) *id = output.id;
    return 0;
}

int IOGPU_create_notification_queue(uint32_t *id) {
    struct IOGPU_create_notification_queue_input scalar = {
        .num_entries = 256,
        .entry_size = 32,
    };
    struct IOGPU_create_notificationqueue_output output = { 0 };
    size_t out_size = sizeof(output);
    kern_return_t kr = IOConnectCallMethod(gTitanContext.IOGPUDevice_port,
                                           IOGPU_SELECTOR_CREATE_NOTIFICATION_QUEUE,
                                           (const uint64_t *)&scalar,
                                           sizeof(scalar) / sizeof(uint64_t),
                                           0, 0, 0, 0,
                                           &output, &out_size);
    if (kr != KERN_SUCCESS) {
        printf("ERROR: failed to create notification queue (%s)\n", mach_error_string(kr));
        return -1;
    }
    if (id) *id = output.id;
    return 0;
}

int IOGPU_create_shared_memory(uint32_t size, uint32_t *id) {
    struct IOGPU_create_shmem_input scalar = {
        .size = size,
        .unknown = 0,
    };
    struct IOGPU_create_shmem_output output = { 0 };
    size_t out_size = sizeof(output);
    kern_return_t kr = IOConnectCallMethod(gTitanContext.IOGPUDevice_port,
                                           IOGPU_SELECTOR_CREATE_SHARED_MEMORY,
                                           (const uint64_t *)&scalar,
                                           sizeof(scalar) / sizeof(uint64_t),
                                           0, 0, 0, 0,
                                           &output, &out_size);
    if (kr != KERN_SUCCESS) {
        printf("ERROR: failed to create shared memory (%s)\n", mach_error_string(kr));
        return -1;
    }
    if (id) *id = output.id;
    return 0;
}

int IOGPU_set_notification_queue(uint32_t command_queue_id, uint32_t shmem_id) {
    struct IOGPU_set_notification_queue_input scalar = {
        .command_queue_id = command_queue_id,
        .notification_queue_id = shmem_id,
    };
    kern_return_t kr = IOConnectCallScalarMethod(gTitanContext.IOGPUDevice_port,
                                                 IOGPU_SELECTOR_SET_NOTIFICATION_QUEUE,
                                                 (const uint64_t *)&scalar,
                                                 sizeof(scalar) / sizeof(uint64_t),
                                                 0, 0);
    if (kr != KERN_SUCCESS) {
        printf("ERROR: failed to set notification queue (%s)\n", mach_error_string(kr));
        return -1;
    }
    return 0;
}

int IOGPU_submit_command_buffers(uint32_t command_queue_id, uint32_t shmem_id_1, uint32_t shmem_id_2) {
    struct IOGPU_submit_command_buffer_input scalar = {
        .queue_id = command_queue_id,
        .unknown = 0,
        .arg_count = 1,
        .arg_size = 56,
    };
    
    void *argument = malloc(56);
    if (!argument) {
        printf("ERROR: failed to allocate memory for command buffer argument\n");
        return -1;
    }
    bzero(argument, 56);
    *(uint32_t *)((uintptr_t)argument + 0) = shmem_id_1;
    *(uint32_t *)((uintptr_t)argument + 4) = shmem_id_2;
    kern_return_t kr = IOConnectCallMethod(gTitanContext.IOGPUDevice_port,
                                           IOGPU_SELECTOR_SUBMIT_COMMAND_BUFFERS,
                                           (const uint64_t *)&scalar,
                                           sizeof(scalar) / sizeof(uint64_t),
                                           argument, 56,
                                           0, 0, NULL, NULL);
    free(argument);
    if (kr != KERN_SUCCESS) {
        printf("ERROR: failed to submit command buffers (%s)\n", mach_error_string(kr));
        return -1;
    }
    return 0;
}
