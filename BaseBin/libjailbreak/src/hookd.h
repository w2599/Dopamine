#ifndef HOOK_D
#define HOOK_D

#include <mach/mach.h>
#include <stdint.h>
#include <stdbool.h>
#include <xpc/xpc.h>

#define HOOKD_MSG_MAX_SIZE 4096

struct hookd_encoded_hook {
	vm_address_t address;
	vm_size_t dataSize;
	uint8_t data[];
};

struct hookd_encoded_fixup {
	vm_address_t address;
	vm_size_t size;
	bool set_maximum;
	vm_prot_t prot;
};

struct hookd_mach_msg {
	mach_msg_header_t hdr;
	pid_t clientPid;
	task_port_t taskPortInClient;
	uint64_t hooksStartOff; // Hooks at hooksStartOff -> fixupsStartOff in data
	uint64_t fixupsStartOff; // Fixups at fixupsStartOff -> sizeof(msg) in data
	uint8_t data[];
};

struct hookd_mach_msg_reply {
	mach_msg_header_t hdr;
	uint64_t hookResultsCount;
	uint64_t fixupResultsCount;
	uint8_t data[];
};

struct hookd_hook {
	uint64_t address;
	uint8_t *data;
	size_t dataSize;
};

extern int (*hookd_send_msg)(struct hookd_mach_msg *msg, struct hookd_mach_msg_reply *reply);

int hookd_send_requests(task_port_t taskPort, struct hookd_hook *hooks, int hooksCount, int *hookResultsOut, struct hookd_encoded_fixup *fixups, int fixupsCount, int *fixupResultsOut);
kern_return_t hookd_vm_protect(mach_port_t taskPort, vm_address_t address, vm_size_t size, bool set_maximum, vm_prot_t new_protection);
kern_return_t hookd_hook(mach_port_t taskPort, uint64_t address, uint8_t *data, size_t dataSize);

#endif