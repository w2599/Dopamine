#include <mach/mach.h>

#include <xpc/xpc.h>
#include <xpc_private.h>
#include <libjailbreak/hookd.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <bsm/libbsm.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// 获取待修改任务的端口引用。
mach_port_t extract_task_port(mach_port_t clientTaskPort, mach_port_t callerPort)
{
	if (callerPort == -1) {
		mach_port_mod_refs(mach_task_self(), clientTaskPort, MACH_PORT_RIGHT_SEND, 1);
		// printf("extract_task_port: Got callerPort=-1, taking clientTaskPort (%d)\n", clientTaskPort); fflush(stdout);
		return clientTaskPort;
	}

	mach_port_t extracted;
	mach_msg_type_name_t right;
	kern_return_t kr = mach_port_extract_right(clientTaskPort, callerPort, MACH_MSG_TYPE_COPY_SEND, &extracted, &right);
	if (kr != KERN_SUCCESS) {
		// printf("extract_task_port: Got clientTaskPort=%d, callerPort=%d, failed extracting: %d\n", clientTaskPort, callerPort, kr); fflush(stdout);
		return MACH_PORT_NULL;
	}

	// printf("extract_task_port: Got clientTaskPort=%d, callerPort=%d, extracted to %d\n", clientTaskPort, callerPort, extracted); fflush(stdout);
	return extracted;
}


// 写入 hook 并恢复代码页权限。
int apply_hook(mach_port_t clientTaskPort, mach_port_t taskPortInClient, vm_address_t vmaddr, const void *data, vm_size_t size)
{
	if (!data || size == 0) return -1;

	mach_port_t taskPort = extract_task_port(clientTaskPort, taskPortInClient);
	if (!MACH_PORT_VALID(taskPort)) {
		// printf("apply_hook: Error, task port %d is invalid\n", taskPort); fflush(stdout);
		return -1;
	}

	// char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
	// pid_t taskPortPid = 0;
	// pid_for_task(taskPort, &taskPortPid);
	// if (proc_pidpath (taskPortPid, pathbuf, sizeof(pathbuf)) <= 0) {
	// 	strlcpy(pathbuf, "<unknown>", sizeof(pathbuf));
	// }
	// printf("Applying hook with size %zu at %#llx in [pid=%d,path=%s]\n", size, vmaddr, taskPortPid, pathbuf);

	kern_return_t kr = vm_protect(taskPort, vmaddr, size, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
	if (kr != KERN_SUCCESS) {
		// printf("Failed to make %lx->%#lx in task %d writable (%d)\n", vmaddr, vmaddr+size, taskPort, kr); fflush(stdout);
		mach_port_mod_refs(mach_task_self(), taskPort, MACH_PORT_RIGHT_SEND, -1);
		return kr;
	}

	kr = vm_write(taskPort, vmaddr, (vm_offset_t)data, (mach_msg_type_number_t)size);
	if (kr != KERN_SUCCESS) {
		// printf("Failed to write data at %#lx in task %d (%d)\n", (vm_offset_t)data, taskPort, kr); fflush(stdout);
	}

	kern_return_t restoreKr = vm_protect(taskPort, vmaddr, size, false, VM_PROT_READ | VM_PROT_EXECUTE);
	if (restoreKr != KERN_SUCCESS) {
		// printf("Failed to make %lx->%#lx in task %d executable (%d)\n", vmaddr, vmaddr+size, taskPort, restoreKr); fflush(stdout);
		mach_port_mod_refs(mach_task_self(), taskPort, MACH_PORT_RIGHT_SEND, -1);
		return restoreKr;
	}

	mach_port_mod_refs(mach_task_self(), taskPort, MACH_PORT_RIGHT_SEND, -1);
	return kr;
}

// 更新目标任务的内存保护。
int apply_fixup(mach_port_t clientTaskPort, mach_port_t taskPortInClient, vm_address_t address, vm_size_t size, bool set_maximum, vm_prot_t prot)
{
	mach_port_t taskPort = extract_task_port(clientTaskPort, taskPortInClient);
	if (!MACH_PORT_VALID(taskPort)) {
		// printf("apply_fixup: Error, task port %d is invalid\n", taskPort); fflush(stdout);
		return -1;
	}

	kern_return_t kr = vm_protect(taskPort, address, size, set_maximum, prot);
	mach_port_mod_refs(mach_task_self(), taskPort, MACH_PORT_RIGHT_SEND, -1);
	return kr;
}

// 完整检查记录边界，使用减法避免长度溢出。
static bool hookd_validate_message(const struct hookd_mach_msg *msg, size_t *hookCountOut, size_t *fixupCountOut)
{
	if (msg->hdr.msgh_size < sizeof(*msg) || msg->hdr.msgh_size > HOOKD_MSG_MAX_SIZE ||
		(msg->hdr.msgh_bits & MACH_MSGH_BITS_COMPLEX)) return false;
	size_t dataSize = msg->hdr.msgh_size - sizeof(*msg);
	if (msg->hooksStartOff > msg->fixupsStartOff || msg->fixupsStartOff > dataSize) return false;
	size_t hooksSize = msg->fixupsStartOff - msg->hooksStartOff;
	size_t fixupsSize = dataSize - msg->fixupsStartOff;
	if (fixupsSize % sizeof(struct hookd_encoded_fixup)) return false;

	size_t hookCount = 0;
	for (size_t offset = 0; offset < hooksSize;) {
		size_t remaining = hooksSize - offset;
		if (remaining < sizeof(struct hookd_encoded_hook)) return false;
		struct hookd_encoded_hook hook;
		memcpy(&hook, &msg->data[msg->hooksStartOff + offset], sizeof(hook));
		if (!hook.dataSize || hook.dataSize > remaining - sizeof(hook) ||
			hook.dataSize > UINTPTR_MAX - hook.address) return false;
		offset += sizeof(hook) + hook.dataSize;
		hookCount++;
	}
	size_t fixupCount = fixupsSize / sizeof(struct hookd_encoded_fixup);
	for (size_t i = 0; i < fixupCount; i++) {
		const uint8_t *record = &msg->data[msg->fixupsStartOff + i * sizeof(struct hookd_encoded_fixup)];
		if (record[offsetof(struct hookd_encoded_fixup, set_maximum)] > 1) return false;
		struct hookd_encoded_fixup fixup;
		memcpy(&fixup, record, sizeof(fixup));
		if (fixup.size > UINTPTR_MAX - fixup.address) return false;
	}
	*hookCountOut = hookCount;
	*fixupCountOut = fixupCount;
	return true;
}

// 校验并一次分配回复，确保错误请求不会部分执行。
static struct hookd_mach_msg_reply *hookd_process_message(const struct hookd_mach_msg *msg)
{
	size_t hookCount = 0, fixupCount = 0;
	if (!hookd_validate_message(msg, &hookCount, &fixupCount)) return NULL;
	size_t replySize = sizeof(struct hookd_mach_msg_reply) + (hookCount + fixupCount) * sizeof(int64_t);
	if (replySize > HOOKD_MSG_MAX_SIZE) return NULL;
	struct hookd_mach_msg_reply *reply = calloc(1, replySize);
	if (!reply) return NULL;
	task_port_t clientTaskPort = MACH_PORT_NULL;
	kern_return_t kr = task_for_pid(mach_task_self(), msg->clientPid, &clientTaskPort);
	if (kr != KERN_SUCCESS || !MACH_PORT_VALID(clientTaskPort)) {
		if (MACH_PORT_VALID(clientTaskPort)) mach_port_deallocate(mach_task_self(), clientTaskPort);
		free(reply);
		return NULL;
	}
	reply->hdr.msgh_size = replySize;
	reply->hookResultsCount = hookCount;
	reply->fixupResultsCount = fixupCount;
	int64_t *results = (int64_t *)reply->data;
	size_t offset = msg->hooksStartOff;
	for (size_t i = 0; i < hookCount; i++) {
		struct hookd_encoded_hook hook;
		memcpy(&hook, &msg->data[offset], sizeof(hook));
		results[i] = apply_hook(clientTaskPort, msg->taskPortInClient, hook.address,
			&msg->data[offset + sizeof(hook)], hook.dataSize);
		offset += sizeof(hook) + hook.dataSize;
	}
	for (size_t i = 0; i < fixupCount; i++) {
		struct hookd_encoded_fixup fixup;
		memcpy(&fixup, &msg->data[msg->fixupsStartOff + i * sizeof(fixup)], sizeof(fixup));
		results[hookCount + i] = apply_fixup(clientTaskPort, msg->taskPortInClient,
			fixup.address, fixup.size, fixup.set_maximum, fixup.prot);
	}
	mach_port_deallocate(mach_task_self(), clientTaskPort);
	return reply;
}

// 接收带审计信息的请求，并释放每次回复及端口权利。
void server_loop(mach_port_t port)
{
	union {
		uint64_t alignment;
		uint8_t bytes[HOOKD_MSG_MAX_SIZE + MAX_TRAILER_SIZE];
	} buffer;
	while (true) {
		struct hookd_mach_msg *msg = (struct hookd_mach_msg *)buffer.bytes;
		kern_return_t kr = mach_msg(&msg->hdr, MACH_RCV_MSG |
			MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
			MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
			0, sizeof(buffer), port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
		if (kr != KERN_SUCCESS) continue;
		if (msg->hdr.msgh_size < sizeof(*msg) || msg->hdr.msgh_size > HOOKD_MSG_MAX_SIZE ||
			(msg->hdr.msgh_bits & MACH_MSGH_BITS_COMPLEX)) goto deny;
		if (!MACH_PORT_VALID(msg->hdr.msgh_remote_port)) goto deny;
		size_t trailerOffset = round_msg(msg->hdr.msgh_size);
		if (sizeof(mach_msg_audit_trailer_t) > sizeof(buffer) - trailerOffset) goto deny;
		mach_msg_audit_trailer_t *trailer = (void *)(buffer.bytes + trailerOffset);
		if (trailer->msgh_trailer_type != MACH_MSG_TRAILER_FORMAT_0 ||
			trailer->msgh_trailer_size < sizeof(*trailer) ||
			trailer->msgh_trailer_size > sizeof(buffer) - trailerOffset) goto deny;
#if !HOOKD_SKIP_CALLER_VERIFICATION
		if (audit_token_to_pid(trailer->msgh_audit) != 1) goto deny;
#endif
		struct hookd_mach_msg_reply *reply = hookd_process_message(msg);
		if (!reply) goto deny;
		mach_msg_type_name_t disposition = MACH_MSGH_BITS_REMOTE(msg->hdr.msgh_bits);
		if (disposition == MACH_MSG_TYPE_COPY_SEND) disposition = MACH_MSG_TYPE_MOVE_SEND;
		reply->hdr.msgh_bits = MACH_MSGH_BITS(disposition, 0);
		reply->hdr.msgh_remote_port = msg->hdr.msgh_remote_port;
		reply->hdr.msgh_id = msg->hdr.msgh_id + 100;
		// 回复接管端口，发送失败也只释放一次。
		msg->hdr.msgh_remote_port = MACH_PORT_NULL;
		msg->hdr.msgh_bits &= ~MACH_MSGH_BITS_REMOTE_MASK;
		kr = mach_msg(&reply->hdr, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
			reply->hdr.msgh_size, 0, MACH_PORT_NULL, 1000, MACH_PORT_NULL);
		if (kr != KERN_SUCCESS) mach_msg_destroy(&reply->hdr);
		free(reply);

deny:
		mach_msg_destroy(&msg->hdr);
	}
}

// 注册服务端口并向启动方发送带发送权的 checkin。
int main(int argc, char **argv)
{
	mach_port_t serverPort = MACH_PORT_NULL;
	kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &serverPort);
	if (kr != KERN_SUCCESS) return kr;
	mach_port_t *registeredPorts = NULL;
	mach_msg_type_number_t registeredPortsCount = 0;
	kr = mach_ports_lookup(mach_task_self(), &registeredPorts, &registeredPortsCount);
	if (kr == KERN_SUCCESS && (registeredPortsCount < 3 || !MACH_PORT_VALID(registeredPorts[2]))) kr = KERN_INVALID_ARGUMENT;
	if (kr == KERN_SUCCESS) {
		mach_msg_header_t hdr = { 0 };
		hdr.msgh_size = sizeof(hdr);
		hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND);
		hdr.msgh_remote_port = registeredPorts[2];
		hdr.msgh_local_port = serverPort;
		hdr.msgh_id = 0x40000000;
		kr = mach_msg(&hdr, MACH_SEND_MSG | MACH_SEND_TIMEOUT, hdr.msgh_size, 0,
			MACH_PORT_NULL, 5000, MACH_PORT_NULL);
	}
	if (registeredPorts) {
		for (mach_msg_type_number_t i = 0; i < registeredPortsCount; i++) {
			if (MACH_PORT_VALID(registeredPorts[i])) mach_port_deallocate(mach_task_self(), registeredPorts[i]);
		}
		vm_deallocate(mach_task_self(), (vm_address_t)registeredPorts, sizeof(mach_port_t) * registeredPortsCount);
	}
	if (kr == KERN_SUCCESS) server_loop(serverPort);
	mach_port_destroy(mach_task_self(), serverPort);
	return kr;
}
