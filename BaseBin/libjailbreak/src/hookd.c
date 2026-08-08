#include "hookd.h"

#include "libjailbreak.h"
#include <spawn.h>
#include <xpc_private.h>
#include "inline_svc.h"

#include "jbclient_mach.h"
int (*hookd_send_msg)(struct hookd_mach_msg *msg, struct hookd_mach_msg_reply *reply) = jbclient_mach_hookd_send_msg;

size_t hookd_sizeof_encoded_hook(struct hookd_hook *hook)
{
	return sizeof(struct hookd_encoded_hook) + hook->dataSize;;
}

int hook_encode_hook(struct hookd_encoded_hook *encodedHook, struct hookd_hook *hook)
{
	encodedHook->address = hook->address;
	encodedHook->dataSize = hook->dataSize;
	memcpy(&encodedHook->data[0], hook->data, hook->dataSize);
	return 0;
}

int hookd_encode_msg(struct hookd_mach_msg *msg, int clientPid, task_port_t taskPort, struct hookd_hook *hooks, int hooksCount, struct hookd_encoded_fixup *fixups, int fixupsCount)
{
	if (!msg) return -1;

	size_t msgSize = sizeof(struct hookd_mach_msg);

	size_t hooksSize = 0;
	for (int i = 0; i < hooksCount; i++) {
		hooksSize += hookd_sizeof_encoded_hook(&hooks[i]);
	}
	msgSize += hooksSize;

	size_t fixupsSize = sizeof(struct hookd_encoded_fixup) * fixupsCount;
	msgSize += fixupsSize;

	if (msgSize > HOOKD_MSG_MAX_SIZE) return -1;

	msg->hdr.msgh_size = msgSize;

	msg->clientPid = clientPid;
	msg->taskPortInClient = taskPort == mach_task_self() ? -1 : taskPort;

	msg->hooksStartOff  = 0;
	msg->fixupsStartOff = hooksSize;

	uint64_t off = msg->hooksStartOff;
	for (int i = 0; i < hooksCount && off < msg->fixupsStartOff; i++) {
		size_t hookSize = hookd_sizeof_encoded_hook(&hooks[i]);
		hook_encode_hook((struct hookd_encoded_hook *)&msg->data[off], &hooks[i]);
		off += hookSize;
	}

	memcpy(&msg->data[msg->fixupsStartOff], fixups, fixupsCount * sizeof(struct hookd_encoded_fixup));

	return 0;
}

int hookd_decode_reply(struct hookd_mach_msg_reply *reply, int *hookResultsOut, int *fixupResultsOut)
{
	if (reply->hdr.msgh_size < sizeof(struct hookd_mach_msg_reply)) return -1;
	if (reply->hdr.msgh_size != (sizeof(struct hookd_mach_msg_reply) + reply->hookResultsCount * sizeof(int64_t) + reply->fixupResultsCount * sizeof(int64_t))) return -1;

	int64_t *hookResults  = (int64_t *)&reply->data[0];
	int64_t *fixupResults = (int64_t *)&reply->data[reply->hookResultsCount * sizeof(int64_t)];

	for (int i = 0; i < reply->hookResultsCount; i++) {
		hookResultsOut[i] = (int)hookResults[i];
	}

	for (int i = 0; i < reply->fixupResultsCount; i++) {
		fixupResultsOut[i] = (int)fixupResults[i];
	}

	return 0;
}

int hookd_send_requests(task_port_t taskPort, struct hookd_hook *hooks, int hooksCount, int *hookResultsOut, struct hookd_encoded_fixup *fixups, int fixupsCount, int *fixupResultsOut)
{
	if (!hookd_send_msg) return -1;

	int r = 0;

	uint8_t msgBuf[HOOKD_MSG_MAX_SIZE];
	memset(msgBuf, 0, HOOKD_MSG_MAX_SIZE);
	struct hookd_mach_msg *msg = (struct hookd_mach_msg *)msgBuf;
	r = hookd_encode_msg(msg, getpid_inline(), taskPort, hooks, hooksCount, fixups, fixupsCount);
	if (r != 0) return r;

	uint8_t replyBuf[HOOKD_MSG_MAX_SIZE + MAX_TRAILER_SIZE];
	memset(replyBuf, 0, HOOKD_MSG_MAX_SIZE + MAX_TRAILER_SIZE);
	struct hookd_mach_msg_reply *reply = (struct hookd_mach_msg_reply *)replyBuf;
	reply->hdr.msgh_size = HOOKD_MSG_MAX_SIZE + MAX_TRAILER_SIZE;
	r = hookd_send_msg(msg, reply);
	if (r != 0) return r;

	if (hookd_decode_reply(reply, hookResultsOut, fixupResultsOut) != 0) return -44;

	return 0;
}

kern_return_t hookd_vm_protect(mach_port_t taskPort, vm_address_t address, vm_size_t size, bool set_maximum, vm_prot_t new_protection)
{
	struct hookd_encoded_fixup fixup;
	fixup.address = address;
	fixup.size = size;
	fixup.set_maximum = set_maximum;
	fixup.prot = new_protection;

	int result = 0;
	int ret = hookd_send_requests(taskPort, NULL, 0, NULL, &fixup, 1, &result);
	if (ret != 0) return ret;
	return result;
}

kern_return_t hookd_hook(mach_port_t taskPort, uint64_t address, uint8_t *data, size_t dataSize)
{
	struct hookd_hook hook;
	hook.address = address;
	hook.data = data;
	hook.dataSize = dataSize;

	int result = 0;
	int ret = hookd_send_requests(taskPort, &hook, 1, &result, NULL, 0, NULL);
	if (ret != 0) return ret;
	return result;
}
