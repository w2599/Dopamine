#include "hookd_provider.h"

#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/hookd.h>
#include <libjailbreak/inline_svc.h>
#include <spawn.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <bsm/libbsm.h>

#define HOOKD_CHECKIN_TIMEOUT 5000
#define HOOKD_SEND_TIMEOUT 1000
#define HOOKD_REPLY_TIMEOUT 5000

pid_t gHookdPid = -1;
mach_port_t gHookdPort = MACH_PORT_NULL;
static pthread_mutex_t gHookdLock = PTHREAD_MUTEX_INITIALIZER;
static atomic_bool gHookdStopping = false;
int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t * __restrict attr, mach_port_t portarray[], uint32_t count);

// 仅对仍属于本进程的子进程发信号，保留未回收的 PID。
static void hookd_stop(void)
{
	if (MACH_PORT_VALID(gHookdPort)) mach_port_deallocate(mach_task_self(), gHookdPort);
	gHookdPort = MACH_PORT_NULL;
	if (gHookdPid > 0) {
		int status = 0;
		pid_t waited = waitpid_inline(gHookdPid, &status, WNOHANG);
		if (waited == 0) {
			kill(gHookdPid, SIGKILL);
			waited = waitpid_inline(gHookdPid, &status, WNOHANG);
		}
		if (waited == gHookdPid || (waited == -1 && errno == ECHILD)) gHookdPid = -1;
	}
}

// 请求退出时立即尝试停止；忙碌请求在解锁后补做。
static void hookd_stop_pending(void)
{
	if (!atomic_load_explicit(&gHookdStopping, memory_order_acquire)) return;
	if (pthread_mutex_trylock(&gHookdLock) != 0) return;
	hookd_stop();
	pthread_mutex_unlock(&gHookdLock);
}

// 启动服务并校验审计身份，接收缓冲包含完整 trailer。
int hookd_start(pid_t *pid, mach_port_t *machPort)
{
	*pid = -1;
	*machPort = MACH_PORT_NULL;
	mach_port_t checkinPort = MACH_PORT_NULL;
	int result = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &checkinPort);
	if (result != KERN_SUCCESS) return result;
	result = mach_port_insert_right(mach_task_self(), checkinPort, checkinPort, MACH_MSG_TYPE_MAKE_SEND);
	if (result != KERN_SUCCESS) goto out;

	posix_spawnattr_t attr;
	result = posix_spawnattr_init(&attr);
	if (result != 0) goto out;
	result = posix_spawnattr_set_registered_ports_np(&attr,
		(mach_port_t[]){MACH_PORT_NULL, MACH_PORT_NULL, checkinPort}, 3);
	if (result == 0) {
		const char *path = JBROOT_PATH("/basebin/hookd");
		const char *envp[] = { "_SafeMode=1", NULL };
		pid_t childPid = -1;
		result = posix_spawn(&childPid, path, NULL, &attr, (char *[]){ (char *)path, NULL }, (char *const *)envp);
		if (result == 0) {
			if (childPid <= 0) result = ECHILD;
			else *pid = childPid;
		}
	}
	posix_spawnattr_destroy(&attr);
	if (result != 0) goto out;

	union {
		uint64_t alignment;
		uint8_t bytes[sizeof(mach_msg_header_t) + MAX_TRAILER_SIZE];
	} buffer = { 0 };
	mach_msg_header_t *hdr = (void *)buffer.bytes;
	result = mach_msg(hdr, MACH_RCV_MSG | MACH_RCV_TIMEOUT |
		MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
		MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
		0, sizeof(buffer), checkinPort, HOOKD_CHECKIN_TIMEOUT, MACH_PORT_NULL);
	if (result != KERN_SUCCESS) goto out;

	result = EPROTO;
	if (hdr->msgh_size == sizeof(*hdr) && !(hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX) &&
		hdr->msgh_id == 0x40000000 && MACH_PORT_VALID(hdr->msgh_remote_port) &&
		MACH_MSGH_BITS_REMOTE(hdr->msgh_bits) == MACH_MSG_TYPE_PORT_SEND) {
		mach_msg_audit_trailer_t *trailer = (void *)(buffer.bytes + round_msg(hdr->msgh_size));
		if (trailer->msgh_trailer_type == MACH_MSG_TRAILER_FORMAT_0 &&
			trailer->msgh_trailer_size >= sizeof(*trailer) &&
			trailer->msgh_trailer_size <= sizeof(buffer) - round_msg(hdr->msgh_size) &&
			audit_token_to_pid(trailer->msgh_audit) == *pid) {
			*machPort = hdr->msgh_remote_port;
			hdr->msgh_remote_port = MACH_PORT_NULL;
			hdr->msgh_bits &= ~MACH_MSGH_BITS_REMOTE_MASK;
			result = 0;
		}
	}
	mach_msg_destroy(hdr);
out:
	// 同时销毁 checkin 接收权及本地发送权。
	mach_port_destroy(mach_task_self(), checkinPort);
	return result;
}

// 有界转发；独立回复端口避免超时后接收上一次的回复。
static int launchd_hookd_send_msg(struct hookd_mach_msg *msg, struct hookd_mach_msg_reply *reply)
{
	if (!msg || !reply || msg->hdr.msgh_size < sizeof(*msg) ||
		msg->hdr.msgh_size > HOOKD_MSG_MAX_SIZE || reply->hdr.msgh_size < sizeof(*reply)) return EINVAL;
	if (atomic_load_explicit(&gHookdStopping, memory_order_acquire)) return ECANCELED;
	int result = pthread_mutex_trylock(&gHookdLock);
	if (result != 0) return result;
	mach_port_t replyPort = MACH_PORT_NULL;
	if (atomic_load_explicit(&gHookdStopping, memory_order_acquire)) {
		result = ECANCELED;
		goto out;
	}
	mach_msg_size_t replyCapacity = reply->hdr.msgh_size;
	if (replyCapacity > HOOKD_MSG_MAX_SIZE + MAX_TRAILER_SIZE) replyCapacity = HOOKD_MSG_MAX_SIZE + MAX_TRAILER_SIZE;

	if (gHookdPid > 0) {
		int status = 0;
		pid_t waited = waitpid_inline(gHookdPid, &status, WNOHANG);
		if (waited == gHookdPid || (waited == -1 && errno == ECHILD)) {
			gHookdPid = -1;
			if (MACH_PORT_VALID(gHookdPort)) mach_port_deallocate(mach_task_self(), gHookdPort);
			gHookdPort = MACH_PORT_NULL;
		}
		else if (waited != 0) {
			result = errno;
			goto out;
		}
		else if (!MACH_PORT_VALID(gHookdPort)) {
			result = EAGAIN;
			goto out;
		}
	}
	if (gHookdPid == -1) {
		result = hookd_start(&gHookdPid, &gHookdPort);
		if (result != 0) goto failed;
	}
	result = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &replyPort);
	if (result != KERN_SUCCESS) goto out;
	msg->hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
	msg->hdr.msgh_remote_port = gHookdPort;
	msg->hdr.msgh_local_port = replyPort;
	msg->hdr.msgh_voucher_port = MACH_PORT_NULL;
	msg->hdr.msgh_id = 0x40000000;
	result = mach_msg(&msg->hdr, MACH_SEND_MSG | MACH_SEND_TIMEOUT, msg->hdr.msgh_size,
		0, MACH_PORT_NULL, HOOKD_SEND_TIMEOUT, MACH_PORT_NULL);
	if (result != KERN_SUCCESS) goto failed;
	result = mach_msg(&reply->hdr, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, replyCapacity,
		replyPort, HOOKD_REPLY_TIMEOUT, MACH_PORT_NULL);
	if (result != KERN_SUCCESS) goto failed;

	bool valid = !(reply->hdr.msgh_bits & MACH_MSGH_BITS_COMPLEX) &&
		reply->hdr.msgh_id == msg->hdr.msgh_id + 100 && reply->hdr.msgh_size >= sizeof(*reply) &&
		reply->hdr.msgh_size <= HOOKD_MSG_MAX_SIZE && reply->hdr.msgh_size <= replyCapacity;
	if (valid) {
		size_t slots = (reply->hdr.msgh_size - sizeof(*reply)) / sizeof(int64_t);
		valid = (reply->hdr.msgh_size - sizeof(*reply)) % sizeof(int64_t) == 0 &&
			reply->hookResultsCount <= slots && reply->fixupResultsCount == slots - reply->hookResultsCount;
	}
	mach_msg_destroy(&reply->hdr);
	if (!valid) {
		result = EPROTO;
		goto failed;
	}
	goto out;
failed:
	hookd_stop();
out:
	if (MACH_PORT_VALID(replyPort)) mach_port_destroy(mach_task_self(), replyPort);
	pthread_mutex_unlock(&gHookdLock);
	// 必须在解锁后读取，防止 teardown 的 trylock 与退出窗口互相错过。
	hookd_stop_pending();
	return result;
}

// 安装 launchd 内的转发入口。
void hookd_provider_init(void)
{
	atomic_store_explicit(&gHookdStopping, false, memory_order_release);
	hookd_send_msg = launchd_hookd_send_msg;
}

// 停止服务且不在 launchd 中无界等待退出。
void hookd_provider_teardown(void)
{
	atomic_store_explicit(&gHookdStopping, true, memory_order_release);
	hookd_send_msg = NULL;
	hookd_stop_pending();
}
