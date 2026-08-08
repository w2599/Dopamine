#include "hookd_provider.h"

#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/hookd.h>
#include <libjailbreak/inline_svc.h>
#include <spawn.h>
#include <signal.h>
#include <errno.h>

pid_t gHookdPid = -1;
mach_port_t gHookdPort = MACH_PORT_NULL;
int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t * __restrict attr, mach_port_t portarray[], uint32_t count);

int hookd_start(pid_t *pid, mach_port_t *machPort)
{
	mach_port_t checkinPort = MACH_PORT_NULL;
	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &checkinPort);
	mach_port_insert_right(mach_task_self(), checkinPort, checkinPort, MACH_MSG_TYPE_MAKE_SEND);

	posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){MACH_PORT_NULL, MACH_PORT_NULL, checkinPort}, 3);

	const char *envp[] = {
		"_SafeMode=1",
		NULL,
	};

	const char *path = JBROOT_PATH("/basebin/hookd");
	int r = posix_spawn(pid, path, NULL, &attr, (char *[]){ (char *)path, NULL }, (char *const *)envp);
	if (r != 0) {
		return r;
	}

	mach_msg_header_t hdr = { 0 };
	hdr.msgh_size = sizeof(hdr) + MAX_TRAILER_SIZE;
	kern_return_t kr = mach_msg(&hdr, MACH_RCV_MSG, 0, hdr.msgh_size, checkinPort, 0, 0);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	gHookdPort = hdr.msgh_remote_port;
	mach_port_mod_refs(mach_task_self(), gHookdPort, MACH_PORT_RIGHT_SEND, 1);

	mach_msg_destroy(&hdr);
	mach_port_deallocate(mach_task_self(), checkinPort);

	return 0;
}

static int launchd_hookd_send_msg(struct hookd_mach_msg *msg, struct hookd_mach_msg_reply *reply)
{
	int wpr = -1;
	if (gHookdPid != -1) {
		int status = 0;
		// Call waitpid as inline syscall to prevent crashes when something tries to hook something close to wait4
		wpr = waitpid_inline(gHookdPid, &status, WNOHANG);
	}	

	if (wpr != 0) {
		int sr = hookd_start(&gHookdPid, &gHookdPort);
		if (sr != 0) return sr;
	}

	mach_port_t replyPort = mig_get_reply_port();

	msg->hdr.msgh_bits        |= MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
	msg->hdr.msgh_remote_port  = gHookdPort;
	msg->hdr.msgh_local_port   = replyPort;
	msg->hdr.msgh_voucher_port = 0;
	msg->hdr.msgh_id           = 0x40000000;

	kern_return_t kr = mach_msg(&msg->hdr, MACH_SEND_MSG, msg->hdr.msgh_size, 0, 0, 0, 0);
	if (kr != KERN_SUCCESS) return kr;
	
	kr = mach_msg(&reply->hdr, MACH_RCV_MSG, 0, reply->hdr.msgh_size, replyPort, 0, 0);
	if (kr != KERN_SUCCESS) return kr;

	mach_msg_destroy(&reply->hdr);
	return 0;
}

void hookd_provider_init(void)
{
	hookd_send_msg = launchd_hookd_send_msg;
}

void hookd_provider_teardown(void)
{
	hookd_send_msg = NULL;
	if (gHookdPid != -1) {
		int status = 0;
		if (waitpid(gHookdPid, &status, WNOHANG) == 0) {
			kill(gHookdPid, SIGKILL);
			cmd_wait_for_exit(gHookdPid);
		}
	}
}