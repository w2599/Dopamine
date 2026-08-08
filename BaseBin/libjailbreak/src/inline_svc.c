#include "inline_svc.h"

#include <errno.h>

int waitpid_inline(pid_t pid, int *result, int flags)
{
	if ((flags & 0xFFFFFFEC) != 0) {
		errno = 22;
		return -1;
	}
	else {
		return wait4_inline(pid, result, flags, 0);
	}
}

pid_t getpid_inline(void)
{
	extern pid_t getpid_svc_inline(void);
	extern int _current_pid;
	if (_current_pid <= 0) {
		_current_pid = getpid_svc_inline();
	}
	return _current_pid;
}