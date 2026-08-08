#ifndef __INLINE_SVC_H
#define __INLINE_SVC_H

#include <sys/types.h>
#include <sys/wait.h>

pid_t wait4_inline(pid_t pid, int *stat_loc, int options, struct rusage *rusage);
int waitpid_inline(pid_t pid, int *result, int flags);
pid_t getpid_inline(void);

#endif