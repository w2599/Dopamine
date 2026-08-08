int ptrace_inline(int request, pid_t pid, caddr_t addr, int data);
int __execve_inline(const char *path, char *const argv[], char *const envp[]);
int __posix_spawn_inline(pid_t *restrict pid, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char * const envp[restrict]);

