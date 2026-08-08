#ifndef ELLEKIT_HOOKD
#define ELLEKIT_HOOKD

extern uint32_t shcstash[];
extern uint32_t shcstash_end[];

extern uint32_t hook_trampoline_template[];
extern uint32_t hook_trampoline_template_call[];
extern uint32_t hook_trampoline_template_jmpback[];
extern uint32_t hook_trampoline_template_end[];

int apply_hookd_syscall_patches(uint32_t *textPtr, size_t textSize);
void init_hookd_external_support(void);
void hookd_intercept_syscall(void);

#endif