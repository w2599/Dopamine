.macro DEF_SYSCALL name, num, err_func
.global \name
\name\():
	mov x16, #\num
	svc 0x80
	b.cc \name\()_done
#ifdef __arm64e__
	pacibsp
#endif
	stp x29, x30, [SP, #-0x10]!
	mov x29, sp
	bl \err_func
	mov sp, x29
	ldp x29, x30, [sp], 0x10
#ifdef __arm64e__
	retab
#endif
\name\()_done:
	ret
.endm

DEF_SYSCALL _ptrace_inline,        0x1a, _cerror
DEF_SYSCALL ___execve_inline,      0x3b, _cerror_nocancel
DEF_SYSCALL ___posix_spawn_inline, 0xf4, _cerror