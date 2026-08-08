.global _hookd_intercept_syscall
_hookd_intercept_syscall:
	cmp x16, 0xFFFFFFFFFFFFFFF2
	b.ne _hookd_intercept_syscall_not_vm_protect
	b _mach_vm_protect_fixed
_hookd_intercept_syscall_not_vm_protect:
	svc 0x80
	ret

.global _hook_trampoline_template
.global _hook_trampoline_template_call
.global _hook_trampoline_template_jmpback
.global _hook_trampoline_template_end
_hook_trampoline_template:
	stp x29, x30, [sp, #-0x10]!
_hook_trampoline_template_call:
	nop // bl _hookd_intercept_syscall
	ldp x29, x30, [sp], 0x10
_hook_trampoline_template_jmpback:
	nop // b <orig>
_hook_trampoline_template_end:

.global ___bsdthread_create_reimpl
___bsdthread_create_reimpl:
	MOV             X16, #0x168
	SVC             0x80
	B.CC            err_ret
#ifdef __arm64e__
	PACIBSP
#endif
	STP             X29, X30, [SP,#-0x10]!
	MOV             X29, SP
	BL              _cerror_nocancel
	MOV             SP, X29
	LDP             X29, X30, [SP],#0x10
#ifdef __arm64e__
	RETAB
#endif
err_ret:
	RET