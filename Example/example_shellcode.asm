BITS 64

	section .text
global hook_func_A:function
extern trampoline

hook_func_A:
	call start_hook
db 'this function has been hooked',0
start_hook:
	pop		rax			; get address of the string
	mov		rdi, rax
	mov		rsi, 0xdeadbeef
	call	trampoline
