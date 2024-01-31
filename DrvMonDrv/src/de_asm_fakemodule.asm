.code

extern dispatcherFunc:proc

asm_func_log proc
	push rsp
	push r15
	push r14
	push r13
	push r12
	push r11
	push r10
	push r9
	push r8
	push rdi
	push rsi
	push rbp
	push rbx
	push rdx
	push rcx
	push rax
	
	mov rcx,rsp
	sub rsp,0100h
	call dispatcherFunc
	add rsp,0100h

	pop rax
	pop rcx
	pop rdx
	pop rbx
	pop rbp
	pop rsi
	pop rdi
	pop r8
	pop r9
	pop r10
	pop r11
	pop r12
	pop r13
	pop r14
	pop r15
	pop rsp
	ret
	

asm_func_log endp
end