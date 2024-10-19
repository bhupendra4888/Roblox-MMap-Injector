.data
	
.const
	
.code
	CallSyscall PROC
		mov r10,rdx
		mov rax,rcx
		mov rcx,rdx
		mov rdx,r8
		mov r8,r9
		mov r9,[rsp+028h]
		add rsp,8h
		syscall
		sub rsp,8h
		ret
	CallSyscall ENDP
END