
.data
    
.const

.code
    Capture PROC
        cpt:
        jmp cpt
    Capture ENDP

    GetCurrentTID PROC
        mov rax, qword ptr gs:[030h]
        mov eax, dword ptr [rax + 048h]
        ret
    GetCurrentTID ENDP

    NtQueryVirtualMemoryInline PROC
        mov r10,rcx
        mov eax,023h
        syscall
        ret
    NtQueryVirtualMemoryInline ENDP
    NtContuneInline PROC
        mov r10,rcx
        mov eax,043h
        syscall
        ret
    NtContuneInline ENDP
    NtProtectVirtualMemoryInline PROC
        mov r10,rcx
        mov eax,050h
        syscall
        ret
    NtProtectVirtualMemoryInline ENDP
END