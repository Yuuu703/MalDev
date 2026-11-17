.code

; NTSTATUS DirectSyscallInvoke(
;   DWORD SyscallNumber,    ; RCX
;   PVOID SyscallAddress,   ; RDX
;   PVOID Arg1,             ; R8
;   PVOID Arg2,             ; R9
;   PVOID Arg3,             ; [RSP + 28h]
;   PVOID Arg4              ; [RSP + 30h]
; )

DirectSyscallInvoke PROC
    ; BƯỚC 1: Lưu lại SyscallAddress từ RDX sang R11 để tránh bị ghi đè
    mov r11, rdx

    ; Set syscall number vào EAX
    mov eax, ecx
    
    ; Set arguments vào registers theo calling convention
    mov r10, r8      ; Arg1 -> R10 (thay cho RCX)
    mov rdx, r9      ; Arg2 -> RDX
    mov r8, [rsp+28h] ; Arg3 -> R8
    mov r9, [rsp+30h] ; Arg4 -> R9
    
    ; Jump đến instruction "syscall" trong ntdll.dll
    jmp r11
    
    ; Không bao giờ đến đây
    ret
DirectSyscallInvoke ENDP

END