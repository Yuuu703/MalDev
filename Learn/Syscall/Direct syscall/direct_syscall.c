#include "direct_syscall.h"

// Hash function (DJB2) - tái sử dụng từ bài trước
DWORD HashStringA(const char* str) {
    DWORD hash = 5381;
    unsigned char c;
    while ((c = (unsigned char)*str++)) {
        if (c >= 'A' && c <= 'Z') c += 32;
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

// Get syscall number từ ntdll.dll
// Cách 1: Parse PE header và tìm pattern "mov r10, rcx; mov eax, <syscall_number>"
BOOL GetSyscallNumber(LPCSTR FunctionName, PDWORD pSyscallNumber) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    // Resolve function address
    FARPROC pFunc = GetProcAddress(hNtdll, FunctionName);
    if (!pFunc) return FALSE;

    // Parse first few bytes to find syscall number
    // Pattern: mov eax, <imm32> (B8 xx xx xx xx)
    PBYTE pBytes = (PBYTE)pFunc;
    for (int i = 0; i < 32; i++) {
        if (pBytes[i] == 0xB8) { // mov eax, imm32
            *pSyscallNumber = *(PDWORD)(pBytes + i + 1);
            return TRUE;
        }
    }

    return FALSE;
}

// Get address of "syscall" instruction trong ntdll.dll
PVOID GetSyscallAddress(LPCSTR FunctionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return NULL;

    FARPROC pFunc = GetProcAddress(hNtdll, FunctionName);
    if (!pFunc) return NULL;

    // Tìm instruction "syscall" (0x0F 0x05) trong function
    PBYTE pBytes = (PBYTE)pFunc;
    for (int i = 0; i < 64; i++) {
        if (pBytes[i] == 0x0F && pBytes[i + 1] == 0x05) {
            return (PVOID)(pBytes + i);
        }
    }

    return NULL;
}

// Get full syscall info
BOOL GetSyscallInfo(LPCSTR FunctionName, PSYSCALL_ENTRY pEntry) {
    if (!GetSyscallNumber(FunctionName, &pEntry->SyscallNumber)) return FALSE;
    pEntry->SyscallAddress = GetSyscallAddress(FunctionName);
    return (pEntry->SyscallAddress != NULL);
}

// Assembly function để thực thi direct syscall
// Syntax cho MSVC x64
NTSTATUS DirectSyscallInvoke(
    DWORD SyscallNumber,
    PVOID SyscallAddress,
    PVOID Arg1,
    PVOID Arg2,
    PVOID Arg3,
    PVOID Arg4
);

// Wrapper cho NtAllocateVirtualMemory
NTSTATUS DirectSyscallAllocateMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize
) {
    SYSCALL_ENTRY entry;
    if (!GetSyscallInfo("NtAllocateVirtualMemory", &entry)) {
        return STATUS_UNSUCCESSFUL;
    }

    // Call assembly function
    return DirectSyscallInvoke(
        entry.SyscallNumber,
        entry.SyscallAddress,
        ProcessHandle,
        BaseAddress,
        0, // ZeroBits
        RegionSize
    );
}