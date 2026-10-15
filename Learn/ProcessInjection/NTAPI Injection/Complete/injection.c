#include<injection.h>

HMODULE GetModule( LPCWSTR lpModuleName){
    HMODULE hModule = NULL;
    if ( lpModuleName == NULL){
        return NULL;
    }
    hModule = GetModuleHandleW(lpModuleName);
    if ( hModule == NULL){
        printf("[-] GetModuleHandleW failed: %d\n", GetLastError());
        return NULL;
    }
    return hModule;
}

BOOL Injection(_In_ CONST HANDLE PID, _In_ LPCWSTR DLLPath, _In_ CONST SIZE_T PathSize){
    NTSTATUS status_open = 0;
    NTSTATUS status_thread = 0;
    SIZE_T bytewritten = 0;
    LPVOID addr = NULL;
    BOOL write = FALSE;
    LPVOID loadlib = NULL;
    HANDLE open = NULL;
    HANDLE kernel32dll = NULL;
    HANDLE ntdll = NULL;
    HANDLE thread = NULL;

    _OBJECT_ATTRIBUTES objattr = { sizeof(objattr) , NULL};

    ntdll = GetModule(L"ntdll.dll");
    kernel32dll = GetModule(L"kernel32.dll");

    fn_NtOpenProcess p_OpenProcess = (fn_NtOpenProcess)GetProcAddress(ntdll, "NtOpenProcess");
    fn_NtCreateThreadEx p_NtCreateThreadEx = (fn_NtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
    fn_NtAllocateVirtualMemory p_NtAllocateVirtualMemory = (fn_NtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    fn_NtWriteVirtualMemory p_NtWriteVirtualMemory = (fn_NtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");

    status_open = p_OpenProcess(&open, PROCESS_ALL_ACCESS, &objattr, PID);
    
    
    loadlib = GetProcAddress(kernel32dll, "LoadLibraryW");
    status_thread = p_NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, &objattr, open, loadlib, addr, FALSE, 0, 0, 0, NULL);
    WaitForSingleObject(thread, INFINITE);

CLEAN_UP:
    if (addr){
        VirtualFreeEx(open, addr, 0, MEM_RELEASE);
    }
    if (open){
        CloseHandle(open);
    }
    if (thread){
        CloseHandle(thread);
    }
    return TRUE;
}