#include<Windows.h>
#include<tlhelp32.h>
#include<injection.h>

unsigned long find_pid(const char* process_name){
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
            CloseHandle(snapshot);
            return pe.th32ProcessID;
        }
    } while (Process32Next(snapshot, &pe));
    CloseHandle(snapshot);
    return 0;
}

int main(void){
    if (!Injection(find_pid("Notepad.exe"), DLL, sizeof(DLL))){
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}