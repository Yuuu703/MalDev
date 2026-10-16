#include<windows.h>
#pragma comment (lib, "user32.lib")

BOOL __stdcall DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason){
        case DLL_PROCESS_ATTACH:
            MessageBoxW(NULL, L"DLL Injected!", L"Success", MB_ICONEXCLAMATION | MB_OK);
            break;
        case DLL_PROCESS_DETACH:
            MessageBoxW(NULL, L"DLL Detached!", L"Success", MB_ICONEXCLAMATION | MB_OK);
            break;
    }

    return TRUE;
}


































