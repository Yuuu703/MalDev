#include<injection.h>

PVOID GetNtDllBaseAddress(){
    // 1. Get the PEB address: On x64, PEB loacates at GS:[0x60]
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    
    // 2. Get the module list from the PEB: The Ldr field of the PEB points to the PEB_LDR_DATA structure, which contains the InMemoryOrderModuleList
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    
    // 3. Browse the InMemoryOrderModuleList to find the base address of ntdll.dll 
    // The InMemoryOrderModuleList is a doubly linked list of LDR_DATA_TABLE_ENTRY structures, each representing a loaded module. 
    // The first entry (Flink) is always the executable (.exe) of our process, and the second entry (Flink of the first entry) is always ntdll.dll, and the third entry (Flink of the second entry) is always kernel32.dll.
    PLDR_DATA_TABLE_ENTRY pExeEntry = (PLDR_DATA_TABLE_ENTRY)pLdr->InMemoryOrderModuleList.Flink;
    
    // 4. Get the base address of ntdll.dll from the second entry in the list
    PLDR_DATA_TABLE_ENTRY pNtdllEntry = (PLDR_DATA_TABLE_ENTRY)pExeEntry->InMemoryOrderLinks.Flink;
    
    // 5. Return the base address of ntdll.dll
    return pNtdllEntry->DllBase;
}

PVOID GetFunctionByHash(HMODULE hModule, LPCSTR lpProcName){

}

BOOL Injection(_In_ CONST HANDLE PID, _In_ LPCWSTR DLLPath, _In_ CONST SIZE_T PathSize){
    NTSTATUS status_open = 0;
    NTSTATUS status_thread = 0;
    SIZE_T bytewritten = 0;
    LPVOID addr = NULL;
    BOOL write = FALSE;
    HANDLE open = NULL;
    HANDLE ntdll = NULL;
    HANDLE thread = NULL;
    _OBJECT_ATTRIBUTES objattr = { sizeof(objattr) , NULL};
    _CLIENT_ID clientid = { PID, NULL };





CLEAN_UP:
}