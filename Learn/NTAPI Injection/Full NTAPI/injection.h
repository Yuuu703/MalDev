#include<windows.h>

#define DLL L"D:\\Mal\\Learn\\ProcessInjection\\DLL Injection\\payload2.dll"
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef struct _UNICODE_STRING
{
    USHORT Length;                                                          //0x0
    USHORT MaximumLength;                                                   //0x2
    PWSTR Buffer;                                                           //0x8
} _UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;                                                           //0x0
    VOID* RootDirectory;                                                    //0x8
    struct _UNICODE_STRING* ObjectName;                                     //0x10
    ULONG Attributes;                                                       //0x18
    VOID* SecurityDescriptor;                                               //0x20
    VOID* SecurityQualityOfService;                                         //0x28
} _OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
    }

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;    
} _CLIENT_ID, *PCLIENT_ID;

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

//NTAPI function pointer typedefs
typedef NTSTATUS(NTAPI* fn_NtOpenProcess)(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
);

typedef NTSTATUS(NTAPI* fn_NtAllocateVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection
);

typedef NTSTATUS(NTAPI* fn_NtWriteVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToWrite,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS(NTAPI* fn_NtCreateThreadEx)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine, // PUSER_THREAD_START_ROUTINE
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
);

typedef NTSTATUS(NTAPI* fn_NtWaitForSingleObject)(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
);

typedef NTSTATUS(NTAPI* fn_NtClose)(
    _In_ _Post_ptr_invalid_ HANDLE Handle
);

typedef NTSTATUS(NTAPI* fn_NtFreeVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ __drv_freesMem(Mem) PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
);

// Get base address of ntddll.dll directly from PEB
typedef struct _PEB_LDR_DATA{
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY{
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase; // <--- this is what we need (Base Address of the module(ntdll.dll))
    PVOID Reserved3[2];
    PUNICODE_STRING FullDllName;
    // ... other fields, but we don't need them for this purpose
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr; // <--- this is what we need (Pointer to the PEB_LDR_DATA structure)
    // ... other fields, but we don't need them for this purpose
} PEB, *PPEB;

/*!
* @brief
* A wrapper function for GetModuleHandleW()
*
* @param lpMoudleName 
* The name of the module to retrieve a handle for
*
* @return
* A handle to the specified module, or NULL if the function fails
*/
HMODULE GetModule(LPCWSTR lpModuleName);

/*!
 * @brief
 *  Injects a target process with the NTAPI
 *  One (1) of the WinAPI functions normally used for a DLL injection is going to be replaced
 *  with its NTAPI function counterpart. In this case, CreateThreadEx -> NtCreateThreadEx
 *
 * @param PID
 *  The PID of the target process
 *
 * @param DLLPath
 *  The path of the specified DLL
 *
 * @param PathSize
 *  The size of the DLLPath parameter
 *
 * @return 
 *  Bool
 */
BOOL Injection(_In_ CONST DWORD PID, _In_ LPCWSTR DLLPath, _In_ CONST SIZE_T PathSize);

