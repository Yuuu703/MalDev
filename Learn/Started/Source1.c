#include <windows.h>

int main(void) {
    MessageBoxW(
        NULL,
        L"Hello, World!",
        L"Hello",
        MB_YESNOCANCEL | MB_ICONEXCLAMATION
    );
    return EXIT_SUCCESS;
}
