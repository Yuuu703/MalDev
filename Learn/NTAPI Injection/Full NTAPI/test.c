#include <windows.h>
#include <stdio.h>
DWORD HashStringA_Djb2(const char* str){
    DWORD hash = 5381;
    unsigned char c;
    while ((c = (unsigned char)*str++)) { 
        if (c >= 'A' && c <= 'Z') c += 32; // Convert uppercase to lowercase
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash;
}
int main() {
    printf("Hash ntopenprocess: 0x%x\n", HashStringA_Djb2("ntopenprocess"));
    printf("Hash ntallocatevirtualmemory: 0x%x\n", HashStringA_Djb2("ntallocatevirtualmemory"));
    printf("Hash ntwritevirtualmemory: 0x%x\n", HashStringA_Djb2("ntwritevirtualmemory"));
    printf("Hash ntcreatethreadex: 0x%x\n", HashStringA_Djb2("ntcreatethreadex"));
    printf("Hash ntwaitforsingleobject: 0x%x\n", HashStringA_Djb2("ntwaitforsingleobject"));
    printf("Hash ntclose: 0x%x\n", HashStringA_Djb2("ntclose"));
    printf("Hash ntfreevirtualmemory: 0x%x\n", HashStringA_Djb2("ntfreevirtualmemory"));
    printf("Hash ldrloaddll: 0x%x\n", HashStringA_Djb2("ldrloaddll"));
    printf("Hash ntquerysysteminformation: 0x%x\n", HashStringA_Djb2("ntquerysysteminformation"));
    return 0;
}
