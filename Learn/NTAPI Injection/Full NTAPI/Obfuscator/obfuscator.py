#!/usr/bin/env python3

import re
import random
import string
from pathlib import Path
from typing import Set, Dict, Tuple

class CObfuscator:
    def __init__(self):
        self.whitelist = {
            # C/C++ keywords
            'int', 'char', 'void', 'float', 'double', 'long', 'short', 'unsigned', 'signed',
            'const', 'static', 'extern', 'volatile', 'inline', 'struct', 'union', 'enum',
            'typedef', 'sizeof', 'return', 'if', 'else', 'for', 'while', 'do', 'switch',
            'case', 'break', 'continue', 'default', 'goto', 'NULL', 'TRUE', 'FALSE',
            'BOOL', 'BYTE', 'WORD', 'DWORD', 'ULONG', 'USHORT', 'PVOID', 'PHANDLE',
            'HANDLE', 'NTSTATUS', 'ACCESS_MASK', 'SIZE_T', 'PSIZE_T', 'ULONG_PTR',
            'PWSTR', 'PCWSTR', 'LPVOID', 'LPCWSTR', 'PBYTE', 'PDWORD', 'PWORD',
            'LIST_ENTRY', 'UNICODE_STRING', 'OBJECT_ATTRIBUTES', 'CLIENT_ID',
            'PEB', 'PEB_LDR_DATA', 'LDR_DATA_TABLE_ENTRY', 'IMAGE_DOS_HEADER',
            'IMAGE_NT_HEADERS', 'IMAGE_EXPORT_DIRECTORY', 'IMAGE_DATA_DIRECTORY',
            'NTSTATUS', 'NTAPI', 'IN', 'OUT', 'IN_OPT', 'OUT_OPT', 'INOUT',
            'MEM_COMMIT', 'MEM_RESERVE', 'MEM_RELEASE', 'PAGE_READWRITE', 'PAGE_EXECUTE_READWRITE',
            'PROCESS_ALL_ACCESS', 'THREAD_ALL_ACCESS', 'STATUS_SUCCESS',
            'IMAGE_DOS_SIGNATURE', 'IMAGE_NT_SIGNATURE', 'IMAGE_DIRECTORY_ENTRY_EXPORT',
            'TRUE', 'FALSE', 'NULL',
            # Windows API functions
            'GetProcAddress', 'GetModuleHandle', 'LoadLibrary', 'VirtualAlloc', 'VirtualFree',
            'OpenProcess', 'CloseHandle', 'CreateToolhelp32Snapshot', 'Process32First',
            'Process32Next', 'strcmp', 'wcslen', 'printf', 'malloc', 'free',
            # Macros and constants
            'NTSYSAPI', 'WINAPI', 'APIENTRY', '_In_', '_Out_', '_In_opt_', '_Out_opt_',
            '_Inout_', '_In_reads_bytes_', '_Out_writes_bytes_',
        }
        
        # Mapping: original identifier  -> new identifier
        self.mapping: Dict[str, str] = {}
        self.counter = 0
        
    def generate_name(self, prefix: str = '') -> str:
        """Sinh tên ngẫu nhiên theo pattern"""
        self.counter += 1
        # Pattern 1: v1, v2, v3... (variable)
        # Pattern 2: s1, s2, s3... (struct)
        # Pattern 3: f1, f2, f3... (function)
        # Pattern 4: a1, b2, c3... (random)
        
        patterns = [
            f"{prefix}{self.counter}",  # v1, s1, f1
            f"{chr(97 + (self.counter % 26))}{self.counter}",  # a1, b2, c3
            f"_{self.counter:04d}",  # _0001, _0002
        ]
        
        return random.choice(patterns)
    
    def extract_identifiers(self, code: str) -> Set[str]:
        """Trích xuất tất cả identifier từ code"""
        # Regex to find identifiers: [a-zA-Z_][a-zA-Z0-9_]*
        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b'
        matches = re.findall(pattern, code)
        
        # filter out keyword and whitelist
        identifiers = set()
        for match in matches:
            if match not in self.whitelist and not match.startswith('_') and len(match) > 2:
                identifiers.add(match)
        
        return identifiers
    
    def obfuscate_code(self, code: str) -> str:


        identifiers = self.extract_identifiers(code)
        
        for identifier in identifiers:

            if identifier.startswith('fn_') or identifier.startswith('p'):
                prefix = 'f'  # function pointer
            elif identifier.startswith('S_') or identifier.startswith('_'):
                prefix = 's'  # struct
            elif identifier[0].isupper():
                prefix = 't'  # type/typedef
            else:
                prefix = 'v'  # variable
            
            self.mapping[identifier] = self.generate_name(prefix)
        

        sorted_identifiers = sorted(identifiers, key=len, reverse=True)
        
        obfuscated = code
        for identifier in sorted_identifiers:
            new_name = self.mapping[identifier]
            pattern = r'\b' + re.escape(identifier) + r'\b'
            obfuscated = re.sub(pattern, new_name, obfuscated)
        
        return obfuscated
    
    def print_mapping(self):
        print("\n=== MAPPING TABLE ===")
        for old, new in sorted(self.mapping.items()):
            print(f"{old:30s} -> {new}")
        print("=====================\n")


def main():
    input_files = ['injection.h', 'injection.c', 'main.c']
    output_dir = Path('obfuscated')
    output_dir.mkdir(exist_ok=True)
    
    obfuscator = CObfuscator()
    

    for input_file in input_files:
        input_path = Path(input_file)
        if not input_path.exists():
            print(f"[!] File not found: {input_file}")
            continue
        
        print(f"[*] Processing {input_file}...")
        
        with open(input_path, 'r', encoding='utf-8') as f:
            code = f.read()
        
        obfuscated = obfuscator.obfuscate_code(code)
        
        output_path = output_dir / f"stealth_{input_file}"
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(obfuscated)
        
        print(f"[+] Saved to {output_path}")
    
    obfuscator.print_mapping()
    
    print(f"[*] Check the '{output_dir}' folder for obfuscated files.")


if __name__ == '__main__':
    main()