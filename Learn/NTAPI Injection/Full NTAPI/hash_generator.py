# hash_generator.py
def djb2_hash_wide(string):
    hash_val = 5381
    for char in string:
        c = ord(char)
        # lowercase
        if 65 <= c <= 90:
            c += 32
        # hash * 33 + c
        hash_val = ((hash_val << 5) + hash_val + c) & 0xFFFFFFFF
    return hash_val

targets = [
    "ntdll.dll",
    "kernel32.dll",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "LdrLoadDll",
    "NtCreateThreadEx",
    "NtOpenProcess",
    "NtWriteVirtualMemory",
    "NtClose",
    "NtQuerySystemInformation"
]

for target in targets:
    h = djb2_hash_wide(target)
    print(f'// Hash for "{target}": 0x{h:08X}')