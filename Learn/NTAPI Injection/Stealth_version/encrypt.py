# encrypt_path.py
path = r"D:\Mal\Learn\ProcessInjection\DLL Injection\payload2.dll"
key = 0x55

encrypted = []
for c in path:
    encrypted.append(ord(c) ^ key)

print("static const WCHAR g_enc_path[] = {")
for i in range(0, len(encrypted), 16):
    chunk = encrypted[i:i+16]
    print("    " + ", ".join(f"0x{x:02X}" for x in chunk) + ",")
print("    0x00")
print("};")