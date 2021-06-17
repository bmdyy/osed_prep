# CVE-2017-14980

## Intro

Sync Breeze v10.0.28 is vulnerable to a Stack Buffer Overflow. An exploit is available on [Exploit-DB](https://www.exploit-db.com/exploits/42928).

These PoC's exploit the same vulnerability, except by using a ROP chain so that it works on systems with DEP enabled.

- POC #1 uses a HeapCreate - HeapAlloc - WriteProcessMemory chain to create an executable heap, copy shellcode there and execute it.

## Usage

`./poc_N.py SERVER`