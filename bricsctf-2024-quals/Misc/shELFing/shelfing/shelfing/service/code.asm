section .data
    binsh db '/bin/sh', 0

section .text
    global _start

_start:
    xor rax, rax
    mov rdi, binsh
    mov rsi, rax
    mov rdx, rax
    mov rax, 59
    syscall  
