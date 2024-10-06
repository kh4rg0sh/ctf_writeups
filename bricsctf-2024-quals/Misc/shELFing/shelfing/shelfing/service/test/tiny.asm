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