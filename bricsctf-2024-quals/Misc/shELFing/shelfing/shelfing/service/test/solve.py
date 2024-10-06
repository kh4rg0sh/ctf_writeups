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

## brics+{0cc8bfea-ec2d-4e68-8c2e-7e55db59cd1a}

"""
ref: 
    https://www.muppetlabs.com/%7Ebreadbox/software/tiny/teensy.html
    https://www.muppetlabs.com/~breadbox/software/ELF.txt
    https://refspecs.linuxbase.org/elf/elf.pdf
    file:///D:/ctfs/pwn/notes/Elf%E2%80%93Structure.pdf
    https://gist.github.com/x0nu11byt3/bcb35c3de461e5fb66173071a2379779
    https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
    http://timelessname.com/elfbin/
"""
